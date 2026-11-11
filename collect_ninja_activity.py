#!/usr/bin/env python3
"""collect_ninja_activity.py -- keep a long-term, searchable history of every
script / automation run in NinjaOne.

Why: NinjaOne's Activity feed UI only shows the most recent 1,000 entries.
The full history is reachable through GET /v2/activities, so this module
copies the device activities we care about into Postgres (table
`ninja_activities`) and keeps them for NINJA_ACTIVITY_RETENTION_DAYS. The
`/ops` pages in the aiassessment Flask app read that table.

Nothing has to change in the PowerShell scripts themselves: NinjaOne already
records each run as one or more DEVICE activities of type ACTION (scripts run
ad-hoc or from a policy schedule) or ACTIONSET (automations), moving through
statusCode START_REQUESTED -> STARTED -> COMPLETED (or CANCELLED). The
COMPLETED row carries activityResult (SUCCESS / FAILURE / ...). The
technician is on the row as userId when a person launched it; policy-
scheduled runs have no userId.

How the pull works (one cursor per activity type, stored in
`ninja_activity_cursors`):
  * First run for a type: page BACKWARD from the newest activity with
    `olderThan=<smallest id seen>` until we pass NINJA_ACTIVITY_BACKFILL_DAYS.
  * Every run after that: page FORWARD with `newerThan=<highest stored id>`
    (the same incremental pattern NinjaOne's own Get-AutomationActivities.ps1
    sample uses), so nothing is skipped no matter how long the worker was down.
  * Rows are keyed on NinjaOne's activity id -> re-reading is harmless.

Each row is enriched at insert time with device name / organization /
location and technician name, so history still reads correctly after a
device is retired or renamed. Device and user lookups are refreshed every
NINJA_DIRECTORY_REFRESH_HOURS (and immediately if an unknown device shows up).

Usage:
    python collect_ninja_activity.py --dry-run --verbose   # print a sample, store nothing
    python collect_ninja_activity.py                       # one harvest into Postgres
    python collect_ninja_activity.py --refresh-directory   # force device/user lookup refresh
    python collect_ninja_activity.py --purge               # apply retention now

worker_main.py calls harvest_all() every NINJA_ACTIVITY_HARVEST_MINUTES.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv

load_dotenv()

# Activity types to keep. ACTION = scripts/actions, ACTIONSET = automations,
# CONDITION_ACTION(SET) = scripts fired by a monitoring condition. Add more
# (e.g. PATCH_MANAGEMENT, CONDITION) if you want them in the device timeline.
DEFAULT_TYPES = "ACTION,ACTIONSET,CONDITION_ACTION,CONDITION_ACTIONSET"
ACTIVITY_TYPES = [t.strip().upper() for t in os.environ.get("NINJA_ACTIVITY_TYPES", DEFAULT_TYPES).split(",") if t.strip()]
BACKFILL_DAYS = int(os.environ.get("NINJA_ACTIVITY_BACKFILL_DAYS", "90"))
RETENTION_DAYS = int(os.environ.get("NINJA_ACTIVITY_RETENTION_DAYS", "730"))
DIRECTORY_REFRESH_HOURS = float(os.environ.get("NINJA_DIRECTORY_REFRESH_HOURS", "6"))
PAGE_SIZE = 1000          # API maximum
MAX_PAGES_PER_RUN = 200   # safety valve: 200k rows per type per harvest
INSERT_CHUNK = 500

PHASES = {
    "START_REQUESTED": "requested",
    "STARTED": "running",
    "IN_PROCESS": "running",
    "WAITING_FOR_USER_RESPONSE": "running",
    "COMPLETED": "completed",
    "CANCEL_REQUESTED": "cancelled",
    "CANCELLED": "cancelled",
}


# --------------------------------------------------------------------------
# API client (token refresh + polite retry on 429/5xx)
# --------------------------------------------------------------------------

class NinjaApi:
    def __init__(self):
        missing = [k for k in ("NINJA_INSTANCE", "NINJA_CLIENT_ID", "NINJA_CLIENT_SECRET") if not os.getenv(k)]
        if missing:
            raise RuntimeError(f"Missing env vars: {', '.join(missing)}")
        host = os.environ["NINJA_INSTANCE"].strip().rstrip("/")
        self.base_url = host if host.startswith("http") else f"https://{host}"
        self.session = requests.Session()
        self._token_expires = 0.0
        self._auth()

    def _auth(self):
        resp = self.session.post(
            f"{self.base_url}/ws/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": os.environ["NINJA_CLIENT_ID"],
                "client_secret": os.environ["NINJA_CLIENT_SECRET"],
                "scope": os.getenv("NINJA_SCOPES", "monitoring management"),
            },
            timeout=30,
        )
        if not resp.ok:
            raise RuntimeError(f"NinjaOne auth failed ({resp.status_code}): {resp.text[:300]}")
        body = resp.json()
        self.session.headers["Authorization"] = f"Bearer {body['access_token']}"
        self._token_expires = time.time() + int(body.get("expires_in", 3600)) - 120

    def get(self, path, params=None):
        for attempt in range(5):
            if time.time() > self._token_expires:
                self._auth()
            resp = self.session.get(f"{self.base_url}{path}", params=params or {}, timeout=60)
            if resp.status_code == 401 and attempt == 0:
                self._auth()
                continue
            if resp.status_code in (429, 500, 502, 503, 504):
                time.sleep(min(60, 2 ** attempt * 3))
                continue
            if not resp.ok:
                raise RuntimeError(f"NinjaOne API error {resp.status_code} for {resp.url}: {resp.text[:300]}")
            return resp.json()
        raise RuntimeError(f"NinjaOne API kept failing for {path}")

    def get_all(self, path, params=None):
        """Cursor pagination used by /v2/devices, /v2/organizations, /v2/locations."""
        out, after = [], None
        while True:
            p = dict(params or {}, pageSize=PAGE_SIZE)
            if after is not None:
                p["after"] = after
            page = self.get(path, p)
            if not page:
                break
            out.extend(page)
            if len(page) < PAGE_SIZE:
                break
            after = page[-1].get("id")
            if after is None:
                break
        return out


# --------------------------------------------------------------------------
# Directory (device / org / location / technician names)
# --------------------------------------------------------------------------

def fetch_directory(api: NinjaApi, verbose=False) -> dict:
    orgs = {o["id"]: o.get("name") for o in api.get_all("/v2/organizations")}
    locs = {l["id"]: l.get("name") for l in api.get_all("/v2/locations")}
    devices = {}
    for d in api.get_all("/v2/devices"):
        devices[d["id"]] = {
            "device_id": d["id"],
            "system_name": d.get("systemName"),
            "display_name": d.get("displayName") or d.get("systemName") or d.get("dnsName"),
            "org_id": d.get("organizationId"),
            "org_name": orgs.get(d.get("organizationId")),
            "location_name": locs.get(d.get("locationId")),
            "node_class": d.get("nodeClass"),
        }
    users = {}
    try:
        for u in api.get("/v2/users") or []:
            name = " ".join(x for x in (u.get("firstName"), u.get("lastName")) if x) or u.get("email")
            users[u["id"]] = {"user_id": u["id"], "name": name, "email": u.get("email"), "user_type": u.get("userType")}
    except RuntimeError as e:
        # Some API client scopes can't list users; we still get names from
        # activity message params when NinjaOne includes them.
        print(f"[ninja-activity] could not list users ({e}); technician names may be blank")
    if verbose:
        print(f"[ninja-activity] directory: {len(devices)} devices, {len(orgs)} orgs, {len(users)} users")
    return {"devices": devices, "users": users}


# --------------------------------------------------------------------------
# Normalising one activity into a row
# --------------------------------------------------------------------------

def _ts(value) -> datetime | None:
    if value is None:
        return None
    v = float(value)
    if v > 1e12:  # milliseconds
        v /= 1000.0
    return datetime.fromtimestamp(v, tz=timezone.utc)


def _params(a: dict) -> dict:
    data = a.get("data") or {}
    msg = data.get("message") if isinstance(data, dict) else None
    if isinstance(msg, dict) and isinstance(msg.get("params"), dict):
        return msg["params"]
    return {}


def script_name_for(a: dict) -> str | None:
    if a.get("sourceName"):
        return a["sourceName"].strip()
    p = _params(a)
    for key in ("scriptName", "actionName", "automationName", "actionsetName", "name"):
        if p.get(key):
            return str(p[key]).strip()
    if a.get("subject"):
        return a["subject"].strip()[:255]
    return None


def to_row(a: dict, directory: dict) -> dict:
    dev = directory["devices"].get(a.get("deviceId")) or {}
    user = directory["users"].get(a.get("userId")) or {}
    p = _params(a)
    status_code = a.get("statusCode")
    return {
        "activity_id": int(a["id"]),
        "activity_time": _ts(a.get("activityTime")),
        "activity_type": a.get("activityType"),
        "status_code": status_code,
        "status": a.get("status"),
        "phase": PHASES.get(status_code or "", "other"),
        "result": a.get("activityResult"),
        "severity": a.get("severity"),
        "series_uid": a.get("seriesUid"),
        "source_config_uid": a.get("sourceConfigUid"),
        "script_name": (script_name_for(a) or "")[:255] or None,
        "device_id": a.get("deviceId"),
        "device_name": dev.get("display_name") or p.get("nodeDisplayName") or p.get("nodeName"),
        "org_id": dev.get("org_id"),
        "org_name": dev.get("org_name") or p.get("clientName") or p.get("organizationName"),
        "location_name": dev.get("location_name"),
        "user_id": a.get("userId"),
        "user_name": user.get("name") or p.get("appUserName"),
        "subject": a.get("subject"),
        "message": a.get("message"),
        "raw": a,
    }


# --------------------------------------------------------------------------
# Pulling
# --------------------------------------------------------------------------

def _page(api, activity_type, **cursor):
    params = {"class": "DEVICE", "type": activity_type, "pageSize": PAGE_SIZE, **cursor}
    return (api.get("/v2/activities", params) or {}).get("activities") or []


def pull_type(api, activity_type, last_id, verbose=False):
    """Return (activities, newest_id). last_id=None means first run (backfill)."""
    collected = []
    if last_id is None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=BACKFILL_DAYS)
        older_than = None
        for _ in range(MAX_PAGES_PER_RUN):
            batch = _page(api, activity_type, **({"olderThan": older_than} if older_than else {}))
            if not batch:
                break
            ids = [b["id"] for b in batch]
            if older_than is not None and max(ids) >= older_than:
                raise RuntimeError(
                    f"olderThan paging for {activity_type} returned ids >= cursor {older_than}; "
                    "NinjaOne paging semantics changed -- stopping backfill rather than looping."
                )
            collected.extend(batch)
            oldest = min(batch, key=lambda b: b["id"])
            if len(batch) < PAGE_SIZE or (_ts(oldest.get("activityTime")) or cutoff) < cutoff:
                break
            older_than = oldest["id"]
        collected = [b for b in collected if (_ts(b.get("activityTime")) or cutoff) >= cutoff]
        newest = max((b["id"] for b in collected), default=0)
        if verbose:
            print(f"[ninja-activity] {activity_type}: backfilled {len(collected)} rows ({BACKFILL_DAYS} days)")
        return collected, newest

    newer_than = last_id
    for _ in range(MAX_PAGES_PER_RUN):
        batch = _page(api, activity_type, newerThan=newer_than)
        if not batch:
            break
        batch_max = max(b["id"] for b in batch)
        collected.extend(b for b in batch if b["id"] > last_id)
        if batch_max <= newer_than or len(batch) < PAGE_SIZE:
            break
        newer_than = batch_max
    newest = max([last_id] + [b["id"] for b in collected])
    if verbose:
        print(f"[ninja-activity] {activity_type}: {len(collected)} new rows since id {last_id}")
    return collected, newest


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

_directory_cache = {"at": 0.0, "data": None}


def _directory(api, verbose=False, force=False):
    stale = time.time() - _directory_cache["at"] > DIRECTORY_REFRESH_HOURS * 3600
    if force or stale or _directory_cache["data"] is None:
        _directory_cache["data"] = fetch_directory(api, verbose)
        _directory_cache["at"] = time.time()
        try:
            import db
            db.save_ninja_directory(_directory_cache["data"])
        except Exception as e:  # directory table is a convenience, never fatal
            print(f"[ninja-activity] could not store directory: {e}")
    return _directory_cache["data"]


def harvest_all(verbose=False, dry_run=False, force_directory=False) -> dict:
    """Pull new activities for every configured type and store them. Never raises
    for a single-type failure; that type's cursor simply isn't advanced."""
    import db

    api = NinjaApi()
    directory = _directory(api, verbose, force=force_directory)
    summary = {}
    for activity_type in ACTIVITY_TYPES:
        try:
            if dry_run:  # one page is enough to eyeball the field shapes
                items = _page(api, activity_type)
                newest = max((i["id"] for i in items), default=0)
            else:
                last_id = db.get_ninja_activity_cursor(activity_type)
                items, newest = pull_type(api, activity_type, last_id, verbose)
            unknown = {i.get("deviceId") for i in items if i.get("deviceId") and i.get("deviceId") not in directory["devices"]}
            if unknown and not force_directory:
                directory = _directory(api, verbose, force=True)
                force_directory = True  # at most one forced refresh per harvest
            rows = [to_row(i, directory) for i in items]
            if dry_run:
                summary[activity_type] = {"fetched": len(rows)}
                for r in rows[:5]:
                    printable = {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in r.items() if k != "raw"}
                    print(json.dumps(printable, indent=2, default=str))
                continue
            inserted = 0
            for i in range(0, len(rows), INSERT_CHUNK):
                inserted += db.save_ninja_activities(rows[i:i + INSERT_CHUNK])
            db.set_ninja_activity_cursor(activity_type, newest, error=None)
            summary[activity_type] = {"fetched": len(rows), "inserted": inserted, "cursor": newest}
        except Exception as e:
            print(f"[ninja-activity] ERROR for {activity_type}: {e}")
            if not dry_run:
                try:
                    db.set_ninja_activity_cursor(activity_type, None, error=str(e)[:1000])
                except Exception:
                    pass
            summary[activity_type] = {"error": str(e)}
    if not dry_run:
        summary["users_inherited"] = db.inherit_ninja_activity_users()
    print(f"[ninja-activity] harvest summary: {summary}")
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="print a sample of what would be stored; touch nothing")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--refresh-directory", action="store_true", help="force device/user lookup refresh")
    ap.add_argument("--purge", action="store_true", help=f"delete rows older than {RETENTION_DAYS} days and exit")
    args = ap.parse_args()

    if args.purge:
        import db
        db.init_db()
        print(f"[ninja-activity] purged {db.purge_ninja_activities(RETENTION_DAYS)} rows older than {RETENTION_DAYS} days")
        return
    if not args.dry_run:
        import db
        db.init_db()
    harvest_all(verbose=args.verbose, dry_run=args.dry_run, force_directory=args.refresh_directory)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        sys.exit(str(e))

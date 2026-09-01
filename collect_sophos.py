#!/usr/bin/env python3
"""
collect_sophos.py — pull the Sophos Endpoint portion of client_month.json for one client/month.

Usage:
    python collect_sophos.py --client brock-norton --month 2026-07 --dry-run
    python collect_sophos.py --client brock-norton --month 2026-07

What this pulls (see Research Findings.md):
  - Endpoint device health summary (active/stale/tamper-protection-off)
  - Recent alerts for the month, by severity
  - Account health-check score (protection/policy/exclusions/tamperProtection)

Auth: one Partner-level OAuth2 credential (SOPHOS_CLIENT_ID/SECRET) covers every
client — this script uses each client's tenant_id + data_region_url from
clients.yaml (already resolved earlier via the Partner API) rather than
re-resolving them at runtime.

Requires: requests, pyyaml, python-dotenv  (pip install requests pyyaml python-dotenv)
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import re

import requests
import yaml
from dotenv import load_dotenv

# Device health thresholds. Sophos's own console uses "2+ weeks" / "2+
# months" buckets (per the sample report), but this collector uses one
# 30-day staleness threshold instead, matching the convention used across
# every other collector in this pipeline (Autotask, NinjaOne) rather than
# replicating each vendor's own slightly different internal cutoffs.
STALE_DAYS = 30

# Matches Sophos's own "Endpoint Computer Activity Status" donut, confirmed
# from a real console screenshot (Active / Inactive 2+ Weeks / Inactive
# 2+ Months / Not Protected). Kept separate from STALE_DAYS above, which
# drives the needs_attention watchlist — this is purely for replicating
# that specific chart's real category boundaries.
TWO_WEEKS_DAYS = 14
TWO_MONTHS_DAYS = 60

ENDPOINT_PAGE_SIZE = 500
ALERTS_PAGE_SIZE = 500


def normalize_data_region_url(raw):
    """clients.yaml stores data_region_url as returned by the Partner API,
    which may or may not include a scheme (seen both ways in practice) —
    normalize to a consistent https://host form the way collect_autotask.py
    does for AUTOTASK_ZONE_URL."""
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    return f"{parsed.scheme}://{parsed.netloc}"


def load_config():
    load_dotenv()
    required = ["SOPHOS_CLIENT_ID", "SOPHOS_CLIENT_SECRET", "SOPHOS_AUTH_URL"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        sys.exit(f"Missing required .env values: {', '.join(missing)}")
    return {
        "client_id": os.getenv("SOPHOS_CLIENT_ID"),
        "client_secret": os.getenv("SOPHOS_CLIENT_SECRET"),
        "auth_url": os.getenv("SOPHOS_AUTH_URL"),
        "timezone": os.getenv("REPORT_TIMEZONE", "UTC"),
        "client_map": os.getenv("CLIENT_MAP", "./clients.yaml"),
        "output_dir": os.getenv("OUTPUT_DIR", "./output"),
    }


def load_client(client_map_path, client_slug):
    with open(client_map_path) as f:
        data = yaml.safe_load(f)
    for client in data["clients"]:
        if client.get("slug") == client_slug:
            return client
    sys.exit(f"No client with slug '{client_slug}' found in {client_map_path}")


def month_range_utc(month_str, tz_name):
    """Given 'YYYY-MM' and a local timezone name, return (start_utc, end_utc)
    as timezone-aware UTC datetimes spanning that calendar month in local
    time — same approach as collect_autotask.py, used here to scope alerts
    to the report month."""
    tz = ZoneInfo(tz_name)
    year, month = (int(x) for x in month_str.split("-"))
    start_local = datetime(year, month, 1, tzinfo=tz)
    end_local = datetime(year + 1, 1, 1, tzinfo=tz) if month == 12 else datetime(year, month + 1, 1, tzinfo=tz)
    return start_local.astimezone(ZoneInfo("UTC")), end_local.astimezone(ZoneInfo("UTC"))


def resolve_month(candidate):
    """Only accepts a strict YYYY-MM string; anything else (None, empty, or
    a malformed value like a stray comment fragment from a .env parser that
    doesn't strip trailing comments) is treated as unset — confirmed to
    happen with REPORT_MONTH's default template value, since python-dotenv
    keeps everything after '=' (including a trailing '# comment') as the
    literal value when it isn't quoted."""
    if candidate and re.fullmatch(r"\d{4}-\d{2}", candidate.strip()):
        return candidate.strip()
    return None


def default_month():
    first_of_this_month = datetime.today().replace(day=1)
    return (first_of_this_month - timedelta(days=1)).strftime("%Y-%m")


class SophosClient:
    def __init__(self, cfg, tenant_id, data_region_url):
        self.data_region_url = normalize_data_region_url(data_region_url)
        self.tenant_id = tenant_id
        self.token = self._get_token(cfg)
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "X-Tenant-ID": self.tenant_id,
        }

    def _get_token(self, cfg):
        resp = requests.post(
            cfg["auth_url"],
            data={
                "grant_type": "client_credentials",
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
                "scope": "token",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if not resp.ok:
            sys.exit(f"Sophos auth failed ({resp.status_code}): {resp.text}")
        return resp.json()["access_token"]

    def get(self, path, params=None):
        resp = requests.get(f"{self.data_region_url}{path}", headers=self.headers, params=params or {})
        if not resp.ok:
            raise RuntimeError(f"Sophos API error {resp.status_code} for {resp.url}:\n{resp.text}")
        return resp.json()

    def get_paginated(self, path, params=None, page_size=500):
        """Sophos pages via pages.nextKey -> pageFromKey, per Research Findings."""
        params = dict(params or {})
        params["pageSize"] = page_size
        items = []
        while True:
            data = self.get(path, params=params)
            items.extend(data.get("items", []))
            next_key = data.get("pages", {}).get("nextKey")
            if not next_key:
                break
            params["pageFromKey"] = next_key
        return items


def parse_iso8601(ts):
    """Sophos timestamps look like '2021-02-12T15:04:53.780Z'."""
    if not ts:
        return None
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def collect(cfg, client, month_str, verbose=False):
    tenant_id = client["sophos"]["tenant_id"]
    data_region_url = client["sophos"]["data_region_url"]
    sophos = SophosClient(cfg, tenant_id, data_region_url)

    month_start, month_end = month_range_utc(month_str, cfg["timezone"])
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=STALE_DAYS)
    two_weeks_cutoff = now - timedelta(days=TWO_WEEKS_DAYS)
    two_months_cutoff = now - timedelta(days=TWO_MONTHS_DAYS)

    # --- Endpoint health ---
    endpoints = sophos.get_paginated("/endpoint/v1/endpoints", page_size=ENDPOINT_PAGE_SIZE)
    if verbose:
        print(f"[debug] endpoints returned: {len(endpoints)}")
        if endpoints:
            print(f"[debug] sample endpoint: {json.dumps(endpoints[0], indent=2)[:1500]}")

    active_count = 0
    stale_devices = []
    tamper_off_devices = []
    unhealthy_devices = []
    attention_reasons = {}
    # Two-tier buckets matching Sophos's own console chart exactly.
    # "not_protected" is always 0 here by definition — a device with no
    # Sophos agent at all would never appear in this endpoint list to
    # begin with, so we have no way to see devices that aren't reporting
    # at all (a real limitation, not a computed zero).
    activity_status = {"active": 0, "inactive_2weeks": 0, "inactive_2months": 0, "not_protected": 0}

    # Sophos Central doesn't purge old agent records on re-image/re-enroll,
    # so the SAME hostname can legitimately map to multiple distinct
    # endpoint records (confirmed against real HCN data: "Ana Sarai
    # MacBook Pro" and "LeShaundra's MacBook Pro" each had 4-5 separate
    # stale/unhealthy records). attention_reasons is keyed by hostname and
    # dedupes reason *categories* per hostname (using the worst/most-recent
    # figure within each category) rather than concatenating one raw phrase
    # per duplicate record — the old behavior produced unreadable run-on
    # strings like "no contact in 106 days, ..., no contact in 96 days, ...".
    attention_max_days_silent = {}
    attention_tamper_off = set()
    attention_unhealthy_statuses = {}
    attention_duplicate_count = {}

    for ep in endpoints:
        hostname = ep.get("hostname") or ep.get("id", "unknown-device")
        last_seen = parse_iso8601(ep.get("lastSeenAt"))
        is_stale = last_seen is not None and last_seen < stale_cutoff
        tamper_off = ep.get("tamperProtectionEnabled") is False
        health = (ep.get("health") or {}).get("overall")

        attention_duplicate_count[hostname] = attention_duplicate_count.get(hostname, 0) + 1

        if last_seen is None or last_seen >= two_weeks_cutoff:
            activity_status["active"] += 1
        elif last_seen >= two_months_cutoff:
            activity_status["inactive_2weeks"] += 1
        else:
            activity_status["inactive_2months"] += 1

        if is_stale:
            stale_devices.append(hostname)
            days_silent = (now - last_seen).days
            attention_max_days_silent[hostname] = max(attention_max_days_silent.get(hostname, 0), days_silent)
        else:
            active_count += 1

        if tamper_off:
            tamper_off_devices.append(hostname)
            attention_tamper_off.add(hostname)

        if health and health.lower() not in ("good", "green"):
            unhealthy_devices.append(hostname)
            attention_unhealthy_statuses.setdefault(hostname, set()).add(health)

    # Build one clean, deduplicated reason string per hostname.
    all_flagged_hostnames = (
        set(attention_max_days_silent) | attention_tamper_off | set(attention_unhealthy_statuses)
    )
    for hostname in all_flagged_hostnames:
        parts = []
        dup_count = attention_duplicate_count.get(hostname, 1)
        record_note = f" (across {dup_count} device records at this name)" if dup_count > 1 else ""
        if hostname in attention_max_days_silent:
            parts.append(f"no contact in {attention_max_days_silent[hostname]} days{record_note}")
        if hostname in attention_tamper_off:
            parts.append("tamper protection disabled")
        if hostname in attention_unhealthy_statuses:
            statuses = ", ".join(sorted(attention_unhealthy_statuses[hostname]))
            parts.append(f"health status: {statuses}")
        attention_reasons[hostname] = parts

    # --- Alerts, scoped to the report month ---
    all_alerts = sophos.get_paginated("/common/v1/alerts", page_size=ALERTS_PAGE_SIZE)
    if verbose:
        print(f"[debug] total alerts returned (unfiltered, all-time or API default window): {len(all_alerts)}")
        if all_alerts:
            print(f"[debug] sample alert: {json.dumps(all_alerts[0], indent=2)[:1000]}")

    month_alerts = []
    for a in all_alerts:
        raised_at = parse_iso8601(a.get("raisedAt"))
        if raised_at is not None and month_start <= raised_at < month_end:
            month_alerts.append(a)

    alerts_by_severity = {}
    high_severity_alerts = []
    for a in month_alerts:
        severity = str(a.get("severity", "unknown")).lower()
        alerts_by_severity[severity] = alerts_by_severity.get(severity, 0) + 1
        if severity == "high":
            high_severity_alerts.append({
                "description": a.get("description", ""),
                "raisedAt": a.get("raisedAt"),
            })

    # --- Account health-check score ---
    health_check = {}
    try:
        health_check = sophos.get("/account-health-check/v1/health-check")
        if verbose:
            print(f"[debug] health-check response: {json.dumps(health_check, indent=2)[:1500]}")
    except RuntimeError as e:
        if verbose:
            print(f"[debug] account-health-check call failed: {e}")

    needs_attention = [
        {"device": name, "reason": ", ".join(reasons)}
        for name, reasons in attention_reasons.items()
    ]

    # protected_count / not_checked_in_count: render_report.py's build_security()
    # and build_kpis() read these explicit fields (falling back to
    # device_count / 0 if absent). Every device returned by the endpoint API
    # has Sophos installed by definition (a device with no agent never
    # appears via this API at all — see activity_status["not_protected"]
    # above), so "protected_count" is simply every device this endpoint
    # returned, never a fraction of it — confirmed by client feedback that a
    # prior report wrongly labeled the not-recently-checked-in population
    # "Unprotected." not_checked_in_count uses the SAME 14-day cutoff as
    # activity_status's "active" bucket (not the older 30-day
    # stale_30day_count), so this number and the activity donut below always
    # agree with each other, and it must NOT be relabeled "unprotected" when
    # rendering — these devices do have current endpoint protection, they
    # just haven't phoned home recently.
    protected_count = len(endpoints)
    not_checked_in_count = activity_status["inactive_2weeks"] + activity_status["inactive_2months"]

    return {
        "sophos_endpoint": {
            "month": month_str,
            "device_count": len(endpoints),
            "protected_count": protected_count,
            "not_checked_in_count": not_checked_in_count,
            "active_count": active_count,
            "activity_status": activity_status,
            "stale_30day_count": len(stale_devices),
            "stale_30day_devices": stale_devices,
            "tamper_protection_off_count": len(tamper_off_devices),
            "tamper_protection_off_devices": tamper_off_devices,
            "unhealthy_devices": unhealthy_devices,
            "alerts_this_month_by_severity": alerts_by_severity,
            "high_severity_alerts_this_month": high_severity_alerts,
            "alerts_data_caveat": (
                "Best-effort only. Confirmed against real data that /common/v1/alerts "
                "does not surface everything visible in the Sophos console's own "
                "'Recent threat graphs' widget (e.g. Mal/HTMLGen-A, Lockdown events "
                "seen in-console for CBDG-AE did not appear via this endpoint, even "
                "though they were status=New, not resolved). Likely a different "
                "underlying data type (Detections/Cases) not fully exposed here. "
                "Treat zero/low alert counts as 'nothing the API surfaced', not "
                "'confirmed zero activity.'"
            ),
            "account_health_check": health_check,
            "needs_attention": needs_attention,
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Collect Sophos Endpoint metrics for one client/month.")
    parser.add_argument("--client", required=True, help="Client slug as it appears in clients.yaml")
    parser.add_argument("--month", default=None, help="YYYY-MM; defaults to previous calendar month")
    parser.add_argument("--dry-run", action="store_true", help="Print results instead of writing a file")
    parser.add_argument("--verbose", action="store_true", help="Print diagnostic info about the API responses")
    args = parser.parse_args()

    cfg = load_config()
    client = load_client(cfg["client_map"], args.client)

    if not client.get("sources", {}).get("sophos_endpoint", False):
        print(f"[skip] {client['name']}: sources.sophos_endpoint is false — nothing to collect.")
        return

    month_str = resolve_month(args.month) or resolve_month(os.getenv("REPORT_MONTH")) or default_month()

    print(f"Collecting Sophos Endpoint data for {client['name']} ({month_str})...")
    result = collect(cfg, client, month_str, verbose=args.verbose)

    if args.dry_run:
        print(json.dumps(result, indent=2))
        return

    out_dir = os.path.join(cfg["output_dir"], client["slug"])
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "client_month.json")

    existing = {}
    if os.path.exists(out_path):
        with open(out_path) as f:
            existing = json.load(f)
    existing.update(result)
    with open(out_path, "w") as f:
        json.dump(existing, f, indent=2)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()

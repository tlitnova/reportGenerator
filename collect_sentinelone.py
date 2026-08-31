#!/usr/bin/env python3
"""
collect_sentinelone.py — pull SentinelOne endpoint protection status for one
client (for clients not on Sophos Endpoint).

Usage:
    python collect_sentinelone.py --client client-8 --month 2026-07 --dry-run --verbose

Auth: Bearer-style token via "Authorization: ApiToken <token>" header —
confirmed consistently across multiple independent integration docs, not a
single-source guess. Base URL is your own console hostname (tenant-specific,
not shared), from SENTINELONE_CONSOLE_URL in .env.

Multi-tenant model: Account > Sites > Groups. A client maps to one Site;
SENTINELONE_API_TOKEN must be an Account-scoped Service User (confirmed
during setup) so it can see this client's site alongside every other one.

Pagination: v2.1 uses cursor-based pagination (pagination.nextCursor), not
page numbers — confirmed from multiple sources, implemented accordingly.

CALIBRATION NOTE: auth format, base URL pattern, and the top-level response
envelope are confirmed from multiple independent sources. Individual field
names within an agent/threat record (e.g. exactly which field holds "last
seen" or "infected" status) are based on SentinelOne's well-documented
public API conventions but not yet verified against this account's real
response — --verbose will show the real shape on first run.

Requires: requests, pyyaml, python-dotenv  (pip install requests pyyaml python-dotenv)
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
import yaml
from dotenv import load_dotenv

STALE_DAYS = 30


def default_month():
    first_of_this_month = datetime.today().replace(day=1)
    return (first_of_this_month - timedelta(days=1)).strftime("%Y-%m")


def month_range_utc(month_str, tz_name="UTC"):
    from zoneinfo import ZoneInfo
    tz = ZoneInfo(tz_name)
    year, month = (int(x) for x in month_str.split("-"))
    start_local = datetime(year, month, 1, tzinfo=tz)
    end_local = datetime(year + 1, 1, 1, tzinfo=tz) if month == 12 else datetime(year, month + 1, 1, tzinfo=tz)
    return start_local.astimezone(ZoneInfo("UTC")), end_local.astimezone(ZoneInfo("UTC"))


def normalize_console_url(raw):
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    return f"{parsed.scheme}://{parsed.netloc}"


def load_config():
    load_dotenv()
    required = ["SENTINELONE_CONSOLE_URL", "SENTINELONE_API_TOKEN"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        sys.exit(f"Missing required .env values: {', '.join(missing)}")
    return {
        "console_url": normalize_console_url(os.getenv("SENTINELONE_CONSOLE_URL")),
        "api_token": os.getenv("SENTINELONE_API_TOKEN"),
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


class SentinelOneClient:
    def __init__(self, cfg):
        self.base_url = f"{cfg['console_url']}/web/api/v2.1"
        self.headers = {"Authorization": f"ApiToken {cfg['api_token']}"}

    def get_all_pages(self, path, params=None):
        """Cursor-based pagination, confirmed for v2.1 — follows
        pagination.nextCursor until absent, rather than page numbers."""
        params = dict(params or {})
        items = []
        while True:
            resp = requests.get(f"{self.base_url}{path}", headers=self.headers, params=params)
            if not resp.ok:
                sys.exit(f"SentinelOne API error {resp.status_code} for {resp.url}:\n{resp.text}")
            data = resp.json()
            items.extend(data.get("data", []))
            next_cursor = data.get("pagination", {}).get("nextCursor")
            if not next_cursor:
                break
            params["cursor"] = next_cursor
        return items


def collect(cfg, client, month_str, verbose=False):
    site_id = client.get("sentinelone", {}).get("site_id")
    if not site_id:
        sys.exit(f"{client['name']} has sources.sentinelone true but no site_id set in clients.yaml.")

    s1 = SentinelOneClient(cfg)
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=STALE_DAYS)
    month_start, month_end = month_range_utc(month_str, cfg["timezone"])

    agents = s1.get_all_pages("/agents", params={"siteIds": site_id})
    if verbose:
        print(f"[debug] agents returned for site {site_id}: {len(agents)}")
        if agents:
            print(f"[debug] sample agent: {json.dumps(agents[0], indent=2)[:1500]}")

    stale_devices = []
    infected_devices = []
    attention_by_agent = {}

    for agent in agents:
        agent_id = agent.get("id", "unknown-agent")
        name = agent.get("computerName") or agent.get("hostname") or agent_id

        last_active = agent.get("lastActiveDate")
        if last_active:
            try:
                last_active_dt = datetime.fromisoformat(str(last_active).replace("Z", "+00:00"))
                if last_active_dt < stale_cutoff:
                    stale_devices.append(name)
                    days_silent = (now - last_active_dt).days
                    attention_by_agent.setdefault(agent_id, {"device": name, "reasons": []})["reasons"].append(
                        f"no contact in {days_silent} days"
                    )
            except ValueError:
                if verbose:
                    print(f"[debug] could not parse lastActiveDate for {name}: {last_active!r}")

        if agent.get("infected"):
            infected_devices.append(name)
            attention_by_agent.setdefault(agent_id, {"device": name, "reasons": []})["reasons"].append(
                "active unmitigated threat"
            )

    threats = s1.get_all_pages("/threats", params={"siteIds": site_id})
    if verbose:
        print(f"[debug] threats returned (all-time, unfiltered) for site {site_id}: {len(threats)}")
        if threats:
            print(f"[debug] sample threat: {json.dumps(threats[0], indent=2)[:1500]}")

    month_threats = []
    for t in threats:
        info = t.get("threatInfo", t)  # some responses may be flat rather than nested
        created_at = info.get("createdAt") or t.get("createdAt")
        if not created_at:
            continue
        try:
            created_dt = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
        except ValueError:
            if verbose:
                print(f"[debug] could not parse threat createdAt: {created_at!r}")
            continue
        if month_start <= created_dt < month_end:
            month_threats.append(info)

    threats_by_confidence = {}
    unmitigated_count = 0
    for info in month_threats:
        confidence = str(info.get("confidenceLevel", "unknown"))
        threats_by_confidence[confidence] = threats_by_confidence.get(confidence, 0) + 1
        if info.get("mitigationStatus") == "not_mitigated":
            unmitigated_count += 1

    needs_attention = [
        {"device": v["device"], "reason": ", ".join(v["reasons"])}
        for v in attention_by_agent.values()
    ]

    return {
        "sentinelone": {
            "month": month_str,
            "device_count": len(agents),
            "stale_30day_count": len(stale_devices),
            "stale_30day_devices": stale_devices,
            "infected_count": len(infected_devices),
            "infected_devices": infected_devices,
            "threats_this_month_by_confidence": threats_by_confidence,
            "threats_this_month_total": len(month_threats),
            "threats_this_month_unmitigated": unmitigated_count,
            "needs_attention": needs_attention,
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Collect SentinelOne status for one client.")
    parser.add_argument("--client", required=True, help="Client slug as it appears in clients.yaml")
    parser.add_argument("--month", default=None, help="YYYY-MM; defaults to previous calendar month (affects threat counts only)")
    parser.add_argument("--dry-run", action="store_true", help="Print results instead of writing a file")
    parser.add_argument("--verbose", action="store_true", help="Print diagnostic info about the API responses")
    args = parser.parse_args()

    cfg = load_config()
    client = load_client(cfg["client_map"], args.client)

    if not client.get("sources", {}).get("sentinelone", False):
        print(f"[skip] {client['name']}: sources.sentinelone is false — nothing to collect.")
        return

    month_str = args.month or default_month()

    print(f"Collecting SentinelOne data for {client['name']} ({month_str})...")
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

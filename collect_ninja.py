#!/usr/bin/env python3
"""
collect_ninja.py — pull the NinjaOne portion of client_month.json for one client.

Usage:
    python collect_ninja.py --client brock-norton --dry-run
    python collect_ninja.py --client brock-norton

NinjaOne data doesn't really have a "month" the way Autotask tickets do —
device health, patch status, and offline devices are a snapshot of *now*,
not a historical range. So this collector doesn't take --month; run it
whenever you're assembling that month's report and it reflects current state.

What this pulls (see Research Findings.md):
  - Device inventory + OS mix for the client's organization
  - Offline devices (tracked, but not treated as a "needs attention" signal —
    it's a live instant-in-time flag, not a reliable indicator of neglect)
  - Devices not seen in 30+ days (this IS a needs-attention signal)
  - Patch compliance (Installed/Approved/Pending/Failed), matching the
    vendor's own "Patch Compliance" report exactly — combining OS and 3rd
    party patches, since NinjaOne splits those across four separate
    endpoints per device with no single endpoint covering all four states.
  - A consolidated "needs attention" list combining staleness + failed patches

Requires: requests, pyyaml, python-dotenv  (pip install requests pyyaml python-dotenv)
"""

import argparse
import json
import os
import sys
import concurrent.futures
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import requests
import yaml
from dotenv import load_dotenv

STALE_DAYS = 30

# NinjaOne's per-organization device list isn't expected to run into
# thousands of devices for a single MSP client, so this collector requests
# one large page rather than implementing cursor pagination. If a client
# ever has more devices than this, raise it — or flag it and we'll add
# proper pagination.
DEVICE_PAGE_SIZE = 1000

# Patch compliance requires 4 separate per-device endpoint calls (NinjaOne
# has no single endpoint returning Installed/Approved/Pending/Failed
# together), plus 1 more for OS name — 5 calls per device. For a client
# with many devices, running these serially would be slow. This fetches
# multiple devices' data concurrently; raise/lower based on how your
# NinjaOne account's rate limits behave in practice.
MAX_WORKERS = 8

# The four endpoints that together cover the vendor's own four patch
# states. Two are OS patches, two are 3rd-party ("software") patches; per
# the vendor's own "Patch Compliance" report, the page-level score combines
# both into one total, so we do too.
# NinjaOne splits patch data across two kinds of endpoint:
# - "installs" endpoints return install HISTORY (each item has an
#   installedAt timestamp) — Installed + Failed states. These need to be
#   scoped to the report month, or every device's entire multi-year patch
#   history gets summed together (confirmed bug: an unscoped pull returned
#   ~14x the vendor report's own monthly count).
# - The other two return current BACKLOG state (Approved + Pending) with no
#   installedAt at all — there's no "this month's pending count," pending
#   is just whatever's pending right now. These are never time-filtered,
#   matching the vendor report's own methodology.
PATCH_INSTALL_ENDPOINTS = [
    "/v2/device/{id}/os-patch-installs",        # Installed + Failed (OS)
    "/v2/device/{id}/software-patch-installs",  # Installed + Failed (3rd party)
]
PATCH_BACKLOG_ENDPOINTS = [
    "/v2/device/{id}/os-patches",       # Pending + Approved (OS)
    "/v2/device/{id}/software-patches",  # Pending + Approved (3rd party)
]


def month_range_utc(month_str, tz_name):
    """Given 'YYYY-MM' and a local timezone name, return (start_epoch,
    end_epoch) as UTC epoch-second boundaries spanning that calendar month
    in local time. Used to scope patch INSTALL events (which have a real
    timestamp) to the report month — device/offline/backlog data stays a
    pure current-state snapshot, unaffected by this."""
    tz = ZoneInfo(tz_name)
    year, month = (int(x) for x in month_str.split("-"))
    start_local = datetime(year, month, 1, tzinfo=tz)
    end_local = datetime(year + 1, 1, 1, tzinfo=tz) if month == 12 else datetime(year, month + 1, 1, tzinfo=tz)
    return start_local.astimezone(ZoneInfo("UTC")).timestamp(), end_local.astimezone(ZoneInfo("UTC")).timestamp()


def default_month():
    """Previous calendar month, in YYYY-MM — matches collect_autotask.py's default."""
    first_of_this_month = datetime.today().replace(day=1)
    return (first_of_this_month - timedelta(days=1)).strftime("%Y-%m")


def normalize_os_name(name):
    """NinjaOne reports the same Windows edition with different display
    strings depending on the device (confirmed against real data:
    "Microsoft Windows 11 Pro Edition" vs "Windows 11 Professional Edition"
    for what is the same underlying SKU) — merge those so os_mix reflects
    real device counts rather than label variance. Two separate quirks are
    involved: a "Microsoft " prefix that appears inconsistently regardless
    of edition, and "Pro" vs "Professional" wording. Other editions (Home
    vs. Home Premium) are genuinely different SKUs and are left alone."""
    if name is None:
        return name
    normalized = name.replace("Microsoft Windows", "Windows")
    normalized = normalized.replace("Professional Edition", "Pro Edition")
    return normalized


def load_config():
    load_dotenv()
    required = ["NINJA_INSTANCE", "NINJA_CLIENT_ID", "NINJA_CLIENT_SECRET"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        sys.exit(f"Missing required .env values: {', '.join(missing)}")
    return {
        "instance": os.getenv("NINJA_INSTANCE").strip().rstrip("/"),
        "client_id": os.getenv("NINJA_CLIENT_ID"),
        "client_secret": os.getenv("NINJA_CLIENT_SECRET"),
        "scopes": os.getenv("NINJA_SCOPES", "monitoring management"),
        "client_map": os.getenv("CLIENT_MAP", "./clients.yaml"),
        "output_dir": os.getenv("OUTPUT_DIR", "./output"),
        "timezone": os.getenv("REPORT_TIMEZONE", "UTC"),
    }


def load_client(client_map_path, client_slug):
    with open(client_map_path) as f:
        data = yaml.safe_load(f)
    for client in data["clients"]:
        if client.get("slug") == client_slug:
            return client
    sys.exit(f"No client with slug '{client_slug}' found in {client_map_path}")


class NinjaClient:
    def __init__(self, cfg):
        host = cfg["instance"]
        if not host.startswith("http"):
            host = f"https://{host}"
        self.base_url = host
        self.token = self._get_token(cfg)
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def _get_token(self, cfg):
        resp = requests.post(
            f"{self.base_url}/ws/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
                "scope": cfg["scopes"],
            },
        )
        if not resp.ok:
            sys.exit(f"NinjaOne auth failed ({resp.status_code}): {resp.text}")
        return resp.json()["access_token"]

    def get(self, path, params=None):
        resp = requests.get(f"{self.base_url}{path}", headers=self.headers, params=params or {})
        if not resp.ok:
            raise RuntimeError(f"NinjaOne API error {resp.status_code} for {resp.url}:\n{resp.text}")
        return resp.json()


def fetch_device_data(ninja, device, stale_cutoff, now, month_start, month_end, verbose=False, dump_samples=False, detailed=False):
    """Gathers everything needed for one device: OS name, staleness, and
    merged patch-state counts. Runs inside a worker thread — one device's
    failure shouldn't take down the others, so endpoint failures are caught
    and logged rather than raised.

    `detailed` controls patch-pull cost: True runs both install-history
    endpoints plus both backlog endpoints (full Installed/Approved/Pending/
    Failed, OS + 3rd party); False runs only the OS install-history endpoint
    (Installed/Failed only). Either way, install-history items are filtered
    to [month_start, month_end) by their installedAt timestamp — backlog
    (Approved/Pending) items have no timestamp and are never filtered."""
    device_id = device.get("id")
    display_name = device.get("systemName") or device.get("dnsName") or f"device-{device_id}"

    result = {
        "display_name": display_name,
        "os_name": "Unknown",
        "is_offline": bool(device.get("offline")),
        "is_stale": False,
        "days_silent": None,
        "patch_counts": {"INSTALLED": 0, "APPROVED": 0, "PENDING": 0, "FAILED": 0},
        "other_statuses": {},
        "failed_patch_count": 0,
        "undated_install_count": 0,
    }

    last_contact = device.get("lastContact")  # epoch seconds, per NinjaOne API
    if last_contact is not None and last_contact < stale_cutoff:
        result["is_stale"] = True
        result["days_silent"] = round((now - last_contact) / 86400)

    # OS name: the org-scoped device list doesn't include it at all
    # (confirmed against real data) — the fuller per-device detail endpoint
    # does. Field path confirmed working against real data as os.name.
    try:
        detail = ninja.get(f"/v2/device/{device_id}")
        if verbose and dump_samples:
            print(f"[debug] sample device detail response: {json.dumps(detail, indent=2)[:2000]}")
        result["os_name"] = normalize_os_name(
            (detail.get("os") or {}).get("name")
            or (detail.get("system") or {}).get("name")
            or detail.get("osName")
            or "Unknown"
        )
    except RuntimeError as e:
        if verbose:
            print(f"[debug] device detail lookup failed for {device_id}: {e}")

    def tally(items, path_template, filter_to_month):
        for p in (items or []):
            if not isinstance(p, dict):
                continue
            if filter_to_month:
                installed_at = p.get("installedAt")
                if installed_at is not None and not (month_start <= installed_at < month_end):
                    # Has a timestamp, and it's outside this month — genuinely excluded.
                    continue
                if installed_at is None:
                    # No timestamp at all (seen in real data) — this is still
                    # a real installed/failed record, just one we can't place
                    # in time. Don't silently drop it; count it and track
                    # separately so totals stay honest about what's dated
                    # vs. not, rather than quietly undercounting.
                    result["undated_install_count"] += 1
            status = str(p.get("status", "")).upper()
            if status in result["patch_counts"]:
                result["patch_counts"][status] += 1
            elif status:
                result["other_statuses"][status] = result["other_statuses"].get(status, 0) + 1
            if status == "FAILED":
                result["failed_patch_count"] += 1

    install_endpoints = PATCH_INSTALL_ENDPOINTS if detailed else PATCH_INSTALL_ENDPOINTS[:1]
    for path_template in install_endpoints:
        path = path_template.format(id=device_id)
        try:
            data = ninja.get(path)
        except RuntimeError as e:
            if verbose:
                print(f"[debug] {path} failed for device {device_id}: {e}")
            continue
        if verbose and dump_samples:
            print(f"[debug] sample response for {path_template}: {json.dumps(data, indent=2)[:800]}")
        tally(data, path_template, filter_to_month=True)

    if detailed:
        for path_template in PATCH_BACKLOG_ENDPOINTS:
            path = path_template.format(id=device_id)
            try:
                data = ninja.get(path)
            except RuntimeError as e:
                if verbose:
                    print(f"[debug] {path} failed for device {device_id}: {e}")
                continue
            if verbose and dump_samples:
                print(f"[debug] sample response for {path_template}: {json.dumps(data, indent=2)[:800]}")
            tally(data, path_template, filter_to_month=False)

    return result


def collect(cfg, client, month_str, verbose=False):
    org_id = client["ninjaone"]["organization_id"]
    detailed = client["ninjaone"].get("detailed_patch_compliance", False)
    ninja = NinjaClient(cfg)

    month_start, month_end = month_range_utc(month_str, cfg.get("timezone", "UTC"))

    devices = ninja.get(f"/v2/organization/{org_id}/devices", params={"pageSize": DEVICE_PAGE_SIZE})
    if verbose:
        print(f"[debug] devices returned for org {org_id}: {len(devices)}")
        print(f"[debug] detailed_patch_compliance: {detailed}")
        print(f"[debug] patch month window: {month_str} ({month_start} - {month_end} UTC epoch)")
        if devices:
            print(f"[debug] sample device keys: {sorted(devices[0].keys())}")

    now = datetime.now(timezone.utc).timestamp()
    stale_cutoff = now - (STALE_DAYS * 86400)

    per_device_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(
                fetch_device_data, ninja, d, stale_cutoff, now, month_start, month_end, verbose,
                d is devices[0] if devices else False, detailed,
            )
            for d in devices
        ]
        for future in concurrent.futures.as_completed(futures):
            per_device_results.append(future.result())

    os_mix = {}
    offline_devices = []
    stale_devices = []
    devices_with_failed_patches = []
    attention_reasons = {}  # display_name -> list of reasons, consolidated at the end
    patch_counts = {"INSTALLED": 0, "APPROVED": 0, "PENDING": 0, "FAILED": 0}
    other_statuses_seen = {}
    undated_install_count = 0

    for r in per_device_results:
        os_mix[r["os_name"]] = os_mix.get(r["os_name"], 0) + 1

        # "offline" is a live, instant-in-time flag (is it connected right
        # now?) rather than a real signal of neglect — per the client's own
        # call, it's tracked for visibility only, never surfaced as
        # needing attention. 30-day staleness is the signal that matters.
        if r["is_offline"]:
            offline_devices.append(r["display_name"])
        if r["is_stale"]:
            stale_devices.append(r["display_name"])
            attention_reasons.setdefault(r["display_name"], []).append(
                f"no contact in {r['days_silent']} days"
            )

        for status, count in r["patch_counts"].items():
            patch_counts[status] += count
        for status, count in r["other_statuses"].items():
            other_statuses_seen[status] = other_statuses_seen.get(status, 0) + count
        undated_install_count += r["undated_install_count"]

        if r["failed_patch_count"]:
            devices_with_failed_patches.append(r["display_name"])
            attention_reasons.setdefault(r["display_name"], []).append(
                f"{r['failed_patch_count']} failed patch(es)"
            )

    if verbose and other_statuses_seen:
        print(f"[debug] patch statuses seen that don't match Installed/Approved/Pending/Failed: {other_statuses_seen}")
    if verbose and undated_install_count:
        print(f"[debug] install records with no installedAt (counted, but not placeable in the month window): {undated_install_count}")

    # KNOWN LIMITATION: this will not exactly match NinjaOne's own "Patch
    # Compliance" dashboard number. That dashboard's total is far smaller
    # than what these public endpoints return even after month-scoping —
    # its internal methodology (likely catalog-scoping, dedup, or something
    # else not exposed via the API) isn't fully reproducible from here. This
    # is a solid operational monthly summary, not a byte-exact replica of
    # NinjaOne's UI. For a client in a compliance cycle (e.g. CMMC) needing
    # an authoritative patch record, NinjaOne's own native export remains
    # the audit artifact of record — this output is the narrative/dashboard
    # version, not a substitute for it.
    total_patches = sum(patch_counts.values())
    patch_score_pct = round(100 * patch_counts["INSTALLED"] / total_patches, 1) if total_patches else None

    needs_attention = [
        {"device": name, "reason": ", ".join(reasons)}
        for name, reasons in attention_reasons.items()
    ]

    return {
        "ninjaone": {
            "device_count": len(devices),
            "os_mix": os_mix,
            "offline_count": len(offline_devices),
            "offline_devices": offline_devices,
            "stale_30day_count": len(stale_devices),
            "stale_30day_devices": stale_devices,
            "patch_compliance": {
                "month": month_str,  # Installed/Failed are scoped to this month;
                                       # Approved/Pending are current backlog, not
                                       # month-scoped (they have no install date)
                "installed": patch_counts["INSTALLED"],
                "approved": patch_counts["APPROVED"],
                "pending": patch_counts["PENDING"],
                "failed": patch_counts["FAILED"],
                "score_pct": patch_score_pct,
                "detailed": detailed,
                "undated_install_count": undated_install_count,  # installed/failed
                    # records with no installedAt — counted above, but not
                    # excludable/includable by month since we can't place them
            },
            "devices_with_failed_patches": devices_with_failed_patches,
            "needs_attention": needs_attention,
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Collect NinjaOne metrics for one client.")
    parser.add_argument("--client", required=True, help="Client slug as it appears in clients.yaml")
    parser.add_argument("--month", default=None, help="YYYY-MM; defaults to previous calendar month (only affects patch Installed/Failed counts)")
    parser.add_argument("--dry-run", action="store_true", help="Print results instead of writing a file")
    parser.add_argument("--verbose", action="store_true", help="Print diagnostic info about the API responses")
    args = parser.parse_args()

    cfg = load_config()
    client = load_client(cfg["client_map"], args.client)

    if not client.get("sources", {}).get("ninjaone", False):
        print(f"[skip] {client['name']}: sources.ninjaone is false — nothing to collect.")
        return

    month_str = args.month or os.getenv("REPORT_MONTH") or default_month()

    print(f"Collecting NinjaOne data for {client['name']}...")
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

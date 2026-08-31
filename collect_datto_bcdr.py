#!/usr/bin/env python3
"""
collect_datto_bcdr.py — pull the Datto BCDR portion of client_month.json
for one client (on-prem/cloud appliance backup status).

Usage:
    python collect_datto_bcdr.py --client client-3 --dry-run --verbose
    python collect_datto_bcdr.py --client client-3

Auth: HTTP Basic (public key = username, secret key = password) — the
BCDR-scoped key, confirmed separate from the SaaS Protection key despite
older docs claiming they're shared (see collect_datto_saas.py's notes).

Confirmed endpoints (from Datto's own PowerShell wrapper docs):
  GET /bcdr/device/{serialNumber}        — single appliance details
  GET /bcdr/device/{serialNumber}/asset  — agents/shares protected by that
                                            appliance, with their backup status

CALIBRATION WARNING: I know these endpoints exist and their general purpose,
but not the exact field names in the asset response (e.g. what "last backup
timestamp" is actually called). This tries a few plausible field names and
reports via --verbose exactly what it finds, the same pattern used for
NinjaOne's OS field.

Requires: requests, pyyaml, python-dotenv  (pip install requests pyyaml python-dotenv)
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import yaml
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

# Datto's own default thresholds for flagging a backup as behind schedule
# (per BCDR Status page documentation) — used here as the staleness signal.
LOCAL_BACKUP_STALE_HOURS = 24
OFFSITE_SYNC_STALE_HOURS = 48


def normalize_api_url(raw):
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    return f"{parsed.scheme}://{parsed.netloc}"


def load_config():
    load_dotenv()
    required = ["DATTO_BCDR_PUBLIC_KEY", "DATTO_BCDR_SECRET_KEY", "DATTO_BCDR_API_URL"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        sys.exit(f"Missing required .env values: {', '.join(missing)}")
    return {
        "public_key": os.getenv("DATTO_BCDR_PUBLIC_KEY"),
        "secret_key": os.getenv("DATTO_BCDR_SECRET_KEY"),
        "api_url": normalize_api_url(os.getenv("DATTO_BCDR_API_URL")),
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


def collect(cfg, client, verbose=False):
    device_serials = client.get("datto_bcdr", {}).get("device_serials", [])
    if not device_serials:
        sys.exit(f"{client['name']} has sources.datto_bcdr true but no device_serials set in clients.yaml.")

    auth = HTTPBasicAuth(cfg["public_key"], cfg["secret_key"])
    now = datetime.now(timezone.utc)

    devices_out = []
    needs_attention = []

    for serial in device_serials:
        resp = requests.get(f"{cfg['api_url']}/v1/bcdr/device/{serial}", auth=auth)
        if not resp.ok:
            print(f"[warn] could not fetch device {serial}: HTTP {resp.status_code} — {resp.text[:300]}")
            continue
        device = resp.json()
        if verbose:
            print(f"[debug] device {serial} response: {json.dumps(device, indent=2)[:1500]}")

        resp2 = requests.get(f"{cfg['api_url']}/v1/bcdr/device/{serial}/asset", auth=auth)
        if not resp2.ok:
            print(f"[warn] could not fetch assets for device {serial}: HTTP {resp2.status_code} — {resp2.text[:300]}")
            assets = []
        else:
            asset_data = resp2.json()
            assets = asset_data.get("items", asset_data) if isinstance(asset_data, dict) else asset_data
            if verbose:
                print(f"[debug] {len(assets)} asset(s) for device {serial}")
                if assets:
                    print(f"[debug] sample asset: {json.dumps(assets[0], indent=2)[:1500]}")

        device_name = device.get("name") or device.get("hostname") or serial
        asset_summaries = []
        for asset in assets:
            asset_name = asset.get("name") or asset.get("hostname") or "unknown-asset"

            # Confirmed against real data — these are the actual field names,
            # not a guess. lastSnapshot/latestOffsite are epoch seconds;
            # localSnapshots (count) is a different field entirely and was
            # an earlier bug here — don't confuse the two again.
            last_backup_ts = asset.get("lastSnapshot")
            last_offsite_ts = asset.get("latestOffsite")
            screenshot_ok = asset.get("lastScreenshotAttemptStatus")
            is_paused = bool(asset.get("isPaused"))
            is_archived = bool(asset.get("isArchived"))

            backups = asset.get("backups") or []
            most_recent_status = backups[0].get("backup", {}).get("status") if backups else None
            # NOTE: this is the size of the most recent backup job, not a
            # confirmed measure of "space this asset currently occupies on
            # the appliance's local disk" — those may be close in practice
            # but aren't verified identical. Named accordingly rather than
            # implying more precision than we actually have.
            most_recent_backup_size_bytes = backups[0].get("backup", {}).get("totalUsedStorage") if backups else None

            local_stale = False
            offsite_stale = False
            if last_backup_ts:
                hours_since_local = (now - datetime.fromtimestamp(last_backup_ts, tz=timezone.utc)).total_seconds() / 3600
                local_stale = hours_since_local > LOCAL_BACKUP_STALE_HOURS
            if last_offsite_ts:
                hours_since_offsite = (now - datetime.fromtimestamp(last_offsite_ts, tz=timezone.utc)).total_seconds() / 3600
                offsite_stale = hours_since_offsite > OFFSITE_SYNC_STALE_HOURS

            asset_summaries.append({
                "asset_name": asset_name,
                "last_backup": datetime.fromtimestamp(last_backup_ts, tz=timezone.utc).isoformat() if last_backup_ts else None,
                "last_offsite_sync": datetime.fromtimestamp(last_offsite_ts, tz=timezone.utc).isoformat() if last_offsite_ts else None,
                "most_recent_backup_status": most_recent_status,
                "most_recent_backup_size_bytes": most_recent_backup_size_bytes,
                "screenshot_verification_ok": screenshot_ok,
                "is_paused": is_paused,
                "is_archived": is_archived,
                "local_backup_stale": local_stale,
                "offsite_sync_stale": offsite_stale,
            })

            # Paused/archived agents are expected to not be backing up —
            # don't flag them as a problem.
            if is_paused or is_archived:
                continue
            reasons = []
            if local_stale:
                reasons.append(f"local backup stale (>{LOCAL_BACKUP_STALE_HOURS}h)")
            if offsite_stale:
                reasons.append(f"offsite sync stale (>{OFFSITE_SYNC_STALE_HOURS}h)")
            if most_recent_status and most_recent_status != "success":
                reasons.append(f"most recent backup status: {most_recent_status}")
            if screenshot_ok is False:
                reasons.append("last screenshot verification failed")
            if reasons:
                needs_attention.append({"device": f"{device_name} / {asset_name}", "reason": ", ".join(reasons)})

        devices_out.append({
            "serial": serial,
            "name": device_name,
            "asset_count": len(assets),
            "assets": asset_summaries,
        })

    return {
        "datto_bcdr": {
            "device_count": len(devices_out),
            "devices": devices_out,
            "needs_attention": needs_attention,
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Collect Datto BCDR status for one client.")
    parser.add_argument("--client", required=True, help="Client slug as it appears in clients.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Print results instead of writing a file")
    parser.add_argument("--verbose", action="store_true", help="Print diagnostic info about the API responses")
    args = parser.parse_args()

    cfg = load_config()
    client = load_client(cfg["client_map"], args.client)

    if not client.get("sources", {}).get("datto_bcdr", False):
        print(f"[skip] {client['name']}: sources.datto_bcdr is false — nothing to collect.")
        return

    print(f"Collecting Datto BCDR data for {client['name']}...")
    result = collect(cfg, client, verbose=args.verbose)

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

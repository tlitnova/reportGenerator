#!/usr/bin/env python3
"""
collect_datto_saas.py — pull the Datto SaaS Protection portion of
client_month.json for one client (M365/Google Workspace backup status).

Usage:
    python collect_datto_saas.py --client cbdg-ae --dry-run --verbose
    python collect_datto_saas.py --client client-6

Auth: HTTP Basic (public key = username, secret key = password) — not OAuth.
One credential covers every client, PROVIDED it was created with "Select
Vendor" left completely blank. A key created with any vendor selected
(confirmed against real data — one was scoped to "Lifecycle Manager") will
401 against this endpoint even though it authenticates fine elsewhere.

Confirmed against real data: GET /v1/saas/domains alone returns everything
this collector needs (backup percentage, seats used, active services count)
for every customer under this credential — no second per-customer call
required.

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

# Datto's raw appType strings -> the friendly per-service labels the report
# uses. Confirmed against live /v1/saas/{customerId}/applications responses
# (2026-09-01): every customer probed used exactly these four appType
# values under an "Office365" suite. Fall back to stripping the "Office365"
# prefix for anything unrecognized (e.g. a future Google Workspace suite)
# rather than failing.
APP_TYPE_LABELS = {
    "Office365Exchange": "Exchange",
    "Office365OneDrive": "OneDrive",
    "Office365SharePoint": "SharePoint",
    "Office365Teams": "Teams",
}


def _friendly_app_label(app_type):
    return APP_TYPE_LABELS.get(app_type, app_type.replace("Office365", "") or app_type)


def _ms_to_date_str(ms):
    if not ms:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%b %d, %Y")


def normalize_api_url(raw):
    """DATTO_SAAS_PROTECTION_API_URL may be entered with or without a
    scheme — normalize the same way collect_autotask.py and
    collect_sophos.py do for their base URLs."""
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    return f"{parsed.scheme}://{parsed.netloc}"


def load_config():
    load_dotenv()
    required = ["DATTO_SAAS_PROTECTION_PUBLIC_KEY", "DATTO_SAAS_PROTECTION_SECRET_KEY", "DATTO_SAAS_PROTECTION_API_URL"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        sys.exit(f"Missing required .env values: {', '.join(missing)}")
    return {
        "public_key": os.getenv("DATTO_SAAS_PROTECTION_PUBLIC_KEY"),
        "secret_key": os.getenv("DATTO_SAAS_PROTECTION_SECRET_KEY"),
        "api_url": normalize_api_url(os.getenv("DATTO_SAAS_PROTECTION_API_URL")),
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
    saas_customer_id = client.get("datto_saas_protection", {}).get("saas_customer_id")
    if not saas_customer_id:
        sys.exit(f"{client['name']} has sources.datto_saas_protection true but no saas_customer_id set in clients.yaml.")

    auth = HTTPBasicAuth(cfg["public_key"], cfg["secret_key"])
    resp = requests.get(f"{cfg['api_url']}/v1/saas/domains", auth=auth)
    if not resp.ok:
        sys.exit(
            f"Datto SaaS Protection API error {resp.status_code}: {resp.text}\n"
            f"If this is a 401, check that the API key's 'Select Vendor' field is blank — "
            f"a key scoped to any vendor is confirmed to break this endpoint."
        )
    domains = resp.json()
    if verbose:
        print(f"[debug] /v1/saas/domains returned {len(domains)} customer(s)")

    matched = next((d for d in domains if int(d.get("saasCustomerId", -1)) == int(saas_customer_id)), None)
    if matched is None:
        sys.exit(
            f"saas_customer_id {saas_customer_id} not found among the {len(domains)} customers this "
            f"credential can see. Available IDs: {[d.get('saasCustomerId') for d in domains]}"
        )
    if verbose:
        print(f"[debug] matched customer: {json.dumps(matched, indent=2)}")

    stats = matched.get("backupStats", {})

    # Per-service (OneDrive/Exchange/SharePoint/Teams) mini-panel data —
    # confirmed live against /v1/saas/{customerId}/applications on
    # 2026-09-01. Each appType's backupHistory is a list of rolling time
    # windows; index 0 is always the most recent ("Between0dAnd1d") window,
    # which is what the client-facing mini-panel should show. This
    # endpoint does NOT expose "Backups/Exports/Restores In Progress"
    # live counters or a "Total Protected Data" size the way the Datto
    # partner-portal UI does — those fields simply aren't in this response,
    # so the report's mini-panel omits them rather than fabricating zeros.
    saas_apps = []
    apps_resp = requests.get(f"{cfg['api_url']}/v1/saas/{saas_customer_id}/applications", auth=auth)
    if apps_resp.ok:
        apps_data = apps_resp.json()
        for item in apps_data.get("items", []):
            for suite in item.get("suites", []):
                for app in suite.get("appTypes", []):
                    history = app.get("backupHistory") or []
                    latest = history[0] if history else {}
                    saas_apps.append({
                        "app_type": app.get("appType"),
                        "label": _friendly_app_label(app.get("appType", "")),
                        "active_count": latest.get("activeServiceCount"),
                        "protected_count": latest.get("activeServiceWithPerfectBackupCount"),
                        "total_count": latest.get("totalServiceCount"),
                        "status": latest.get("status"),
                        "last_fully_protected": _ms_to_date_str(latest.get("endTime")),
                    })
    elif verbose:
        print(f"[warn] /v1/saas/{saas_customer_id}/applications returned {apps_resp.status_code} — skipping per-app mini-panel")

    return {
        "datto_saas_protection": {
            "saas_customer_id": saas_customer_id,
            "seats_used": matched.get("seatsUsed"),
            "product_type": matched.get("productType"),
            "active_services_count": stats.get("activeServicesCount"),
            "active_services_with_recent_backup_count": stats.get("activeServicesWithRecentBackupCount"),
            "backup_percentage": stats.get("backupPercentage"),
            "saas_apps": saas_apps,
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Collect Datto SaaS Protection status for one client.")
    parser.add_argument("--client", required=True, help="Client slug as it appears in clients.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Print results instead of writing a file")
    parser.add_argument("--verbose", action="store_true", help="Print diagnostic info about the API responses")
    args = parser.parse_args()

    cfg = load_config()
    client = load_client(cfg["client_map"], args.client)

    if not client.get("sources", {}).get("datto_saas_protection", False):
        print(f"[skip] {client['name']}: sources.datto_saas_protection is false — nothing to collect.")
        return

    print(f"Collecting Datto SaaS Protection data for {client['name']}...")
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

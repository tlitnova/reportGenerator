#!/usr/bin/env python3
"""
collect_addigy.py — pull the Addigy portion of client_month.json for one client
(macOS/iOS device compliance, encryption, and staleness).

Usage:
    python collect_addigy.py --client client-3 --dry-run --verbose
    python collect_addigy.py --client client-3

Auth: single credential (ADDIGY_ORG_ID + ADDIGY_API_SECRET) covers every
client — devices are filtered per-client by policy_id, per clients.yaml.
API v1 was deprecated (March 31, 2026), so this uses v2 exclusively.

Confirmed against real data:
  - Auth header is x-api-key (not Authorization/Bearer, an earlier wrong guess).
  - Response fields live nested under facts.{name}.value, not flat on the device.
  - The endpoint only returns a small default fact set unless you name the
    ones you want via desired_fact_identifiers.
  - Fractional seconds on timestamps vary in digit count — normalized before parsing.

Scoping note: policy_id alone returns every device ever enrolled, including
ones untouched for years (confirmed: some 700+ days silent). Addigy's own
Executive report implicitly scopes to an active date range, so this
collector does the same — see ACTIVE_FLEET_DAYS below — rather than
surfacing years-old ghost devices as if they were this month's problem.

Requires: requests, pyyaml, python-dotenv  (pip install requests pyyaml python-dotenv)
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

import requests
import yaml
from dotenv import load_dotenv

ADDIGY_API_BASE = "https://api.addigy.com/api/v2"
STALE_DAYS = 30

# A device silent longer than this is treated as historical/decommissioned,
# not part of the "current fleet" — excluded from needs_attention entirely
# (matching how Addigy's own Executive report implicitly scopes to a date
# range) but still counted separately so nothing is silently dropped.
ACTIVE_FLEET_DAYS = 180

# Fuzzy device-type classification from whichever model-name-like fact is
# present — exact fact name for this isn't confirmed, so this tries a few
# candidates and reports via --verbose which one (if any) actually has data.
DEVICE_TYPE_FACT_CANDIDATES = ["hardware_model", "device_model_name", "product_name"]


def load_config():
    load_dotenv()
    required = ["ADDIGY_ORG_ID", "ADDIGY_API_SECRET"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        sys.exit(f"Missing required .env values: {', '.join(missing)}")
    return {
        "org_id": os.getenv("ADDIGY_ORG_ID"),
        "api_secret": os.getenv("ADDIGY_API_SECRET"),
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


def _facts_list(base_facts_wanted):
    return base_facts_wanted + DEVICE_TYPE_FACT_CANDIDATES


def _filter_actually_worked(items, policy_id):
    """Checks a returned device's own policy_ids fact to confirm the filter
    genuinely took effect — confirmed necessary against real data: a 200
    response with a plausible-looking device list was observed even when
    the filter was completely ignored (same 189-device total for two
    different policy IDs)."""
    for d in items[:5]:
        entry = d.get("facts", {}).get("policy_ids")
        if isinstance(entry, dict) and entry.get("value"):
            return policy_id in entry["value"]
    return None  # couldn't verify either way — no device had the fact populated


def fetch_devices(cfg, policy_id, verbose=False):
    """POST the Universal Device Search endpoint, filtered to one policy.
    Confirmed: Addigy v2 authenticates via an x-api-key header specifically —
    not Authorization/Bearer, which was an earlier wrong guess here.

    The filter shape is NOT yet confirmed — a 200 response was observed that
    silently ignored the filter entirely (identical ~189-device results for
    two genuinely different policy IDs). Rather than guess once more, this
    tries several real candidate shapes in order and verifies each one
    against actual returned data before trusting it."""
    headers = {"x-api-key": cfg["api_secret"], "Content-Type": "application/json"}
    base_facts = ["device_name", "mac_os_x_version", "is_compliant", "filevault_enabled", "last_online", "online", "policy_ids"]

    candidates = [
        ("top-level policy_id param", {"policy_id": policy_id, "desired_fact_identifiers": _facts_list(base_facts)}),
        ("top-level filters, policy_ids field", {
            "filters": [{"audit_field": "policy_ids", "type": "list", "operation": "contains", "value": [policy_id]}],
            "desired_fact_identifiers": _facts_list(base_facts),
        }),
        ("nested query.filters, policy_ids field", {
            "query": {"filters": [{"audit_field": "policy_ids", "type": "list", "operation": "contains", "value": [policy_id]}]},
            "desired_fact_identifiers": _facts_list(base_facts),
        }),
    ]

    last_items, last_total = [], None
    for label, body in candidates:
        resp = requests.post(f"{ADDIGY_API_BASE}/devices", headers=headers, json=body)
        if verbose:
            print(f"[debug] tried '{label}' -> HTTP {resp.status_code}")
        if not resp.ok:
            if verbose:
                print(f"[debug]   body rejected: {resp.text[:300]}")
            continue
        data = resp.json()
        items = data.get("items", data if isinstance(data, list) else [])
        total = data.get("metadata", {}).get("total")
        if verbose:
            print(f"[debug]   metadata: {data.get('metadata')}")
        last_items, last_total = items, total

        worked = _filter_actually_worked(items, policy_id)
        if worked:
            if verbose:
                print(f"[debug]   VERIFIED: a returned device's policy_ids actually contains {policy_id} — using this shape")
            return items
        elif worked is False and verbose:
            print(f"[debug]   filter did not take effect (returned device's policy_ids doesn't include {policy_id})")

    print(
        f"[warn] none of the tried request shapes could be verified as actually filtering by policy "
        f"{policy_id} — falling back to the last response (total={last_total}). Numbers below may "
        f"reflect the wrong device set. This needs Addigy's real Swagger/API docs "
        f"(api.addigy.com/api/v2/documentation) checked directly for the correct filter shape."
    )
    return last_items


def classify_device_type(model_string):
    """Fuzzy-classifies a device as Mac/iPhone/iPad from whatever
    model-name-like string we got — exact field confirmed empirically per
    account, this just does simple substring matching once we have one."""
    if not model_string:
        return "Unknown"
    s = str(model_string).lower()
    if "ipad" in s:
        return "iPad"
    if "iphone" in s:
        return "iPhone"
    if "macbook" in s or "imac" in s or "mac mini" in s or "mac pro" in s or "macbookpro" in s or "macbookair" in s:
        return "Mac"
    return "Unknown"


def collect(cfg, client, verbose=False):
    policy_id = client.get("addigy", {}).get("policy_id")
    if not policy_id:
        sys.exit(f"{client['name']} has sources.addigy true but no policy_id set in clients.yaml.")

    devices = fetch_devices(cfg, policy_id, verbose=verbose)
    if verbose:
        print(f"[debug] devices returned for policy {policy_id}: {len(devices)}")
        if devices:
            print(f"[debug] sample device: {json.dumps(devices[0], indent=2)[:1500]}")

    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=STALE_DAYS)
    active_fleet_cutoff = now - timedelta(days=ACTIVE_FLEET_DAYS)

    def parse_addigy_timestamp(raw):
        """Addigy's fractional-second digit count varies (seen both 1 and
        3 digits), which trips Python's fromisoformat on this version —
        strip fractional seconds entirely since day-level precision is all
        we need here."""
        cleaned = re.sub(r"\.\d+Z$", "Z", str(raw)).replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)

    device_type_mix = {"Mac": 0, "iPhone": 0, "iPad": 0, "Unknown": 0}
    os_mix = {}
    compliant_count = 0
    non_compliant_devices = []
    filevault_off_devices = []
    stale_devices = []
    long_inactive_devices = []
    active_fleet_count = 0
    # Keyed by agentid (unique per device), not display name — multiple
    # real devices can share the same human-friendly name (confirmed
    # against real data: two separate iPads both named "Adam's iPad"),
    # and keying by name was silently merging their separate issues into
    # one nonsensical combined entry.
    attention_by_agent = {}

    for d in devices:
        facts = d.get("facts", {})
        agent_id = d.get("agentid", "unknown-agent")

        def fact(name):
            """Extracts a fact's value — confirmed real shape is
            facts.{name} = {"value": ..., "type": ..., "error_msg": ...},
            not a flat field on the device object."""
            entry = facts.get(name)
            return entry.get("value") if isinstance(entry, dict) else None

        name = fact("device_name") or agent_id or "unknown-device"

        last_online = fact("last_online")
        last_online_dt = None
        if last_online:
            try:
                last_online_dt = parse_addigy_timestamp(last_online)
            except ValueError:
                if verbose:
                    print(f"[debug] could not parse last_online value for {name}: {last_online!r}")

        # Devices silent longer than ACTIVE_FLEET_DAYS are historical —
        # counted, but excluded from the fleet-health metrics below so a
        # personal iPad dark since 2024 doesn't skew this month's numbers.
        if last_online_dt is not None and last_online_dt < active_fleet_cutoff:
            long_inactive_devices.append(name)
            continue

        active_fleet_count += 1

        mac_os_version = fact("mac_os_x_version")

        # A populated mac_os_x_version is itself direct proof the device is
        # a Mac — confirmed against real data that hardware_model/
        # device_model_name/product_name are sometimes empty specifically
        # on Mac devices (which is why they were showing up as "Unknown"
        # type despite having a real macOS version — the OS data and the
        # model-name data don't always come from the same populated fact
        # on the same device). Only fall back to model-string matching for
        # devices that aren't already confirmed as Mac this way.
        if mac_os_version:
            device_type = "Mac"
        else:
            model_string = None
            for candidate in DEVICE_TYPE_FACT_CANDIDATES:
                model_string = fact(candidate)
                if model_string:
                    if verbose and d is devices[0]:
                        print(f"[debug] device type fact '{candidate}' has data: {model_string!r}")
                    break
            device_type = classify_device_type(model_string)
        device_type_mix[device_type] = device_type_mix.get(device_type, 0) + 1

        os_version = mac_os_version or f"Unknown ({device_type})"
        os_mix[os_version] = os_mix.get(os_version, 0) + 1

        reasons = []
        is_compliant = fact("is_compliant")
        if is_compliant:
            compliant_count += 1
        elif is_compliant is False:
            non_compliant_devices.append(name)
            reasons.append("not compliant")

        if fact("filevault_enabled") is False:
            filevault_off_devices.append(name)
            reasons.append("FileVault disabled")

        if last_online_dt is not None and last_online_dt < stale_cutoff:
            stale_devices.append(name)
            days_silent = (now - last_online_dt).days
            reasons.append(f"no contact in {days_silent} days")

        if reasons:
            attention_by_agent[agent_id] = {"device": name, "reason": ", ".join(reasons)}

    needs_attention = list(attention_by_agent.values())

    return {
        "addigy": {
            "total_ever_enrolled_count": len(devices),
            "active_fleet_count": active_fleet_count,
            "long_inactive_count": len(long_inactive_devices),
            "long_inactive_devices": long_inactive_devices,
            "device_type_mix": device_type_mix,
            "os_mix": os_mix,
            "compliant_count": compliant_count,
            "non_compliant_devices": non_compliant_devices,
            "filevault_off_devices": filevault_off_devices,
            "stale_30day_count": len(stale_devices),
            "stale_30day_devices": stale_devices,
            "needs_attention": needs_attention,
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Collect Addigy device status for one client.")
    parser.add_argument("--client", required=True, help="Client slug as it appears in clients.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Print results instead of writing a file")
    parser.add_argument("--verbose", action="store_true", help="Print diagnostic info about the API responses")
    args = parser.parse_args()

    cfg = load_config()
    client = load_client(cfg["client_map"], args.client)

    if not client.get("sources", {}).get("addigy", False):
        print(f"[skip] {client['name']}: sources.addigy is false — nothing to collect.")
        return

    print(f"Collecting Addigy data for {client['name']}...")
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

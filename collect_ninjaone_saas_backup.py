#!/usr/bin/env python3
"""
collect_ninjaone_saas_backup.py — pull NinjaOne SaaS Backup (Dropsuite)
status for one client (M365/Google Workspace email backup).

Usage:
    python collect_ninjaone_saas_backup.py --client client-4 --dry-run --verbose

CONFIRMED against the real "REST API for Sub-reseller ver 1.0.0" spec
(found on ninjaone.com, not the Zendesk-locked version):
  - Auth headers are exactly X-Reseller-Token and X-Access-Token — earlier
    attempts tried many close variants (Auth-Token, X-Auth-Token,
    Authorization, etc.) but never this exact pair, which was the entire
    bug. A third "Secret Token" shown in the portal's API Information page
    is NOT used anywhere in this API at all — a dead end, not a missing
    piece.
  - X-Access-Token here is the RESELLER-level "Authentication Token" (the
    one from Settings > API Settings, same portal page as Reseller Token)
    — not a per-organization token. Some endpoints in the spec instead want
    a per-organization token found under that org's own "Login Accounts"
    tab; this collector only uses the reseller-level endpoints, which take
    the simpler reseller-wide token.
  - GET /users/{id} — {id} is exactly the value already stored as
    ninjaone_saas_backup.organization_id in clients.yaml (confirmed format:
    e.g. "1788161-14") — returns a subscription summary directly: seats
    used/available, storage, organization name, active seats.
  - GET /users/{id}/tenants — list of domains under that subscription, each
    with total_users and status.
  - Base URL: https://dropsuite.us/api (confirmed from the real API
    Information page + spec's example paths).

Requires: requests, pyyaml, python-dotenv  (pip install requests pyyaml python-dotenv)
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
import yaml
from dotenv import load_dotenv


def default_month():
    """Previous calendar month, in YYYY-MM — matches every other collector's default."""
    first_of_this_month = datetime.today().replace(day=1)
    return (first_of_this_month - timedelta(days=1)).strftime("%Y-%m")


def resolve_month(candidate):
    """Only accepts a strict YYYY-MM string; anything else (None, empty, or
    a malformed value like a stray comment fragment from a .env parser that
    doesn't strip trailing comments) is treated as unset. This is a real bug
    class worth guarding against generally, not just here — confirmed to
    happen with REPORT_MONTH's default template value."""
    if candidate and re.fullmatch(r"\d{4}-\d{2}", candidate.strip()):
        return candidate.strip()
    return None


def month_bounds_utc(month_str):
    year, month = (int(x) for x in month_str.split("-"))
    start = datetime(year, month, 1, tzinfo=timezone.utc)
    end = datetime(year + 1, 1, 1, tzinfo=timezone.utc) if month == 12 else datetime(year, month + 1, 1, tzinfo=timezone.utc)
    return start, end


def normalize_api_url(raw):
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    return f"{parsed.scheme}://{parsed.netloc}"


def load_config():
    load_dotenv()
    required = ["NINJA_SAAS_BACKUP_RESELLER_TOKEN", "NINJA_SAAS_BACKUP_AUTH_TOKEN", "NINJA_SAAS_BACKUP_API_URL"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        sys.exit(f"Missing required .env values: {', '.join(missing)}")
    return {
        "reseller_token": os.getenv("NINJA_SAAS_BACKUP_RESELLER_TOKEN"),
        "auth_token": os.getenv("NINJA_SAAS_BACKUP_AUTH_TOKEN"),
        "api_url": normalize_api_url(os.getenv("NINJA_SAAS_BACKUP_API_URL")),
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


class DropsuiteClient:
    def __init__(self, cfg, access_token=None):
        self.base_url = f"{cfg['api_url']}/api"
        self.headers = {
            "X-Reseller-Token": cfg["reseller_token"],
            # Confirmed against real data: GET /users/{id} needs the
            # reseller-wide Admin Token, but GET /users/{id}/tenants,
            # /accounts, /delegated, /retention_policies all need a
            # DIFFERENT, per-organization-specific token instead (found on
            # that org's own "Login Accounts" tab in the portal) — a 401
            # with "not authorized to perform this action" on those
            # specific endpoints while /users/{id} works fine is the tell.
            "X-Access-Token": access_token or cfg["auth_token"],
        }

    def get(self, path, params=None):
        resp = requests.get(f"{self.base_url}{path}", headers=self.headers, params=params or {})
        if not resp.ok:
            sys.exit(f"Dropsuite API error {resp.status_code} for {resp.url}:\n{resp.text}")
        return resp.json()

    def get_all_pages(self, path, params=None):
        """Follows the confirmed pagination shape from the spec (pagination.
        next_page present until the final page) rather than guessing at one."""
        params = dict(params or {})
        params.setdefault("per_page", 100)
        items = []
        page = 1
        while True:
            params["page"] = page
            data = self.get(path, params=params)
            items.extend(data.get("data", []))
            pagination = data.get("pagination", {})
            if "next_page" not in pagination:
                break
            page = pagination["next_page"]
        return items


def lookup_org_auth_token(admin_client, org_id, verbose=False):
    """GET /users (reseller-wide list, works with the admin token we already
    have confirmed working) returns every organization WITH ITS OWN
    authentication_token embedded directly in each entry — confirmed from
    the spec's own sample response. This means the per-organization token
    /tenants and /accounts need can be found programmatically, with no
    manual portal hunting required."""
    all_orgs = admin_client.get("/users")
    # Spec shows GET /users returning either a bare list or {"data": [...]}
    # depending on endpoint family — handle both.
    orgs = all_orgs.get("data", all_orgs) if isinstance(all_orgs, dict) else all_orgs
    if verbose:
        print(f"[debug] GET /users returned {len(orgs)} organization(s)")
    for org in orgs:
        if str(org.get("id")) == str(org_id) or str(org.get("organization_id")) == str(org_id):
            if verbose:
                print(f"[debug] matched org_id {org_id} -> found its own authentication_token")
            return org.get("authentication_token")
    if verbose:
        print(f"[debug] org_id {org_id} not found in GET /users response")
    return None


def collect(cfg, client, month_str, verbose=False):
    org_id = client.get("ninjaone_saas_backup", {}).get("organization_id")
    if not org_id:
        sys.exit(f"{client['name']} has sources.ninjaone_saas_backup true but no organization_id set in clients.yaml.")

    month_start, month_end = month_bounds_utc(month_str)

    # /users/{id} works with the reseller-wide admin token.
    admin_client = DropsuiteClient(cfg)
    subscription = admin_client.get(f"/users/{org_id}")
    if verbose:
        print(f"[debug] GET /users/{org_id}: {json.dumps(subscription, indent=2)}")

    result = {
        "ninjaone_saas_backup": {
            "month": month_str,
            "organization_id": org_id,
            "organization_name": subscription.get("organization_name"),
            "seats_used": subscription.get("seats_used"),
            "seats_available": subscription.get("seats_available"),
            "active_seats": subscription.get("active_seats"),
            "deactivated_seats": subscription.get("deactivated_seats"),
            "storage_used": subscription.get("storage_used"),
            "storage_available": subscription.get("storage_available"),
            "archive_enabled": subscription.get("archive"),
        }
    }

    # Look up this org's own authentication_token automatically, rather
    # than requiring it be manually found in a portal UI and hand-entered
    # per client — confirmed derivable from GET /users' own response shape.
    org_token = lookup_org_auth_token(admin_client, org_id, verbose=verbose)
    if not org_token:
        print(
            f"[warn] could not find org_id {org_id}'s own authentication_token via GET /users — "
            f"skipping tenant/mailbox detail (subscription summary above is still real data, "
            f"just without per-mailbox breakdown)."
        )
        result["ninjaone_saas_backup"]["tenants"] = None
        result["ninjaone_saas_backup"]["total_mailboxes"] = None
        return result

    org_client = DropsuiteClient(cfg, access_token=org_token)
    tenants_resp = org_client.get(f"/users/{org_id}/tenants")
    tenants = tenants_resp.get("data", [])
    if verbose:
        print(f"[debug] GET /users/{org_id}/tenants: {len(tenants)} tenant(s)")
        if tenants:
            print(f"[debug] sample tenant: {json.dumps(tenants[0], indent=2)}")

    status_counts = {"active": 0, "available": 0, "excluded": 0}
    added_this_month = []
    total_mailboxes = 0

    for tenant in tenants:
        accounts = org_client.get_all_pages(
            f"/users/{org_id}/tenants/{tenant.get('id')}/accounts",
            params={"type": tenant.get("type")},
        )
        if verbose:
            print(f"[debug] tenant {tenant.get('domain')}: {len(accounts)} account(s)")

        for acct in accounts:
            if not acct.get("mailbox"):
                continue
            total_mailboxes += 1
            status = acct.get("status")
            if status in status_counts:
                status_counts[status] += 1

            created_at = acct.get("created_at")
            if created_at:
                try:
                    created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                    if month_start <= created_dt < month_end:
                        added_this_month.append(acct.get("email"))
                except ValueError:
                    if verbose:
                        print(f"[debug] could not parse created_at for {acct.get('email')}: {created_at!r}")

    result["ninjaone_saas_backup"].update({
        "tenants": [
            {"domain": t.get("domain"), "type": t.get("type"), "status": t.get("status"), "total_users": t.get("total_users")}
            for t in tenants
        ],
        "total_mailboxes": total_mailboxes,
        "mailboxes_active": status_counts["active"],
        "mailboxes_available_not_backed_up": status_counts["available"],
        "mailboxes_excluded": status_counts["excluded"],
        "mailboxes_added_this_month": len(added_this_month),
        "mailboxes_added_this_month_emails": added_this_month,
        "mailboxes_removed_this_month": None,
    })
    return result


def main():
    parser = argparse.ArgumentParser(description="Collect NinjaOne SaaS Backup status for one client.")
    parser.add_argument("--client", required=True, help="Client slug as it appears in clients.yaml")
    parser.add_argument("--month", default=None, help="YYYY-MM; defaults to previous calendar month (used for mailboxes_added_this_month)")
    parser.add_argument("--dry-run", action="store_true", help="Print results instead of writing a file")
    parser.add_argument("--verbose", action="store_true", help="Print diagnostic info about the API responses")
    args = parser.parse_args()

    cfg = load_config()
    client = load_client(cfg["client_map"], args.client)

    if not client.get("sources", {}).get("ninjaone_saas_backup", False):
        print(f"[skip] {client['name']}: sources.ninjaone_saas_backup is false — nothing to collect.")
        return

    month_str = resolve_month(args.month) or resolve_month(os.getenv("REPORT_MONTH")) or default_month()

    print(f"Collecting NinjaOne SaaS Backup data for {client['name']}...")
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

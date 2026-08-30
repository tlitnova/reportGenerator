#!/usr/bin/env python3
"""
collect_autotask.py — pull the Autotask portion of client_month.json for one client/month.

Usage:
    python collect_autotask.py --client brock-norton --month 2026-07 --dry-run
    python collect_autotask.py --client brock-norton --month 2026-07

What this pulls, and why (see Research Findings.md for the source fields):
  - Tickets resolved in the month, with first-response-met % and resolution-met %
    (native Autotask SLA fields — serviceLevelAgreementHasBeenMet, firstResponseDateTime,
    firstResponseDueDateTime, resolvedDateTime, resolvedDueDateTime)
  - Hours worked in the month, grouped by ticket issue type (TimeEntries + Tickets join)

Requires: requests, pyyaml, python-dotenv  (pip install requests pyyaml python-dotenv)
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import requests
import yaml
from dotenv import load_dotenv

# --- Config -------------------------------------------------------------

# Autotask enforces a per-query item limit on "in" filters. This number is a
# conservative starting point, not a documented constant — if a query errors
# out with something like "too many filter items", lower this.
TICKET_ID_CHUNK_SIZE = 200

# How a ticket is considered "touched this month" for the time-entries pull.
# We can't cheaply ask Autotask "which tickets had time logged in month X"
# directly, so we widen the candidate set using lastActivityDate (which
# updates whenever a note or time entry is added) and then filter precisely
# on TimeEntries.dateWorked. If your numbers look short here, the most likely
# cause is a ticket where time was logged this month but lastActivityDate
# fell outside the window some other way — flag the specific ticket number
# and we can tighten this.


def normalize_zone_url(raw):
    """AUTOTASK_ZONE_URL can arrive in a few shapes depending on what the
    zoneInformation lookup returned or how it was pasted in — sometimes just
    the host, sometimes with /atservicesrest or /v1.0 already attached.
    Extract the scheme+host and always rebuild the same way so the rest of
    the script doesn't have to guess."""
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    return f"{parsed.scheme}://{parsed.netloc}/atservicesrest/v1.0"


def load_config():
    load_dotenv()
    required = ["AUTOTASK_USERNAME", "AUTOTASK_SECRET", "AUTOTASK_INTEGRATION_CODE", "AUTOTASK_ZONE_URL"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        sys.exit(f"Missing required .env values: {', '.join(missing)}")
    return {
        "username": os.getenv("AUTOTASK_USERNAME"),
        "secret": os.getenv("AUTOTASK_SECRET"),
        "integration_code": os.getenv("AUTOTASK_INTEGRATION_CODE"),
        "zone_url": normalize_zone_url(os.getenv("AUTOTASK_ZONE_URL")),
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
    as timezone-aware datetimes spanning that calendar month in local time,
    converted to UTC — since Autotask stores/returns all timestamps in UTC."""
    tz = ZoneInfo(tz_name)
    year, month = (int(x) for x in month_str.split("-"))
    start_local = datetime(year, month, 1, tzinfo=tz)
    if month == 12:
        end_local = datetime(year + 1, 1, 1, tzinfo=tz)
    else:
        end_local = datetime(year, month + 1, 1, tzinfo=tz)
    return start_local.astimezone(ZoneInfo("UTC")), end_local.astimezone(ZoneInfo("UTC"))


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class AutotaskClient:
    def __init__(self, cfg):
        self.base_url = cfg["zone_url"]
        self.headers = {
            "ApiIntegrationCode": cfg["integration_code"],
            "UserName": cfg["username"],
            "Secret": cfg["secret"],
            "Content-Type": "application/json",
            # Autotask's REST API sits behind Akamai, which blocks the default
            # "python-requests/x.x" User-Agent as bot traffic before the
            # request ever reaches Autotask itself (an "Access Denied" page
            # from errors.edgesuite.net, not an Autotask permissions error,
            # is the tell). A normal-looking User-Agent avoids that.
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        }
        self._picklist_cache = {}

    def _check(self, resp):
        if not resp.ok:
            # Autotask returns a JSON body with the real reason (zone mismatch,
            # invalid integration code, insufficient permissions, etc.) that
            # requests' default exception doesn't show — surface it directly.
            try:
                detail = resp.json()
            except ValueError:
                detail = resp.text
            sys.exit(f"Autotask API error {resp.status_code} for {resp.url}:\n{detail}")

    def query(self, entity, filter_body, max_records=500):
        """Runs a query and pages through all results via nextPageUrl.
        The first request is a POST with the filter in the body; nextPageUrl
        is a complete, self-contained URL (query + paging state), so
        subsequent pages are plain GETs against it."""
        items = []
        resp = requests.post(
            f"{self.base_url}/{entity}/query",
            headers=self.headers,
            json={"MaxRecords": max_records, "filter": filter_body},
        )
        self._check(resp)
        data = resp.json()
        items.extend(data.get("items", []))
        next_url = data.get("pageDetails", {}).get("nextPageUrl")

        while next_url:
            resp = requests.get(next_url, headers=self.headers)
            self._check(resp)
            data = resp.json()
            items.extend(data.get("items", []))
            next_url = data.get("pageDetails", {}).get("nextPageUrl")

        return items

    def picklist(self, entity, field_name):
        """Returns {picklist_value: label} for a picklist field, cached per run."""
        cache_key = (entity, field_name)
        if cache_key in self._picklist_cache:
            return self._picklist_cache[cache_key]
        resp = requests.get(f"{self.base_url}/{entity}/entityInformation/fields", headers=self.headers)
        self._check(resp)
        fields = resp.json().get("fields", [])
        mapping = {}
        for f in fields:
            if f.get("name") == field_name and f.get("isPickList"):
                for pv in f.get("picklistValues") or []:
                    # Autotask's picklist metadata returns option values as
                    # strings even for integer-backed fields, while the
                    # entity data itself returns them as numbers — normalize
                    # both sides to strings so the lookup actually matches.
                    mapping[str(pv["value"])] = pv["label"]
        self._picklist_cache[cache_key] = mapping
        return mapping


def and_filter(*conditions):
    """Wraps multiple conditions in Autotask's explicit AND grouping.
    (Using this everywhere rather than a flat multi-item list, since the
    flat form's AND-vs-error behavior isn't consistently documented —
    explicit grouping is unambiguous.)"""
    return [{"op": "and", "items": list(conditions)}]


def collect(cfg, client, month_str):
    company_id = client["autotask"]["company_id"]
    at = AutotaskClient(cfg)
    start_utc, end_utc = month_range_utc(month_str, cfg["timezone"])
    start_iso, end_iso = iso(start_utc), iso(end_utc)

    # --- Tickets resolved in the month, with SLA fields ---
    resolved_tickets = at.query(
        "Tickets",
        and_filter(
            {"op": "eq", "field": "companyID", "value": company_id},
            {"op": "gte", "field": "resolvedDateTime", "value": start_iso},
            {"op": "lt", "field": "resolvedDateTime", "value": end_iso},
        ),
    )

    resolved_count = len(resolved_tickets)
    first_response_met = sum(
        1 for t in resolved_tickets
        if t.get("firstResponseDateTime") and t.get("firstResponseDueDateTime")
        and t["firstResponseDateTime"] <= t["firstResponseDueDateTime"]
    )
    first_response_eligible = sum(1 for t in resolved_tickets if t.get("firstResponseDueDateTime"))
    resolution_met = sum(
        1 for t in resolved_tickets
        if t.get("resolvedDateTime") and t.get("resolvedDueDateTime")
        and t["resolvedDateTime"] <= t["resolvedDueDateTime"]
    )
    resolution_eligible = sum(1 for t in resolved_tickets if t.get("resolvedDueDateTime"))

    first_response_met_pct = round(100 * first_response_met / first_response_eligible, 1) if first_response_eligible else None
    resolution_met_pct = round(100 * resolution_met / resolution_eligible, 1) if resolution_eligible else None

    # --- Candidate tickets for time-entry categorization (see note at top) ---
    candidate_tickets = at.query(
        "Tickets",
        and_filter(
            {"op": "eq", "field": "companyID", "value": company_id},
            {"op": "gte", "field": "lastActivityDate", "value": start_iso},
            {"op": "lt", "field": "lastActivityDate", "value": end_iso},
        ),
    )
    ticket_issue_type = {t["id"]: t.get("issueType") for t in candidate_tickets}
    issue_type_labels = at.picklist("Tickets", "issueType")

    if cfg.get("verbose"):
        print(f"[debug] candidate_tickets (lastActivityDate in month): {len(candidate_tickets)}")
        print(f"[debug] issueType picklist entries loaded: {len(issue_type_labels)}")

    time_entries = []
    ticket_ids = list(ticket_issue_type.keys())
    for i in range(0, len(ticket_ids), TICKET_ID_CHUNK_SIZE):
        chunk = ticket_ids[i:i + TICKET_ID_CHUNK_SIZE]
        if not chunk:
            continue
        time_entries.extend(at.query(
            "TimeEntries",
            and_filter(
                {"op": "in", "field": "ticketID", "value": chunk},
                {"op": "gte", "field": "dateWorked", "value": start_iso},
                {"op": "lt", "field": "dateWorked", "value": end_iso},
            ),
        ))

    hours_by_category = {}
    total_hours = 0.0
    tickets_with_time = set()
    for te in time_entries:
        hours = float(te.get("hoursWorked") or 0)
        total_hours += hours
        tickets_with_time.add(te.get("ticketID"))
        issue_type_val = ticket_issue_type.get(te.get("ticketID"))
        label = issue_type_labels.get(str(issue_type_val), "Uncategorized")
        hours_by_category[label] = round(hours_by_category.get(label, 0) + hours, 2)
        if cfg.get("verbose") and label == "Uncategorized":
            in_candidates = te.get("ticketID") in ticket_issue_type
            print(f"[debug] ticket {te.get('ticketID')} -> Uncategorized "
                  f"(in candidate set: {in_candidates}, issueType value: {issue_type_val!r})")

    return {
        "autotask": {
            "month": month_str,
            "tickets_resolved": resolved_count,
            "first_response_met_pct": first_response_met_pct,
            "resolution_met_pct": resolution_met_pct,
            "hours_worked_total": round(total_hours, 2),
            "hours_worked_by_category": hours_by_category,
            "ticket_count_with_time": len(tickets_with_time),
        }
    }


def default_month():
    """Previous calendar month, in YYYY-MM."""
    first_of_this_month = datetime.today().replace(day=1)
    last_month = first_of_this_month - timedelta(days=1)
    return last_month.strftime("%Y-%m")


def main():
    parser = argparse.ArgumentParser(description="Collect Autotask metrics for one client/month.")
    parser.add_argument("--client", required=True, help="Client slug as it appears in clients.yaml")
    parser.add_argument("--month", default=None, help="YYYY-MM; defaults to previous calendar month")
    parser.add_argument("--dry-run", action="store_true", help="Print results instead of writing a file")
    parser.add_argument("--verbose", action="store_true", help="Print diagnostic info about the categorization join")
    args = parser.parse_args()

    cfg = load_config()
    cfg["verbose"] = args.verbose
    client = load_client(cfg["client_map"], args.client)

    if not client.get("sources", {}).get("autotask", False):
        print(f"[skip] {client['name']}: sources.autotask is false — nothing to collect.")
        return

    month_str = args.month or os.getenv("REPORT_MONTH") or default_month()

    print(f"Collecting Autotask data for {client['name']} ({month_str})...")
    result = collect(cfg, client, month_str)

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

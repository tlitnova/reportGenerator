#!/usr/bin/env python3
"""
collect_mailbox.py — scan the report mailbox for Sophos Email + Phish Threat
scheduled-report attachments, match each to a client, and parse the CSVs.

Usage:
    python collect_mailbox.py --month 2026-07 --dry-run
    python collect_mailbox.py --month 2026-07 --dry-run --client brock-norton
    python collect_mailbox.py --month 2026-07

Unlike the other collectors, this one is NOT per-client by default — it scans
one shared mailbox that receives reports for every client at once, and
matches each email/attachment to whichever client it belongs to. Use
--client to filter to just one client's expected reports while calibrating
the matching logic against real report subjects/filenames.

Why this exists at all: per Research Findings.md, Sophos Email Security has
no general-purpose reporting API for accounts without an XDR/MDR add-on, and
Sophos Phish Threat has no results API at all — scheduled CSV reports to a
mailbox are the only path for both.

Requires: requests, pyyaml, python-dotenv  (pip install requests pyyaml python-dotenv)

CALIBRATION WARNING: the keyword matching (report type, client matching) and
CSV column detection below are best-effort guesses, since the real subject
lines, filenames, and CSV column headers Sophos actually sends are unknown
until we see one. Run with --verbose on real data and expect to adjust the
KEYWORD lists and column-matching below to what actually comes through.
"""

import argparse
import base64
import csv
import io
import json
import os
import re
import sys
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import requests
import yaml
from dotenv import load_dotenv
from pypdf import PdfReader

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# Confirmed against real report PDFs: content-based classification is more
# reliable than filename/subject guessing. The Phish Threat PDF in
# particular has no client name anywhere in its own content (no "Company
# Name" field like the Email report has) — only the campaign name hints at
# the client, so client-matching for it has to search the extracted PDF
# text too, not just the filename/subject.
PDF_EMAIL_MARKERS = ["sophos email", "dashboard summary report", "inbound summary"]
PDF_PHISH_MARKERS = ["phishthreat summary", "campaigns started", "caught users"]

# Kept for CSV attachments and as a subject-line fallback, in case a real
# scheduled email ever arrives with a more descriptive subject than these
# manually-exported filenames had.
EMAIL_REPORT_KEYWORDS = ["email security", "message summary", "sophos email"]
PHISH_REPORT_KEYWORDS = ["phish threat", "phishthreat", "phish-threat"]

# Keyword groups for fuzzy-matching CSV columns without knowing exact header
# names in advance. Each maps an output field to substrings we look for in
# column headers (case-insensitive); matching numeric columns get summed.
EMAIL_COLUMN_KEYWORDS = {
    "emails_scanned": ["scanned"],
    "threats_identified": ["threat", "malware", "spam"],
}
PHISH_COLUMN_KEYWORDS = {
    "emails_sent": ["sent"],
    "opened": ["open"],
    "clicked": ["click"],
    "reported": ["report"],
    "trained": ["train"],
}


def load_config():
    load_dotenv()
    required = ["M365_TENANT_ID", "M365_CLIENT_ID", "M365_CLIENT_SECRET", "REPORT_MAILBOX_ADDRESS"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        sys.exit(f"Missing required .env values: {', '.join(missing)}")
    return {
        "tenant_id": os.getenv("M365_TENANT_ID"),
        "client_id": os.getenv("M365_CLIENT_ID"),
        "client_secret": os.getenv("M365_CLIENT_SECRET"),
        "mailbox": os.getenv("REPORT_MAILBOX_ADDRESS"),
        "folder_name": os.getenv("REPORT_MAILBOX_FOLDER", "Vendor Reports"),
        "timezone": os.getenv("REPORT_TIMEZONE", "UTC"),
        "client_map": os.getenv("CLIENT_MAP", "./clients.yaml"),
        "output_dir": os.getenv("OUTPUT_DIR", "./output"),
    }


def load_clients(client_map_path):
    with open(client_map_path) as f:
        data = yaml.safe_load(f)
    return data["clients"]


def month_range_utc(month_str, tz_name):
    tz = ZoneInfo(tz_name)
    year, month = (int(x) for x in month_str.split("-"))
    start_local = datetime(year, month, 1, tzinfo=tz)
    end_local = datetime(year + 1, 1, 1, tzinfo=tz) if month == 12 else datetime(year, month + 1, 1, tzinfo=tz)
    return start_local.astimezone(ZoneInfo("UTC")), end_local.astimezone(ZoneInfo("UTC"))


def default_month():
    first_of_this_month = datetime.today().replace(day=1)
    return (first_of_this_month - timedelta(days=1)).strftime("%Y-%m")


class GraphClient:
    def __init__(self, cfg):
        self.token = self._get_token(cfg)
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def _get_token(self, cfg):
        resp = requests.post(
            f"https://login.microsoftonline.com/{cfg['tenant_id']}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        if not resp.ok:
            sys.exit(f"Microsoft Graph auth failed ({resp.status_code}): {resp.text}")
        return resp.json()["access_token"]

    def get(self, url, params=None):
        resp = requests.get(url, headers=self.headers, params=params or {})
        if not resp.ok:
            raise RuntimeError(f"Graph API error {resp.status_code} for {resp.url}:\n{resp.text}")
        return resp.json()

    def get_all_pages(self, url, params=None):
        items = []
        while url:
            data = self.get(url, params=params)
            items.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            params = None  # nextLink already includes query params
        return items


def find_folder_id(graph, mailbox, folder_name, verbose=False):
    """Looks for folder_name among top-level mail folders, then falls back
    to checking Inbox's child folders — a common place for a rules-created
    subfolder to live."""
    top_level = graph.get(f"{GRAPH_BASE}/users/{mailbox}/mailFolders", params={"$top": 100}).get("value", [])
    if verbose:
        print(f"[debug] top-level folders: {[f['displayName'] for f in top_level]}")
    for f in top_level:
        if f["displayName"].lower() == folder_name.lower():
            return f["id"]

    inbox = next((f for f in top_level if f["displayName"].lower() == "inbox"), None)
    if inbox:
        children = graph.get(f"{GRAPH_BASE}/users/{mailbox}/mailFolders/{inbox['id']}/childFolders").get("value", [])
        if verbose:
            print(f"[debug] Inbox child folders: {[f['displayName'] for f in children]}")
        for f in children:
            if f["displayName"].lower() == folder_name.lower():
                return f["id"]

    sys.exit(
        f"Could not find a mail folder named '{folder_name}' at the top level or under Inbox. "
        f"Check REPORT_MAILBOX_FOLDER in .env against the real folder name/location."
    )


def classify_report(subject, filename):
    text = f"{subject} {filename}".lower()
    if any(k in text for k in EMAIL_REPORT_KEYWORDS):
        return "sophos_email"
    if any(k in text for k in PHISH_REPORT_KEYWORDS):
        return "sophos_phish_threat"
    return None


def match_client(subject, filename, clients, only_client_slug=None, verbose=False):
    """Matches an email/attachment to a client, in two passes:
    1. Strict: the client's full name or slug (alnum-only) appears
       somewhere in the combined text. High confidence.
    2. Fallback: a single significant word (4+ letters) from the client's
       name appears in the text. Needed for reports like Phish Threat,
       where the only client hint is a campaign name that may only
       partially match (confirmed against real data: "Brock Series"
       shares just the word "Brock" with client "Brock-Norton", not the
       full name) — but this is lower confidence and could mismatch if
       two clients share a common word, so it's flagged when used."""
    text = re.sub(r"[^a-z0-9]", "", f"{subject} {filename}".lower())
    candidates = [c for c in clients if not only_client_slug or c["slug"] == only_client_slug]

    for client in candidates:
        name_key = re.sub(r"[^a-z0-9]", "", client["name"].lower())
        slug_key = re.sub(r"[^a-z0-9]", "", client["slug"].lower())
        if name_key in text or slug_key in text:
            return client

    raw_text = f"{subject} {filename}".lower()
    for client in candidates:
        words = [w for w in re.findall(r"[a-z]+", client["name"].lower()) if len(w) >= 4]
        for word in words:
            if word in raw_text:
                if verbose:
                    print(f"[debug] fuzzy-matched '{client['name']}' via partial word '{word}' — verify this is correct")
                return client
    return None


def sum_matching_columns(rows, keyword_groups, verbose=False):
    """Fuzzy-matches CSV column headers against keyword groups and sums
    numeric values in matching columns. Returns {field: total} plus, when
    verbose, prints which real column name(s) matched each field — this is
    the main calibration point once real CSVs are seen."""
    if not rows:
        return {}
    headers = list(rows[0].keys())
    results = {}
    for field, keywords in keyword_groups.items():
        matched_cols = [h for h in headers if any(k in h.lower() for k in keywords)]
        if verbose:
            print(f"[debug] field '{field}' matched columns: {matched_cols}")
        total = 0
        any_numeric = False
        for col in matched_cols:
            for row in rows:
                val = row.get(col, "")
                try:
                    total += float(val)
                    any_numeric = True
                except (ValueError, TypeError):
                    continue
        results[field] = total if any_numeric else None
    return results


def extract_pdf_pages(content_bytes):
    reader = PdfReader(io.BytesIO(content_bytes))
    return [p.extract_text() or "" for p in reader.pages]


def parse_sophos_email_pdf(pages, verbose=False):
    """Confirmed working against a real Brock-Norton Sophos Email Dashboard
    Summary Report PDF. One important gotcha: page 1's own "Includes" list
    mentions every section name as a table-of-contents bullet, so section
    lookup must check that a page STARTS WITH the header, not just contains
    it anywhere — an earlier version of this matched the TOC bullet instead
    of the real content page and silently returned nothing."""
    full_text = "\n".join(pages)
    out = {}

    m = re.search(r"Company Name\s*\n(.+?)\n", full_text)
    out["company_name"] = m.group(1).strip() if m else None
    m = re.search(r"From (.+?) To (.+?)\n", full_text)
    out["date_range"] = {"from": m.group(1).strip(), "to": m.group(2).strip()} if m else None

    def section_page(keyword):
        for p in pages:
            if p and p.strip().startswith(keyword):
                return p
        return ""

    def num_after(label, text):
        m = re.search(rf"{re.escape(label)}\s*\n?\s*(\d+)", text)
        return int(m.group(1)) if m else None

    def threat_breakdown(section_text):
        breakdown = {}
        table_match = re.search(r"Number of Emails\n(.*?)Total Potential Threats", section_text, re.S)
        if table_match:
            for line in table_match.group(1).strip().split("\n"):
                row = re.match(r"^(.+?)\s(\d+)$", line.strip())
                if row:
                    breakdown[row.group(1)] = int(row.group(2))
        return breakdown

    inbound = section_page("INBOUND SUMMARY")
    out["inbound"] = {
        "mailboxes_protected": num_after("Mailboxes Protected", inbound),
        "emails_scanned": num_after("Inbound Emails Scanned", inbound),
        "legitimate": num_after("Legitimate Emails", inbound),
        "total_potential_threats": num_after("Total Potential Threats", inbound),
        "threat_breakdown": threat_breakdown(inbound),
    }

    outbound = section_page("OUTBOUND SUMMARY")
    out["outbound"] = {
        "mailboxes_protected": num_after("Mailboxes Protected", outbound),
        "emails_scanned": num_after("Outbound Emails Scanned", outbound),
        "legitimate": num_after("Legitimate Emails", outbound),
        "encrypted": num_after("Encrypted Emails", outbound),
        "total_potential_threats": num_after("Total Potential Threats", outbound),
        "threat_breakdown": threat_breakdown(outbound),
    }

    at_risk = section_page("AT RISK USERS SUMMARY")
    # NOTE: only the "no risky users" case has been seen against real data.
    # A populated at-risk-users table's exact layout is unconfirmed — this
    # falls back to a marker string rather than guessing a table format.
    out["at_risk_users"] = "none" if "no risky users" in at_risk.lower() else "SEE_RAW_TEXT_UNCONFIRMED_FORMAT"
    if verbose and out["at_risk_users"] != "none":
        print(f"[debug] at-risk-users section had unexpected content, needs a real example to parse: {at_risk[:500]}")

    tls = section_page("TLS ENCRYPTION SUMMARY")
    tls_data = {}
    for category in ["Unencrypted", r"TLS v1\.3", r"TLS v1\.2"]:
        m = re.search(rf"{category}\s+(\d+)\s+(\d+)", tls)
        if m:
            tls_data[category.replace("\\", "")] = {"inbound": int(m.group(1)), "outbound": int(m.group(2))}
    out["tls"] = tls_data

    post_delivery = section_page("POST DELIVERY SUMMARY")
    out["post_delivery_retrieved"] = num_after("Total Emails Retrieved Post Delivery", post_delivery)

    return out


def parse_phish_threat_pdf(pages, verbose=False):
    """Confirmed working against a real Brock-Norton PhishThreat Summary
    PDF. No client-identifying field exists anywhere in this report's own
    content — client matching has to rely on the campaign name instead
    (e.g. "Brock Series"), handled by the caller, not this parser."""
    full_text = "\n".join(pages)
    out = {}

    m = re.search(r"(\d+)\s*\nCampaigns started \(90 days\)", full_text)
    out["campaigns_started_90d"] = int(m.group(1)) if m else None
    m = re.search(r"(\d+)\s*\nCampaigns ended \(90 days\)", full_text)
    out["campaigns_ended_90d"] = int(m.group(1)) if m else None
    m = re.search(r"(\d+)\s*\nUpcoming campaigns", full_text)
    out["upcoming_campaigns"] = int(m.group(1)) if m else None
    m = re.search(r"(\d+) Active campaigns", full_text)
    out["active_campaigns_count"] = int(m.group(1)) if m else None

    # NOTE: only ever tested with exactly one active campaign in the real
    # data. If a client ever runs multiple simultaneous campaigns, this
    # will only capture one set of these metrics — worth revisiting then.
    metrics = {}
    for field, label in [
        ("emails_sent", "Emails sent"), ("emails_delivered", "Emails delivered"),
        ("emails_opened", "Emails opened"), ("reported_threat", "Reported threat"),
        ("users_caught", "Users caught"), ("finished_training", "Finished training"),
    ]:
        m = re.search(rf"(\d+) {label}", full_text)
        metrics[field] = int(m.group(1)) if m else None
    out["most_recent_campaign"] = metrics

    campaign_name_match = re.search(r"([A-Za-z][A-Za-z ]+?)\s*\(\d{4}-\d{2}-\d{2}\)", full_text)
    out["campaign_name"] = campaign_name_match.group(1).strip() if campaign_name_match else None

    caught_users = []
    m = re.search(r"Name Times Caught Last Caught\n(.*?)(?:Past 90 days|Threat reporters)", full_text, re.S)
    if m:
        for line in m.group(1).strip().split("\n"):
            row = re.match(r"^(.+?)\s+(\d+)\s+([A-Za-z]{3}\s+\d{1,2},\s+\d{4})$", line.strip())
            if row:
                caught_users.append({"name": row.group(1), "times_caught": int(row.group(2)), "last_caught": row.group(3)})
    out["caught_users"] = caught_users
    out["threat_reporters_none"] = "No emails were reported" in full_text

    awareness = {}
    for field, label in [("users_tested_pct", "Users tested"), ("users_caught_pct", "Users caught"), ("passed_training_pct", "Passed training")]:
        m = re.search(rf"(\d+)\s*%\s*\n{label}", full_text)
        awareness[field] = int(m.group(1)) if m else None
    out["awareness"] = awareness

    return out


def parse_csv_attachment(content_bytes, verbose=False):
    text = content_bytes.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)
    if verbose and rows:
        print(f"[debug] CSV headers: {list(rows[0].keys())}")
        print(f"[debug] first row: {rows[0]}")
    return rows


def collect(cfg, clients, month_str, only_client_slug=None, verbose=False):
    graph = GraphClient(cfg)
    folder_id = find_folder_id(graph, cfg["mailbox"], cfg["folder_name"], verbose)
    month_start, month_end = month_range_utc(month_str, cfg["timezone"])

    messages_url = f"{GRAPH_BASE}/users/{cfg['mailbox']}/mailFolders/{folder_id}/messages"
    filter_str = (
        f"receivedDateTime ge {month_start.strftime('%Y-%m-%dT%H:%M:%SZ')} "
        f"and receivedDateTime lt {month_end.strftime('%Y-%m-%dT%H:%M:%SZ')}"
    )
    messages = graph.get_all_pages(messages_url, params={
        "$filter": filter_str,
        "$select": "id,subject,receivedDateTime,hasAttachments",
        "$top": 50,
    })
    if verbose:
        print(f"[debug] messages found in {cfg['folder_name']} for {month_str}: {len(messages)}")
        for m in messages:
            print(f"[debug]   - {m['receivedDateTime']}  hasAttachments={m['hasAttachments']}  subject={m['subject']!r}")

    results_by_client = {}
    unmatched = []

    for msg in messages:
        if not msg.get("hasAttachments"):
            continue
        attachments = graph.get(f"{GRAPH_BASE}/users/{cfg['mailbox']}/messages/{msg['id']}/attachments").get("value", [])
        for att in attachments:
            filename = att.get("name", "")
            content_bytes = base64.b64decode(att["contentBytes"])
            is_pdf = filename.lower().endswith(".pdf")
            is_csv = filename.lower().endswith(".csv")

            if not (is_pdf or is_csv):
                unmatched.append({"reason": "unsupported attachment type", "subject": msg["subject"], "filename": filename})
                continue

            parsed_pdf_pages = None
            report_type = None
            extra_match_text = ""

            if is_pdf:
                parsed_pdf_pages = extract_pdf_pages(content_bytes)
                full_text_lower = "\n".join(parsed_pdf_pages).lower()
                # Content-based classification, confirmed necessary against
                # real data: filenames alone (e.g. "PhishThreatSummary_...")
                # don't reliably carry a client name, and subject lines are
                # unknown until a real scheduled email arrives.
                if any(k in full_text_lower for k in PDF_EMAIL_MARKERS):
                    report_type = "sophos_email"
                elif any(k in full_text_lower for k in PDF_PHISH_MARKERS):
                    report_type = "sophos_phish_threat"
            else:
                report_type = classify_report(msg["subject"], filename)

            if report_type is None:
                unmatched.append({"reason": "unrecognized report type", "subject": msg["subject"], "filename": filename})
                continue

            # For PDFs, pull whatever client-identifying text the report's
            # own content offers — the Email report has a real Company Name
            # field; the Phish Threat report has no such field at all, only
            # a campaign name (e.g. "Brock Series") that may reference the
            # client's name.
            if report_type == "sophos_email" and parsed_pdf_pages:
                parsed = parse_sophos_email_pdf(parsed_pdf_pages, verbose=verbose)
                extra_match_text = parsed.get("company_name") or ""
            elif report_type == "sophos_phish_threat" and parsed_pdf_pages:
                parsed = parse_phish_threat_pdf(parsed_pdf_pages, verbose=verbose)
                extra_match_text = parsed.get("campaign_name") or ""
            elif is_csv:
                rows = parse_csv_attachment(content_bytes, verbose=verbose)
                keywords = EMAIL_COLUMN_KEYWORDS if report_type == "sophos_email" else PHISH_COLUMN_KEYWORDS
                parsed = sum_matching_columns(rows, keywords, verbose=verbose)
                parsed["row_count"] = len(rows)

            client = match_client(f"{msg['subject']} {extra_match_text}", filename, clients, only_client_slug, verbose=verbose)
            if client is None:
                unmatched.append({
                    "reason": "no matching client",
                    "subject": msg["subject"], "filename": filename,
                    "content_hint": extra_match_text or None,
                })
                continue

            source_flag = "sophos_email" if report_type == "sophos_email" else "sophos_phish_threat"
            if not client.get("sources", {}).get(source_flag, False):
                unmatched.append({
                    "reason": f"matched {client['name']} but sources.{source_flag} is false",
                    "subject": msg["subject"], "filename": filename,
                })
                continue

            results_by_client.setdefault(client["slug"], {})[report_type] = parsed

    if verbose or unmatched:
        print(f"[debug] {len(unmatched)} attachment(s) not matched to any client/report type:")
        for u in unmatched:
            print(f"[debug]   - {u['reason']}: subject={u['subject']!r} filename={u['filename']!r}")

    return results_by_client, unmatched


def main():
    parser = argparse.ArgumentParser(description="Scan the report mailbox for Sophos Email/Phish Threat CSVs.")
    parser.add_argument("--month", default=None, help="YYYY-MM; defaults to previous calendar month")
    parser.add_argument("--client", default=None, help="Optional: only match this client's slug, for focused debugging")
    parser.add_argument("--dry-run", action="store_true", help="Print results instead of writing files")
    parser.add_argument("--verbose", action="store_true", help="Print diagnostic info about messages/attachments/parsing")
    args = parser.parse_args()

    cfg = load_config()
    clients = load_clients(cfg["client_map"])
    month_str = args.month or os.getenv("REPORT_MONTH") or default_month()

    print(f"Scanning mailbox {cfg['mailbox']} / {cfg['folder_name']} for {month_str}...")
    results_by_client, unmatched = collect(cfg, clients, month_str, only_client_slug=args.client, verbose=args.verbose)

    if args.dry_run:
        print(json.dumps({"results_by_client": results_by_client, "unmatched_count": len(unmatched)}, indent=2))
        return

    for slug, data in results_by_client.items():
        out_dir = os.path.join(cfg["output_dir"], slug)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "client_month.json")
        existing = {}
        if os.path.exists(out_path):
            with open(out_path) as f:
                existing = json.load(f)
        existing.update(data)
        with open(out_path, "w") as f:
            json.dump(existing, f, indent=2)
        print(f"Wrote {out_path}")

    if unmatched:
        print(f"{len(unmatched)} attachment(s) could not be matched — see above with --verbose for details.")


if __name__ == "__main__":
    main()

"""Orchestrates one full monthly report run across every client in clients.yaml.

For each client: runs the collectors its `sources:` flags enable (each
collect_*.py is invoked as a subprocess, same as running them by hand),
builds the report context with the existing render_report.build_context(),
renders the PDF with pdf_reportlab.generate_pdf(), stores the PDF +
context in Postgres (db.py), and emails the PDF (mailer.py).

Idempotent per (client, month): a client already stored in Postgres for the
target month is skipped without re-running its collectors or re-emailing,
so re-running this (or the Worker's scheduling loop) never duplicates work.
Pass --force to regenerate and re-email anyway.

Usage:
    python run_monthly.py                  # previous calendar month, all clients
    python run_monthly.py --month 2026-07  # explicit month
    python run_monthly.py --client client-4
    python run_monthly.py --force          # regenerate even if already stored
    python run_monthly.py --skip-email     # store only, don't send mail
"""
from __future__ import annotations

import argparse
import calendar
import json
import os
import re
import subprocess
import sys
from datetime import date

import yaml

import db
import render_report
from mailer import send_report_email
from pdf_reportlab import generate_pdf

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable

# source flag in clients.yaml -> (collector script, takes --month)
PER_CLIENT_COLLECTORS = {
    "autotask": ("collect_autotask.py", True),
    "ninjaone": ("collect_ninja.py", True),
    "sophos_endpoint": ("collect_sophos.py", True),
    "datto_saas_protection": ("collect_datto_saas.py", False),
    "datto_bcdr": ("collect_datto_bcdr.py", False),
    "addigy": ("collect_addigy.py", False),
    "ninjaone_saas_backup": ("collect_ninjaone_saas_backup.py", True),
    "sentinelone": ("collect_sentinelone.py", True),
}
# these two source flags are served by ONE shared mailbox scan, not a per-client collector
MAILBOX_SOURCE_FLAGS = ("sophos_email", "sophos_phish_threat")


def default_month() -> str:
    """Previous calendar month as YYYY-MM, relative to today."""
    today = date.today()
    year, month = today.year, today.month - 1
    if month == 0:
        month, year = 12, year - 1
    return f"{year:04d}-{month:02d}"


def load_clients(client_map_path: str) -> list[dict]:
    with open(client_map_path) as f:
        data = yaml.safe_load(f)
    return data["clients"]


def run_collector(script: str, client_slug: str, month: str | None, verbose: bool) -> bool:
    """Runs one collect_*.py as a subprocess. Returns True on success."""
    cmd = [PYTHON, os.path.join(REPO_DIR, script), "--client", client_slug]
    if month is not None:
        cmd += ["--month", month]
    if verbose:
        cmd.append("--verbose")
    print(f"    $ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=REPO_DIR)
    if result.returncode != 0:
        print(f"    [error] {script} exited {result.returncode} for {client_slug}")
        return False
    return True


def run_mailbox_collector(month: str, verbose: bool) -> bool:
    cmd = [PYTHON, os.path.join(REPO_DIR, "collect_mailbox.py"), "--month", month]
    if verbose:
        cmd.append("--verbose")
    print(f"    $ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=REPO_DIR)
    if result.returncode != 0:
        print(f"    [error] collect_mailbox.py exited {result.returncode}")
        return False
    return True


def collect_for_client(client: dict, month: str, verbose: bool) -> None:
    sources = client.get("sources", {})
    for flag, (script, takes_month) in PER_CLIENT_COLLECTORS.items():
        if sources.get(flag):
            run_collector(script, client["slug"], month if takes_month else None, verbose)


def any_client_needs_mailbox(clients: list[dict]) -> bool:
    for client in clients:
        sources = client.get("sources", {})
        if any(sources.get(flag) for flag in MAILBOX_SOURCE_FLAGS):
            return True
    return False


def report_filename(client_name: str, month: str) -> str:
    """Client-specific, filesystem-safe PDF filename, e.g. for
    client_name='Middleburg Properties', month='2026-08':
    'Middleburg Properties Monthly Report 08-2026.pdf'.

    Uses 'MM-YYYY' (hyphen), not 'MM/YYYY' — a literal slash is not a
    valid filename character on most filesystems and mail clients.
    """
    year, mm = month.split("-")
    safe_name = re.sub(r'[\\/:*?"<>|]', "", client_name).strip()
    return f"{safe_name} Monthly Report {mm}-{year}.pdf"


def render_and_store(client: dict, cfg: dict, month: str, skip_email: bool) -> bool:
    """Builds context, renders the PDF, stores it in Postgres, emails it.

    Returns True on success. Any failure here is logged and swallowed so one
    client's bad/missing data doesn't abort the whole monthly run.
    """
    slug = client["slug"]
    try:
        data = render_report.load_client_month_data(cfg["output_dir"], slug, month)
    except SystemExit as e:
        print(f"    [skip] {client['name']}: {e}")
        return False

    try:
        context = render_report.build_context(data, client, cfg, month)
    except Exception as e:
        print(f"    [error] build_context failed for {client['name']}: {e}")
        return False

    out_dir = os.path.join(cfg["output_dir"], slug)
    os.makedirs(out_dir, exist_ok=True)
    # Internal on-disk name stays generic/stable (report-<month>.pdf) — the
    # client-specific display name is applied only to the attachment
    # filename below, at send/email time.
    pdf_path = os.path.join(out_dir, f"report-{month}.pdf")
    try:
        generate_pdf(context, pdf_path)
    except Exception as e:
        print(f"    [error] generate_pdf failed for {client['name']}: {e}")
        return False

    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    report = db.save_report(slug, client["name"], month, context, pdf_bytes)
    print(f"    [stored] {client['name']} — {len(pdf_bytes)} bytes in Postgres (report id {report.id})")

    attachment_filename = report_filename(client["name"], month)

    if not skip_email:
        try:
            send_report_email(client["name"], month, pdf_bytes, attachment_filename)
            db.mark_emailed(report.id)
            print(f"    [emailed] {client['name']}")
        except Exception as e:
            print(f"    [warn] email failed for {client['name']}: {e}")

    return True


def run_for_month(month: str | None = None, only_client: str | None = None, force: bool = False,
                   skip_email: bool = False, verbose: bool = False) -> dict:
    """Runs collectors + render + store (+ email) for every client for `month`
    (defaults to the previous calendar month). Returns a summary dict.
    """
    month = month or default_month()
    cfg = render_report.load_config()
    clients = load_clients(cfg["client_map"])
    if only_client:
        clients = [c for c in clients if c["slug"] == only_client]
        if not clients:
            raise SystemExit(f"No client with slug '{only_client}' in {cfg['client_map']}")

    db.init_db()

    pending = [c for c in clients if force or not db.report_exists(c["slug"], month)]
    print(f"=== Monthly run for {month}: {len(pending)}/{len(clients)} client(s) pending ===")

    if pending and any_client_needs_mailbox(pending):
        print("[mailbox] scanning shared inbox for Sophos Email/Phish Threat CSVs...")
        run_mailbox_collector(month, verbose)

    summary = {"month": month, "generated": [], "skipped_already_done": [], "failed": []}
    already_done = [c["slug"] for c in clients if c not in pending]
    summary["skipped_already_done"] = already_done

    for client in pending:
        print(f"[client] {client['name']} ({client['slug']})")
        collect_for_client(client, month, verbose)
        ok = render_and_store(client, cfg, month, skip_email)
        (summary["generated"] if ok else summary["failed"]).append(client["slug"])

    print(f"=== Done: {len(summary['generated'])} generated, "
          f"{len(summary['skipped_already_done'])} already done, "
          f"{len(summary['failed'])} failed ===")
    return summary


def main():
    parser = argparse.ArgumentParser(description="Run the full monthly report pipeline for all (or one) client.")
    parser.add_argument("--month", default=None, help="YYYY-MM; defaults to previous calendar month")
    parser.add_argument("--client", default=None, help="Only run this client slug")
    parser.add_argument("--force", action="store_true", help="Regenerate even if already stored for this month")
    parser.add_argument("--skip-email", action="store_true", help="Store in Postgres but don't send email")
    parser.add_argument("--verbose", action="store_true", help="Pass --verbose through to collectors")
    args = parser.parse_args()

    summary = run_for_month(
        month=args.month, only_client=args.client, force=args.force,
        skip_email=args.skip_email, verbose=args.verbose,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

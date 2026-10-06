"""Long-running Worker entrypoint for DigitalOcean App Platform.

App Platform Workers are just a process kept alive — no HTTP port, no
built-in cron. So this process itself does the scheduling: it wakes up
once an hour, checks whether today is this month's report day, and if so
(and it hasn't already run for the target month) kicks off the full
monthly pipeline (run_monthly.run_for_month).

Report day: the 29th of each month, except February, where it runs on the
28th instead (chosen because Sophos Email/Phish Threat CSVs already land
in the shared mailbox by the 27th of each month — this assumption about
February specifically wasn't confirmed with the client; adjust
REPORT_DAY_DEFAULT / REPORT_DAY_FEBRUARY below if a different day is
wanted). Each run reports on the CURRENT calendar month (the month in
progress), not the previous one.

Idempotency comes from Postgres, not from process state: run_for_month()
skips any client already stored for the target month, so it's always safe
to call again — on restart, on a delayed check, or manually.
"""
from __future__ import annotations

import os
import time
import traceback
from datetime import datetime
from zoneinfo import ZoneInfo

import db
from collect_sophos_web import harvest_all as harvest_web_events
from run_monthly import run_for_month

REPORT_DAY_DEFAULT = int(os.environ.get("REPORT_DAY_DEFAULT", "29"))
REPORT_DAY_FEBRUARY = int(os.environ.get("REPORT_DAY_FEBRUARY", "28"))
POLL_SECONDS = int(os.environ.get("WORKER_POLL_SECONDS", "3600"))  # check once an hour
TZ = ZoneInfo(os.environ.get("REPORT_TIMEZONE", "America/New_York"))
# Sophos web control (AI usage) harvest cadence. The SIEM API only keeps 24h
# of events, so a strictly-every-24h pull would leave small gaps as the
# hourly tick drifts; pulling every 12h with each pull starting where the
# last one ended (de-duplicated by event id) gives full coverage.
WEB_HARVEST_HOURS = float(os.environ.get("WEB_HARVEST_HOURS", "12"))
_last_web_harvest = None


def target_day_for(month: int) -> int:
    return REPORT_DAY_FEBRUARY if month == 2 else REPORT_DAY_DEFAULT


def should_run_today(now: datetime) -> bool:
    return now.day >= target_day_for(now.month)


def all_clients_done(month: str) -> bool:
    """True if every client in clients.yaml already has a stored report for `month`."""
    import render_report
    from run_monthly import load_clients

    cfg = render_report.load_config()
    clients = load_clients(cfg["client_map"])
    return all(db.report_exists(c["slug"], month) for c in clients)


def maybe_harvest_web(now, force=False):
    """Pull Sophos web control events for every Sophos client if it's been
    WEB_HARVEST_HOURS since the last pull (or `force`). Never raises."""
    global _last_web_harvest
    if not force and _last_web_harvest and (now - _last_web_harvest).total_seconds() < WEB_HARVEST_HOURS * 3600:
        return
    try:
        harvest_web_events()
    except Exception:
        print("[worker] ERROR during Sophos web harvest:")
        traceback.print_exc()
    _last_web_harvest = now


def main_loop():
    print(f"[worker] starting. Report days: day>={REPORT_DAY_DEFAULT} (Feb: day>={REPORT_DAY_FEBRUARY}), "
          f"timezone={TZ}, poll every {POLL_SECONDS}s.")
    db.init_db()

    while True:
        try:
            now = datetime.now(TZ)
            # Report on the month in progress (e.g. the Sep 29 run covers
            # 2026-09). The day>=29 gate means this is always late in the
            # month. Previously this used default_month() (previous month),
            # which on Sep 29 targeted an already-finished August and did nothing.
            month = now.strftime("%Y-%m")
            run_due = should_run_today(now) and not all_clients_done(month)
            # Force a fresh pull right before generating reports so the AI
            # usage section is current to the minute.
            maybe_harvest_web(now, force=run_due)
            if should_run_today(now):
                if not run_due:
                    print(f"[worker] {now.isoformat()}: {month} already fully generated — nothing to do.")
                else:
                    print(f"[worker] {now.isoformat()}: day {now.day} >= target day — running monthly pipeline for {month}.")
                    summary = run_for_month(month=month)
                    print(f"[worker] run complete: {summary}")
            else:
                print(f"[worker] {now.isoformat()}: day {now.day} < target day ({target_day_for(now.month)}) — waiting.")
        except Exception:
            print("[worker] ERROR during scheduling loop iteration:")
            traceback.print_exc()

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main_loop()

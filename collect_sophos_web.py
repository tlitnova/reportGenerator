"""collect_sophos_web.py -- harvest Sophos Endpoint web control events and
track month-to-date generative AI usage per client.

The Sophos SIEM events API only returns the last 24 hours, so a month of
history can't be pulled on report day -- it has to be collected as it
happens. worker_main.py calls harvest_all() on a timer; each run pulls every
WebControlViolation event since the previous run's window end (capped at the
24h API limit), stores them in Postgres (sophos_web_events, de-duplicated on
Sophos's event id), tags visits to known AI domains, and rebuilds that
month's ai_usage_monthly rollup.

Each warned visit produces two events: "'<url>' warned due to category
'<X>'" when the warning page is shown, then "User bypassed category block
to '<url>'" when the user clicks through. Only the warned event names the
category. Visit counts collapse these (and the page's sub-resource loads)
into one visit per tool/user/device per 5-minute window.

Which visits show up depends on the client's Sophos web control policy:
only sites in a Warn (or Block) category are logged, and only when "Log web
control events" is on. Bypass events don't say which category fired, so AI
visits are identified from the URL's domain against AI_TOOL_DOMAINS below,
not from Sophos's category.

Usage:
    python collect_sophos_web.py                  # harvest every Sophos client
    python collect_sophos_web.py --client TLNOVA  # one client
    python collect_sophos_web.py --client TLNOVA --dry-run   # print, don't store
    python collect_sophos_web.py --reclassify     # re-tag stored events after rule changes
"""
from __future__ import annotations

import argparse
import os
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import collect_sophos as cs

REPORT_TZ = ZoneInfo(os.environ.get("REPORT_TIMEZONE", "America/New_York"))
SIEM_MAX_LOOKBACK = timedelta(hours=24)
SIEM_SAFETY = timedelta(minutes=2)  # stay inside the 24h limit
WINDOW_OVERLAP = timedelta(minutes=10)  # re-read a little; dupes are dropped by event id
EVENT_TYPE = "Event::Endpoint::WebControlViolation"

# Tool name -> domains. A URL matches when its host IS the domain or is a
# subdomain of it (so "x.ai" matches "grok.x.ai" but not "box.ai"). Kept
# deliberately to AI-specific hosts: broad shared domains like bing.com,
# google.com, or microsoft.com are excluded because most traffic to them
# isn't AI use.
AI_TOOL_DOMAINS = {
    "ChatGPT": ["chatgpt.com", "chat.openai.com", "sora.com", "sora.chatgpt.com"],
    "OpenAI Platform": ["platform.openai.com"],
    "Claude": ["claude.ai", "claude.com", "anthropic.com"],
    "Google Gemini": ["gemini.google.com", "bard.google.com", "aistudio.google.com", "notebooklm.google.com"],
    "Microsoft Copilot": ["copilot.microsoft.com", "copilot.cloud.microsoft", "m365copilot.com",
                          "m365.cloud.microsoft"],  # Microsoft 365 Copilot app; Sophos categorizes it as Generative AI
    "Perplexity": ["perplexity.ai"],
    "DeepSeek": ["deepseek.com"],
    "Grok": ["grok.com", "x.ai"],
    "Meta AI": ["meta.ai"],
    "Mistral Le Chat": ["chat.mistral.ai"],
    "Qwen": ["chat.qwen.ai", "qwen.ai"],
    "Kimi": ["kimi.com", "kimi.ai", "moonshot.cn"],
    "Poe": ["poe.com"],
    "Character.AI": ["character.ai"],
    "Pi": ["pi.ai"],
    "You.com": ["you.com"],
    "Phind": ["phind.com"],
    "Hugging Face": ["huggingface.co", "hf.co"],
    "Midjourney": ["midjourney.com"],
    "Leonardo.ai": ["leonardo.ai"],
    "Runway": ["runwayml.com", "runway.com"],
    "ElevenLabs": ["elevenlabs.io"],
    "Suno": ["suno.com", "suno.ai"],
    "Gamma": ["gamma.app"],
    "Jasper": ["jasper.ai"],
    "Copy.ai": ["copy.ai"],
    "Writesonic": ["writesonic.com"],
    "Otter.ai": ["otter.ai"],
    "Fireflies.ai": ["fireflies.ai"],
    "Fathom": ["fathom.video"],
    "Read.ai": ["read.ai"],
    "QuillBot": ["quillbot.com"],
    "Cursor": ["cursor.com", "cursor.sh"],
    "Replit": ["replit.com"],
    "Lovable": ["lovable.dev"],
    "Bolt": ["bolt.new"],
    "v0": ["v0.dev", "v0.app"],
}

_DOMAIN_INDEX = sorted(
    ((d.lower(), tool) for tool, ds in AI_TOOL_DOMAINS.items() for d in ds),
    key=lambda x: -len(x[0]),  # most specific first
)

_URL_RE = re.compile(r"'(https?://[^']+)'")
_CATEGORY_RE = re.compile(r"due to category '([^']+)'")
_AI_CATEGORY_RE = re.compile(r"generative ai|artificial intelligence|\bai\b", re.I)


def _base_domain(host: str) -> str:
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def classify_host(host: str | None) -> str | None:
    if not host:
        return None
    host = host.lower().rstrip(".")
    for domain, tool in _DOMAIN_INDEX:
        if host == domain or host.endswith("." + domain):
            return tool
    return None


def parse_event(ev: dict, client_slug: str) -> dict:
    name = ev.get("name") or ""
    m = _URL_RE.search(name)
    url = m.group(1) if m else None
    host = urlparse(url).hostname if url else None
    cat = _CATEGORY_RE.search(name)
    lname = name.lower()
    action = ("bypassed" if "bypassed" in lname else "warned" if "warned" in lname
              else "blocked" if "blocked" in lname else "other")
    category = cat.group(1) if cat else None
    ai_tool = classify_host(host)
    if ai_tool is None and category and _AI_CATEGORY_RE.search(category):
        # Sophos says it's generative AI but it's not on our list -- still
        # count it, under its own domain, so new tools surface on their own.
        ai_tool = f"Other AI ({_base_domain(host)})" if host else "Other AI"
    when = cs.parse_iso8601(ev["when"]) if ev.get("when") else datetime.now(timezone.utc)
    return {
        "event_id": ev["id"],
        "client_slug": client_slug,
        "occurred_at": when,
        "month": when.astimezone(REPORT_TZ).strftime("%Y-%m"),
        "action": action,
        "url": url,
        "domain": host,
        "category": category,
        "ai_tool": ai_tool,
        "user_name": ev.get("source"),
        "device_name": ev.get("location"),
        "endpoint_id": ev.get("endpoint_id"),
        "raw": ev,
    }


def fetch_events(client: cs.SophosClient, since: datetime) -> list[dict]:
    """All WebControlViolation events since `since`, following next_cursor."""
    params = {"from_date": int(since.timestamp()), "limit": 1000}
    out = []
    while True:
        data = client.get("/siem/v1/events", params)
        out.extend(i for i in data.get("items", []) if i.get("type") == EVENT_TYPE)
        if not data.get("has_more") or not data.get("next_cursor"):
            break
        params = {"cursor": data["next_cursor"], "limit": 1000}
    return out


def harvest_client(client_cfg: dict, cfg: dict, dry_run: bool = False, verbose: bool = False) -> dict:
    import db

    slug = client_cfg["slug"]
    sophos = client_cfg.get("sophos") or {}
    now = datetime.now(timezone.utc)
    floor = now - SIEM_MAX_LOOKBACK + SIEM_SAFETY

    prev = None if dry_run else db.get_web_harvest(slug)
    since = floor
    if prev and prev.last_window_end:
        since = max(prev.last_window_end - WINDOW_OVERLAP, floor)
    gap = bool(prev and prev.last_window_end and prev.last_window_end - WINDOW_OVERLAP < floor)

    try:
        api = cs.SophosClient(cfg, sophos["tenant_id"], sophos["data_region_url"])
        events = fetch_events(api, since)
    except (Exception, SystemExit) as e:  # SophosClient sys.exit()s on auth failure
        if not dry_run:
            db.record_web_harvest(slug, None, error=str(e)[:2000])
        return {"client": slug, "ok": False, "error": str(e)}

    rows = [parse_event(e, slug) for e in events]
    ai_rows = [r for r in rows if r["ai_tool"]]
    if verbose or dry_run:
        for r in rows:
            print(f"  {r['occurred_at'].isoformat()} {r['action']:8} {r['ai_tool'] or '-':18} {r['domain']}")

    new = 0
    if not dry_run:
        new = db.save_web_events(rows)
        for month in sorted({r["month"] for r in rows} | {now.astimezone(REPORT_TZ).strftime("%Y-%m")}):
            db.rebuild_ai_usage(slug, month)
        db.record_web_harvest(slug, now)

    return {"client": slug, "ok": True, "fetched": len(rows), "new": new, "ai_events": len(ai_rows),
            "since": since.isoformat(), "gap_before_window": gap}


def reclassify_stored() -> int:
    """Re-run parse_event over every stored event's raw payload (e.g. after
    AI_TOOL_DOMAINS changes) and rebuild every affected monthly rollup."""
    import db
    session = db.get_session()
    try:
        E = db.SophosWebEvent
        touched, n = set(), 0
        for ev in session.query(E).yield_per(500):
            r = parse_event(ev.raw, ev.client_slug)
            ev.action, ev.category, ev.ai_tool, ev.domain, ev.url = r["action"], r["category"], r["ai_tool"], r["domain"], r["url"]
            touched.add((ev.client_slug, ev.month))
            n += 1
        session.commit()
    finally:
        session.close()
    for slug, month in sorted(touched):
        db.rebuild_ai_usage(slug, month)
    print(f"[web] reclassified {n} stored events across {len(touched)} client-months")
    return n


def sophos_clients(clients: list[dict]) -> list[dict]:
    return [c for c in clients
            if (c.get("sources") or {}).get("sophos_endpoint") and (c.get("sophos") or {}).get("tenant_id")]


def harvest_all(only_client: str | None = None, dry_run: bool = False, verbose: bool = False) -> list[dict]:
    import render_report
    from run_monthly import load_clients

    cfg_paths = render_report.load_config()
    clients = sophos_clients(load_clients(cfg_paths["client_map"]))
    if only_client:
        clients = [c for c in clients if c["slug"] == only_client]
    cfg = cs.load_config()
    results = []
    for c in clients:
        r = harvest_client(c, cfg, dry_run=dry_run, verbose=verbose)
        results.append(r)
        if r["ok"]:
            note = "  [warn] gap since last harvest (>24h)" if r.get("gap_before_window") else ""
            print(f"[web] {c['name']}: {r['fetched']} web events ({r['new']} new, {r['ai_events']} AI){note}")
        else:
            print(f"[web] {c['name']}: FAILED — {r['error'][:300]}")
        time.sleep(0.5)
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--client")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--reclassify", action="store_true", help="Re-tag stored events with current rules; no API calls")
    a = p.parse_args()
    if not a.dry_run:
        import db
        db.init_db()
    if a.reclassify:
        reclassify_stored()
        return
    harvest_all(a.client, dry_run=a.dry_run, verbose=a.verbose)


if __name__ == "__main__":
    main()

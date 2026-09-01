#!/usr/bin/env python3
"""
render_report.py — turn one client's collected client_month.json into the
final monthly report (HTML always; PDF too if weasyprint is installed).

Usage:
    python render_report.py --client client-3 --month 2026-07
    python render_report.py --client client-3 --month 2026-07 --html-only

Reads output/<slug>/client_month.json (written by the collect_*.py scripts
run WITHOUT --dry-run) and clients.yaml (for display name), computes every
chart/stat/prose value in Python, and renders monthly-report-template.html
via Jinja2. A section only appears if its data source's top-level key is
present in client_month.json — there is no "no data available" placeholder
anywhere in the output.

Two rendering rules were discovered while building the mockup and are
implemented here, not just noted:
  1. Addigy's compliance stat only shows if at least one device has a real
     true/false verdict (compliant_count > 0 or non_compliant_devices is
     non-empty). A client with a null-only fleet (no compliance policy
     configured) gets no compliance stat at all — showing "0/N" in that
     case would misrepresent "never evaluated" as "everything failed".
  2. NinjaOne patch compliance only renders the 4-segment
     installed/approved/pending/failed bar when patch_compliance.detailed
     is true. A non-detailed client's approved/pending are always 0
     because they were never collected, not because they're genuinely
     zero — showing them as real zero-width segments would be misleading,
     so a simpler installed/failed stat pair is shown instead.

Requires: jinja2 (pip install jinja2), and optionally weasyprint for PDF
output (pip install weasyprint) — the script still produces valid HTML
without weasyprint installed, just skips the PDF conversion step.
"""

import argparse
import json
import math
import os
import sys

import yaml
from jinja2 import Environment, FileSystemLoader

try:
    from weasyprint import HTML as WeasyHTML
    WEASYPRINT_AVAILABLE = True
except Exception as e:
    # Deliberately broad: a missing/broken native dependency (Pango,
    # GObject) surfaces as OSError from inside weasyprint's own
    # module-level code, not a clean ImportError — confirmed against a
    # real macOS failure. Catching only ImportError let this crash the
    # whole script before --html-only was even checked.
    WEASYPRINT_AVAILABLE = False
    _weasyprint_import_error = str(e)

TEMPLATE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_NAME = "monthly-report-template.html"

# Shared color palette, matching the approved mockup exactly.
PALETTE = ["#1F4B3F", "#6B8F7B", "#8FA896", "#B8C9BB", "#D8C48A", "#A9702F"]

NEEDS_ATTENTION_SOURCES = ["autotask", "ninjaone", "sophos_endpoint", "addigy", "sentinelone", "datto_bcdr"]


def load_config():
    from dotenv import load_dotenv
    load_dotenv()
    logo_path = os.getenv("LOGO_PATH", "./logo.png")
    logo_abs_path = os.path.abspath(logo_path)
    logo_found = os.path.exists(logo_abs_path)
    if logo_found:
        print(f"[info] logo found at {logo_abs_path}")
    else:
        print(
            f"[warn] LOGO_PATH is set to {logo_path!r}, resolved to {logo_abs_path}, "
            f"but no file exists there — report will show text branding instead. "
            f"Check LOGO_PATH in .env and confirm that exact path/filename exists."
        )
    return {
        "client_map": os.getenv("CLIENT_MAP", "./clients.yaml"),
        "output_dir": os.getenv("OUTPUT_DIR", "./output"),
        "msp_name": os.getenv("MSP_NAME", "TeamLogic IT of Reston & Tysons"),
        # Only used if the file actually exists — a missing logo degrades
        # to plain text in the masthead rather than a broken image.
        "logo_path": logo_abs_path if logo_found else None,
    }


def load_client(client_map_path, client_slug):
    with open(client_map_path) as f:
        data = yaml.safe_load(f)
    for client in data["clients"]:
        if client.get("slug") == client_slug:
            return client
    sys.exit(f"No client with slug '{client_slug}' found in {client_map_path}")


def load_client_month_data(output_dir, client_slug, month_str):
    path = os.path.join(output_dir, client_slug, "client_month.json")
    if not os.path.exists(path):
        sys.exit(
            f"No data file found at {path}.\n"
            f"Run the applicable collect_*.py scripts for this client WITHOUT "
            f"--dry-run first — render_report.py only reads what's already "
            f"been collected, it doesn't fetch anything itself."
        )
    with open(path) as f:
        data = json.load(f)
    return data


def top_n_with_other(counts, n=6):
    """Sorts by value descending, keeps the top n-1, buckets the rest into
    'Other' so a long tail of rare values doesn't blow out a legend."""
    items = sorted(counts.items(), key=lambda kv: -kv[1])
    if len(items) <= n:
        return items
    head = items[: n - 1]
    other_total = sum(v for _, v in items[n - 1:])
    return head + [("Other", other_total)]


def format_bytes(num_bytes):
    """Human-readable size for the donut's center label."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}" if unit != "B" else f"{num_bytes} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"


def make_donut_segments(counts_list, palette=None, radius=70):
    """Same SVG stroke-dasharray donut technique already proven in the
    approved mockup — computed generically here so any section can use a
    real donut chart from real (label, value) data, not just the one
    hand-coded example in the mockup."""
    palette = palette or PALETTE
    circumference = 2 * math.pi * radius
    total = sum(v for _, v in counts_list) or 1
    segments = []
    offset = 0
    for (label, value), color in zip(counts_list, palette):
        pct = value / total
        dash = pct * circumference
        segments.append({
            "label": label, "value": value, "pct": round(pct * 100, 1), "color": color,
            "dasharray": f"{dash:.2f} {circumference - dash:.2f}",
            "dashoffset": f"{-offset:.2f}",
        })
        offset += dash
    return segments


def make_segments(counts_list, palette=None):
    palette = palette or PALETTE
    total = sum(v for _, v in counts_list) or 1
    return [
        {"label": label, "value": value, "pct": round(value / total * 100, 1), "color": color}
        for (label, value), color in zip(counts_list, palette)
    ]


def collect_needs_attention(data):
    items = []
    for key in NEEDS_ATTENTION_SOURCES:
        section = data.get(key)
        if section and section.get("needs_attention"):
            items.extend(section["needs_attention"])
    return items


# ---------------------------------------------------------------- Autotask
def build_autotask(data):
    a = data.get("autotask")
    if not a:
        return None
    tickets = a.get("tickets_resolved", 0)
    frm = a.get("first_response_met_pct", 0)
    res = a.get("resolution_met_pct", 0)
    hours = a.get("hours_worked_total", 0)
    raw_categories = a.get("hours_worked_by_category") or {}
    cleaned_categories = {}
    for cat, hrs in raw_categories.items():
        cleaned_categories[cat.strip()] = cleaned_categories.get(cat.strip(), 0) + hrs
    hours_by_category = sorted(cleaned_categories.items(), key=lambda kv: -kv[1])

    sla_phrase = (
        "within your service level agreement for first response" if frm >= 90
        else "slightly below target for first response — worth a look"
    )
    prose = f"{tickets} ticket{'s' if tickets != 1 else ''} were resolved this month, {sla_phrase}."

    return {
        "tickets_resolved": tickets,
        "hours_worked_total": hours,
        "first_response_met_pct": frm,
        "resolution_met_pct": res,
        "hours_by_category": hours_by_category,
        "prose": prose,
    }


# ---------------------------------------------------------------- NinjaOne
def build_ninjaone(data):
    n = data.get("ninjaone")
    if not n:
        return None
    device_count = n.get("device_count", 0)
    pc = n.get("patch_compliance", {}) or {}
    detailed = pc.get("detailed", False)
    result = {"device_count": device_count}

    if detailed:
        counts = {
            "Installed": pc.get("installed", 0), "Approved": pc.get("approved", 0),
            "Pending": pc.get("pending", 0), "Failed": pc.get("failed", 0),
        }
        colors = {"Installed": "#1F4B3F", "Approved": "#6B8F7B", "Pending": "#D8C48A", "Failed": "#A9702F"}
        total = sum(counts.values()) or 1
        result["compliance_segments"] = [
            {"label": k, "value": v, "pct": round(v / total * 100, 1), "color": colors[k]}
            for k, v in counts.items() if v > 0
        ]
        if device_count == 0:
            prose = "No Windows devices are currently managed by NinjaOne this month."
        else:
            prose = (
                f"{device_count} Windows device{'s' if device_count != 1 else ''} "
                f"are actively managed. Patch compliance sits at {pc.get('score_pct', 0)}% for the month."
            )
    else:
        # Rendering rule: approved/pending were never collected for a
        # non-detailed client — they're not genuinely zero, just
        # unmeasured. Show installed/failed only, not a fake 4-way split.
        result["installed"] = pc.get("installed", 0)
        result["failed"] = pc.get("failed", 0)
        # Explicitly say "Windows" so this reads clearly for clients who
        # also have an Apple Devices (Addigy) section — "0 devices are
        # actively managed" was ambiguous/confusing on its own (real
        # example: HCN, which has zero NinjaOne-managed Windows machines
        # but a full Apple fleet under Addigy).
        if device_count == 0:
            prose = "No Windows devices are currently managed by NinjaOne this month."
        else:
            prose = (
                f"{device_count} Windows device{'s' if device_count != 1 else ''} are actively managed, "
                f"with {pc.get('installed', 0)} patch{'es' if pc.get('installed', 0) != 1 else ''} installed this month."
            )

    result["prose"] = prose

    os_mix = n.get("os_mix") or {}
    if os_mix:
        result["os_segments"] = make_segments(top_n_with_other(os_mix))
    return result


# ------------------------------------------------------------------ Addigy
def build_addigy(data):
    a = data.get("addigy")
    if not a:
        return None
    active = a.get("active_fleet_count", 0)
    raw_type_mix = a.get("device_type_mix") or {}
    device_type_mix = {k: v for k, v in raw_type_mix.items() if v > 0 and k != "Unknown"}

    stats = []
    compliant = a.get("compliant_count", 0)
    non_compliant = a.get("non_compliant_devices") or []
    # Rendering rule: Addigy's is_compliant is null (not false) for any
    # device covered by no compliance policy. Only show a compliance stat
    # when at least one device has a real true/false verdict — otherwise
    # "0/N compliant" would misrepresent "never evaluated" as "failing".
    if compliant > 0 or len(non_compliant) > 0:
        total_evaluated = compliant + len(non_compliant)
        stats.append({
            "value": f"{compliant}/{total_evaluated}",
            "label": "devices meeting compliance policy",
            "flag": compliant < total_evaluated,
        })

    mac_count = raw_type_mix.get("Mac", 0)
    filevault_off = len(a.get("filevault_off_devices") or [])
    if mac_count > 0:
        encrypted = mac_count - filevault_off
        stats.append({
            "value": f"{encrypted}/{mac_count}",
            "label": "active Macs encrypted",
            "flag": encrypted < mac_count,
        })

    prose = f"{active} Apple device{'s' if active != 1 else ''} are actively managed."
    if mac_count > 0 and filevault_off == 0:
        prose += " Every active Mac has disk encryption enabled."

    result = {"prose": prose, "stats": stats}

    outdated_os_devices = a.get("outdated_os_devices") or []
    if outdated_os_devices:
        names = ", ".join(d["device"] for d in outdated_os_devices)
        count = len(outdated_os_devices)
        result["outdated_os_note"] = (
            f"{count} Mac{'s' if count != 1 else ''} running an outdated macOS version and "
            f"need{'s' if count == 1 else ''} to be updated: {names}."
        )
    if device_type_mix:
        result["device_mix_segments"] = make_segments(sorted(device_type_mix.items(), key=lambda kv: -kv[1]))

    # macOS versions only — filter out our own "Unknown (...)" fallback
    # labels used for non-Mac devices, which aren't real version strings.
    os_mix = {k: v for k, v in (a.get("os_mix") or {}).items() if not str(k).startswith("Unknown")}
    if os_mix:
        result["os_segments"] = make_segments(top_n_with_other(os_mix))
    return result


# ---------------------------------------------------------------- Security
def build_security(data):
    se = data.get("sophos_endpoint")
    s1 = data.get("sentinelone")
    if not (se or s1):
        return None

    stats, prose_parts, sources = [], [], []
    activity_donut = None

    if se:
        sources.append("Sophos Endpoint")
        # Use the same 14-day threshold as the activity donut below, not
        # the older 30-day active_count — confirmed against real data that
        # showing both side by side is genuinely confusing (a device seen
        # 20 days ago satisfied the old 30-day rule but correctly fails
        # the stricter, Sophos-matching 14-day one). One consistent
        # definition of "active" throughout this section.
        act = se.get("activity_status")
        active = act.get("active", 0) if act else se.get("active_count", 0)
        # protected_count / not_checked_in_count come straight from
        # collect_sophos.py's own explicit fields — every device returned
        # by the endpoint API has Sophos installed by definition, so
        # "protected" is the full device count, never a fraction of it.
        # A device that hasn't checked in recently is NOT the same as an
        # unprotected one; confirmed by client feedback that a prior
        # report wrongly labeled this population "Unprotected."
        total_protected = se.get("protected_count", se.get("device_count", 0))
        not_checked_in = se.get("not_checked_in_count", 0)
        tamper_off = se.get("tamper_protection_off_count", 0)
        stats.append({"value": total_protected, "label": "devices protected"})
        stats.append({"value": not_checked_in, "label": "not checked in recently", "flag": not_checked_in > 0})
        stats.append({"value": tamper_off, "label": "tamper protection issues", "flag": tamper_off > 0})
        prose_parts.append(
            f"{not_checked_in} device{'s' if not_checked_in != 1 else ''} haven't checked in recently and may need a look"
            if not_checked_in else "Every protected device has checked in recently"
        )
        # Replicates Sophos's own real "Endpoint Computer Activity Status"
        # donut (confirmed from an actual console screenshot) — Active /
        # Inactive 2+ Weeks / Inactive 2+ Months. This chart alone (not a
        # separate Protected/Unprotected chart) is the correct visual for
        # this breakdown, since every device shown here IS protected.
        if act and sum(act.values()) > 0:
            activity_counts = [
                ("Active", act.get("active", 0)),
                ("Inactive 2+ Weeks", act.get("inactive_2weeks", 0)),
                ("Inactive 2+ Months", act.get("inactive_2months", 0)),
            ]
            activity_counts = [(l, v) for l, v in activity_counts if v > 0]
            activity_donut = make_donut_segments(activity_counts, palette=["#1F4B3F", "#D8C48A", "#A9702F"])

    if s1:
        sources.append("SentinelOne")
        infected = s1.get("infected_count", 0)
        stats.append({"value": s1.get("device_count", 0), "label": "endpoints protected"})
        if infected:
            stats.append({"value": infected, "label": "devices with active threats", "flag": True})
        threats = s1.get("threats_this_month_total", 0)
        if threats:
            prose_parts.append(f"{threats} threat detection{'s' if threats != 1 else ''} this month")

    prose = (". ".join(prose_parts) + ".") if prose_parts else "Security monitoring is active across your protected devices."
    return {
        "source_label": " & ".join(sources),
        "stats": stats,
        "prose": prose,
        "activity_donut": activity_donut,
    }


# ----------------------------------------------------------- Sophos Email
def build_sophos_email(data):
    """Standalone Sophos Email section, split out from endpoint/device
    security per client feedback that the two were being conflated into
    one generic 'Security' block. Mirrors the layout of the client's own
    Sophos Email Dashboard Summary Report (confirmed against a real
    Middleburg Communities PDF): Inbound/Outbound stats, an Intelix Threat
    Summary donut, and a real At Risk Users table."""
    email = data.get("sophos_email")
    if not email:
        return None

    inbound = email.get("inbound") or {}
    outbound = email.get("outbound") or {}

    def direction_block(d, label):
        scanned = d.get("emails_scanned", 0)
        threats = d.get("total_potential_threats", 0)
        stats = [
            {"value": scanned, "label": f"{label} emails scanned"},
            {"value": threats, "label": f"{label} threats identified", "flag": threats > 0},
        ]
        mailboxes = d.get("mailboxes_protected")
        if mailboxes:
            stats.append({"value": mailboxes, "label": "mailboxes protected"})
        breakdown = {k: v for k, v in (d.get("threat_breakdown") or {}).items() if v > 0}
        segments = make_segments(top_n_with_other(breakdown)) if breakdown else None
        return {"stats": stats, "segments": segments}

    inbound_block = direction_block(inbound, "inbound") if inbound else None
    outbound_block = direction_block(outbound, "outbound") if outbound else None

    intelix = email.get("intelix") or {}
    intelix_block = None
    if intelix.get("total_analyzed"):
        breakdown = {k: v for k, v in (intelix.get("breakdown") or {}).items() if v > 0}
        intelix_block = {
            "total_analyzed": intelix["total_analyzed"],
            "segments": make_donut_segments(list(breakdown.items())) if breakdown else None,
        }

    at_risk = email.get("at_risk_users")
    at_risk_users = at_risk if isinstance(at_risk, list) else []

    threats_blocked = inbound.get("total_potential_threats", 0) + outbound.get("total_potential_threats", 0)
    prose_parts = []
    if threats_blocked:
        prose_parts.append(f"{threats_blocked} potential threat{'s' if threats_blocked != 1 else ''} blocked across inbound and outbound mail")
    if at_risk_users:
        prose_parts.append(f"{len(at_risk_users)} user{'s' if len(at_risk_users) != 1 else ''} flagged as at-risk this month")
    prose = ". ".join(prose_parts) + "." if prose_parts else "Email security monitoring is active."

    return {
        "prose": prose,
        "inbound": inbound_block,
        "outbound": outbound_block,
        "intelix": intelix_block,
        "at_risk_users": at_risk_users,
    }


# --------------------------------------------------------- Data Protection
def build_data_protection(data):
    datto_saas = data.get("datto_saas_protection")
    bcdr = data.get("datto_bcdr")
    saas_backup = data.get("ninjaone_saas_backup")
    if not (datto_saas or bcdr or saas_backup):
        return None

    sources, prose_parts = [], []
    m365 = None

    if datto_saas:
        sources.append("Datto SaaS Protection")
        pct, seats = datto_saas.get("backup_percentage", 0), datto_saas.get("seats_used", 0)
        m365 = {"stats": [
            {"value": seats, "label": "seats protected"},
            {"value": f"{pct}%", "label": "backup success rate", "flag": pct < 100},
        ]}
        prose_parts.append(
            f"Microsoft 365 backup is running at {pct}% success" if pct < 100
            else "Microsoft 365 backup is current across every protected seat"
        )

        # Per-service mini-panel (OneDrive / Exchange / SharePoint / Teams),
        # replicating the layout of the Datto partner-portal "Backups"
        # view the client already likes. Built from collect_datto_saas.py's
        # saas_apps list — see that file's comment for exactly which
        # partner-portal fields ARE and AREN'T available from the API
        # (no in-progress counters, no total-protected-data size).
        apps = datto_saas.get("saas_apps") or []
        panels = []
        for app in apps:
            active = app.get("active_count")
            protected = app.get("protected_count")
            total = app.get("total_count")
            if active is None and total is None:
                continue  # e.g. Teams before its first backup history window exists
            gap = (total or 0) - (protected or 0)
            panels.append({
                "label": app.get("label"),
                "active_count": active if active is not None else 0,
                "protected_count": protected if protected is not None else 0,
                "total_count": total if total is not None else 0,
                "last_fully_protected": app.get("last_fully_protected") or "\u2014",
                "flag": gap > 0,
            })
        if panels:
            m365["app_panels"] = panels
    elif saas_backup and saas_backup.get("total_mailboxes") is not None:
        sources.append("NinjaOne SaaS Backup")
        total_mb, active_mb = saas_backup["total_mailboxes"], saas_backup.get("mailboxes_active", 0)
        gap = saas_backup.get("mailboxes_available_not_backed_up", 0)
        seats_used = saas_backup.get("seats_used")

        m365_stats = []
        # Lead with seats_used when available — confirmed against the real
        # Dropsuite dashboard that this is the client-recognizable number
        # (labeled "Seat used" there, and likely what they're billed on),
        # not total_mailboxes, which counts everything in the M365 tenant
        # directory including shared/resource/disabled mailboxes that
        # aren't necessarily billable seats. Real data showed these two
        # numbers can differ substantially (319 seats vs. 697 mailboxes)
        # for the same tenant.
        if seats_used is not None:
            m365_stats.append({"value": seats_used, "label": "seats used"})
        m365_stats.append({"value": f"{active_mb}/{total_mb}", "label": "mailboxes in backup scope", "flag": gap > 0})
        if gap:
            m365_stats.append({"value": gap, "label": "mailboxes not yet backed up", "flag": True})
        added = saas_backup.get("mailboxes_added_this_month", 0)
        if added:
            m365_stats.append({"value": added, "label": "mailboxes added this month"})
        m365 = {"stats": m365_stats}
        prose_parts.append(f"{active_mb} of {total_mb} mailboxes are protected" if gap else "Every mailbox is protected")

    bcdr_block = None
    if bcdr:
        sources.append("Datto BCDR")
        all_assets = [a for d in bcdr.get("devices", []) for a in d.get("assets", [])]
        active_assets = [a for a in all_assets if not a.get("is_archived") and not a.get("is_paused")]
        success_count = sum(1 for a in active_assets if a.get("most_recent_backup_status") == "success")
        bcdr_block = {"stats": [
            {"value": f"{success_count}/{len(active_assets)}", "label": "systems backed up successfully",
             "flag": success_count < len(active_assets)},
        ]}
        prose_parts.append(
            "your on-site backup appliance completed every scheduled job" if success_count == len(active_assets)
            else f"{len(active_assets) - success_count} on-site system(s) need attention"
        )

        # Per-system backup size chart. Uses each asset's most recent
        # backup size — a reasonable real proxy for "how much of your
        # appliance's protected data belongs to this system," though not
        # a confirmed measure of current appliance disk usage specifically
        # (see the honest caveat in collect_datto_bcdr.py).
        sized_assets = [
            (a.get("asset_name", "Unknown"), a["most_recent_backup_size_bytes"])
            for a in active_assets if a.get("most_recent_backup_size_bytes")
        ]
        if sized_assets:
            sized_assets.sort(key=lambda kv: -kv[1])
            top = top_n_with_other(dict(sized_assets))
            bcdr_block["storage_donut"] = make_donut_segments(top)
            total_bytes = sum(v for _, v in sized_assets)
            bcdr_block["storage_total_label"] = format_bytes(total_bytes)

    prose = " and ".join(prose_parts)
    prose = (prose[0].upper() + prose[1:] + ".") if prose else ""
    return {"source_label": " & ".join(sources), "prose": prose, "m365": m365, "bcdr": bcdr_block}


# ---------------------------------------------------- KPIs / headline / close
def build_kpis(data, watchlist):
    candidates = []
    if data.get("autotask"):
        candidates.append({"value": f"{data['autotask'].get('first_response_met_pct', 0)}%", "label": "First response met (Autotask)"})
    if data.get("ninjaone"):
        pc = data["ninjaone"].get("patch_compliance") or {}
        if pc.get("detailed"):
            candidates.append({"value": f"{pc.get('score_pct', 0)}%", "label": "Patch compliance (NinjaOne)"})
    if data.get("sophos_endpoint"):
        se = data["sophos_endpoint"]
        total = se.get("device_count", 0)
        if total:
            # Every device here has Sophos installed by definition, so a
            # "% protected" KPI is always 100% and not worth showing. Use
            # the SAME 14-day activity_status["active"] bucket as the
            # Security section and its donut — confirmed this used to read
            # active_count (a different, older 30-day threshold) which
            # produced a number (59%) that never matched anything else on
            # the report. Relabeled from "protected" to "active" since
            # that's what this percentage actually measures.
            act = se.get("activity_status")
            active = act.get("active", 0) if act else se.get("active_count", 0)
            pct = round(active / total * 100)
            candidates.append({"value": f"{pct}%", "label": "Endpoints active (Sophos)"})
    if data.get("datto_saas_protection"):
        candidates.append({"value": f"{data['datto_saas_protection'].get('backup_percentage', 0)}%", "label": "M365 backup success (Datto)"})

    kpis = candidates[:3]
    kpis.append({"value": len(watchlist), "label": "Items needing attention", "flag": len(watchlist) > 0})
    return kpis


def build_headline(data, watchlist):
    positives = []
    if data.get("autotask") and data["autotask"].get("first_response_met_pct", 0) >= 90:
        positives.append("support response times stayed ahead of target")
    if data.get("datto_saas_protection") and data["datto_saas_protection"].get("backup_percentage", 0) == 100:
        positives.append("backups completed without issue")
    if data.get("sophos_endpoint"):
        se = data["sophos_endpoint"]
        if se.get("device_count") and se.get("active_count") == se.get("device_count"):
            positives.append("every active device has current security protection")

    lead = ("Your systems ran smoothly this month — " + ", ".join(positives) + ". ") if positives else ""

    if not watchlist:
        return lead if lead else "Here's a summary of your systems this month."

    n = len(watchlist)
    if n == 1:
        tail = f"{watchlist[0]['device']} needs attention this month: {watchlist[0]['reason']}."
    else:
        tail = f"{n} items need attention this month; details below."
    return lead + tail


def build_what_we_did(data):
    items = []
    if data.get("autotask"):
        a = data["autotask"]
        items.append(f"Resolved {a.get('tickets_resolved', 0)} support tickets, {a.get('first_response_met_pct', 0)}% within first-response target")
    if data.get("ninjaone"):
        pc = data["ninjaone"].get("patch_compliance") or {}
        installed = pc.get("installed", 0)
        if installed:
            items.append(
                f"Applied {installed} approved patches across managed devices" if pc.get("detailed")
                else f"Installed {installed} patches this month"
            )
    if data.get("datto_saas_protection") or data.get("datto_bcdr") or data.get("ninjaone_saas_backup"):
        items.append("Verified backup jobs across all protected systems")
    if data.get("sophos_email"):
        threats = (data["sophos_email"].get("inbound") or {}).get("total_potential_threats", 0)
        if threats:
            items.append(f"Blocked {threats} potential email threat{'s' if threats != 1 else ''}")
    return items


def build_recommended_next(data):
    """Round-robins one item per source per pass through NEEDS_ATTENTION_SOURCES,
    instead of concatenating every source's items in fixed block order and
    slicing to 8. The old approach meant whichever source came first in
    NEEDS_ATTENTION_SOURCES simply filled every slot if it had 8+ items --
    confirmed against real Middleburg data that NinjaOne's 62 items crowded
    out all 8 slots even though Sophos Endpoint's 200 items were the large
    majority (200 of 269) of the actual watchlist. Round-robin guarantees
    every source with items gets a turn before any one source can take a
    second slot."""
    per_source_iters = []
    for key in NEEDS_ATTENTION_SOURCES:
        section = data.get(key)
        na = section.get("needs_attention") if section else None
        if na:
            per_source_iters.append(iter(na))

    seen, items = set(), []
    while per_source_iters and len(items) < 8:
        still_active = []
        for it in per_source_iters:
            if len(items) >= 8:
                still_active.append(it)
                continue
            for w in it:
                key = (w["device"], w["reason"])
                if key in seen:
                    continue
                seen.add(key)
                items.append(f"{w['device']}: {w['reason']}")
                still_active.append(it)
                break
        per_source_iters = still_active
    return items[:8]


def build_context(data, client, cfg, month_str):
    watchlist = collect_needs_attention(data)
    return {
        "client_name": client["name"],
        "msp_name": cfg["msp_name"],
        "logo_path": cfg.get("logo_path"),
        "report_period_label": month_str,
        "headline": build_headline(data, watchlist),
        "kpis": build_kpis(data, watchlist),
        "autotask": build_autotask(data),
        "ninjaone": build_ninjaone(data),
        "addigy": build_addigy(data),
        "security": build_security(data),
        "sophos_email": build_sophos_email(data),
        "data_protection": build_data_protection(data),
        "what_we_did": build_what_we_did(data),
        "recommended_next": build_recommended_next(data),
    }


def render(cfg, client, data, month_str):
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template(TEMPLATE_NAME)
    context = build_context(data, client, cfg, month_str)
    return template.render(**context)


def main():
    parser = argparse.ArgumentParser(description="Render one client's monthly report from collected data.")
    parser.add_argument("--client", required=True, help="Client slug as it appears in clients.yaml")
    parser.add_argument("--month", required=True, help="YYYY-MM — must match what the collectors were run with")
    parser.add_argument("--html-only", action="store_true", help="Skip PDF conversion even if weasyprint is installed")
    args = parser.parse_args()

    cfg = load_config()
    client = load_client(cfg["client_map"], args.client)
    data = load_client_month_data(cfg["output_dir"], args.client, args.month)

    html_output = render(cfg, client, data, args.month)

    out_dir = os.path.join(cfg["output_dir"], args.client)
    os.makedirs(out_dir, exist_ok=True)
    html_path = os.path.join(out_dir, f"report-{args.month}.html")
    with open(html_path, "w") as f:
        f.write(html_output)
    print(f"Wrote {html_path}")

    if not args.html_only:
        if WEASYPRINT_AVAILABLE:
            pdf_path = os.path.join(out_dir, f"report-{args.month}.pdf")
            WeasyHTML(string=html_output, base_url=TEMPLATE_DIR).write_pdf(pdf_path)
            print(f"Wrote {pdf_path}")
        else:
            print(
                "[note] weasyprint isn't usable in this environment — HTML was still written above. "
                f"Real error: {_weasyprint_import_error}"
            )


if __name__ == "__main__":
    main()

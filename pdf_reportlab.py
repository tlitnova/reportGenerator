#!/usr/bin/env python3
"""
pdf_reportlab.py — renders a client's monthly report straight to PDF with
reportlab, replacing the weasyprint + Jinja/HTML path in render_report.py.

Why: weasyprint needs native system libraries (Pango, Cairo, GObject) that
aren't available in DigitalOcean App Platform's Python buildpack — that's
the real cause of the PDF export failing once deployed there, even though
it works fine in a local dev environment where those libraries happen to
be installed. reportlab is pure Python with zero native dependencies, and
is already used successfully by the aiassessment app on this same platform.

This module takes the exact same `context` dict produced by
render_report.build_context() — no data-shaping logic is duplicated or
re-derived here, only the visual rendering layer changes.

Usage:
    from pdf_reportlab import generate_pdf
    generate_pdf(context, "/path/to/report.pdf")
"""

from __future__ import annotations

from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing, String, Wedge
from reportlab.platypus import (
    Flowable,
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ---------------------------------------------------------------- palette
INK = HexColor("#1B2420")
PAPER = HexColor("#F6F4EC")
FOREST = HexColor("#1F4B3F")
SAGE = HexColor("#6B8F7B")
OCHRE = HexColor("#A9702F")
RULE = HexColor("#DAD6C8")

PAGE_MARGIN = 0.85 * inch
CONTENT_WIDTH = LETTER[0] - 2 * PAGE_MARGIN


def _styles() -> dict:
    return {
        "brand": ParagraphStyle("brand", fontName="Helvetica-Bold", fontSize=10, textColor=FOREST, leading=12),
        "period": ParagraphStyle("period", fontName="Helvetica", fontSize=10, textColor=SAGE, leading=12, alignment=2),
        "client_name": ParagraphStyle("client_name", fontName="Times-Bold", fontSize=25, textColor=INK, leading=29, spaceBefore=12),
        "report_title": ParagraphStyle("report_title", fontName="Helvetica", fontSize=12, textColor=SAGE, leading=15, spaceAfter=16),
        "headline": ParagraphStyle("headline", fontName="Times-Roman", fontSize=13, textColor=INK, leading=19, spaceAfter=6),
        "kpi_value": ParagraphStyle("kpi_value", fontName="Times-Bold", fontSize=21, textColor=FOREST, leading=23),
        "kpi_value_flag": ParagraphStyle("kpi_value_flag", fontName="Times-Bold", fontSize=21, textColor=OCHRE, leading=23),
        "kpi_label": ParagraphStyle("kpi_label", fontName="Helvetica", fontSize=8.3, textColor=INK, leading=11),
        "h2": ParagraphStyle("h2", fontName="Times-Bold", fontSize=15.5, textColor=FOREST, leading=18),
        "section_source": ParagraphStyle("section_source", fontName="Helvetica", fontSize=8.3, textColor=SAGE, leading=11, alignment=2),
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9.8, textColor=INK, leading=14.5, spaceAfter=8),
        "subhead": ParagraphStyle("subhead", fontName="Helvetica-Bold", fontSize=9.8, textColor=FOREST, leading=13, spaceBefore=10, spaceAfter=6),
        "stat_num": ParagraphStyle("stat_num", fontName="Helvetica-Bold", fontSize=14.5, textColor=INK, leading=16),
        "stat_num_flag": ParagraphStyle("stat_num_flag", fontName="Helvetica-Bold", fontSize=14.5, textColor=OCHRE, leading=16),
        "stat_cap": ParagraphStyle("stat_cap", fontName="Helvetica", fontSize=7.8, textColor=INK, leading=10),
        "legend": ParagraphStyle("legend", fontName="Helvetica", fontSize=8.3, textColor=INK, leading=13),
        "th": ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9.3, textColor=INK, leading=12),
        "td": ParagraphStyle("td", fontName="Helvetica", fontSize=9.3, textColor=INK, leading=12),
        "td_flag": ParagraphStyle("td_flag", fontName="Helvetica-Bold", fontSize=9.3, textColor=OCHRE, leading=12),
        "close_h2": ParagraphStyle("close_h2", fontName="Times-Bold", fontSize=13.5, textColor=FOREST, leading=16, spaceAfter=12),
        "close_h3": ParagraphStyle("close_h3", fontName="Helvetica-Bold", fontSize=9.3, textColor=INK, leading=13, spaceAfter=6),
        "close_li": ParagraphStyle("close_li", fontName="Helvetica", fontSize=9.3, textColor=INK, leading=13.5, spaceAfter=5, leftIndent=10),
        "close_empty": ParagraphStyle("close_empty", fontName="Helvetica", fontSize=9.3, textColor=INK, leading=13),
        "footer": ParagraphStyle("footer", fontName="Helvetica", fontSize=8.3, textColor=INK, leading=11),
        "app_ratio": ParagraphStyle("app_ratio", fontName="Helvetica-Bold", fontSize=9.3, textColor=INK, leading=12, alignment=2),
        "app_name": ParagraphStyle("app_name", fontName="Helvetica", fontSize=9.3, textColor=INK, leading=12),
    }


def _nz(v, default=""):
    return default if v is None else v


# ------------------------------------------------------------- flowables
class SegmentedBar(Flowable):
    """A horizontal stacked bar — one rect per segment, width proportional
    to seg['pct']. Direct visual analogue of the template's
    .device-mix-bar / .version-bar / .compliance-bar."""

    def __init__(self, segments, width=CONTENT_WIDTH, height=8, radius=2):
        super().__init__()
        self.segments = segments or []
        self.width = width
        self.height = height
        self.radius = radius

    def wrap(self, availWidth, availHeight):
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        x = 0.0
        for seg in self.segments:
            w = self.width * (float(seg.get("pct", 0)) / 100.0)
            if w <= 0:
                continue
            c.setFillColor(HexColor(seg["color"]))
            c.rect(x, 0, w, self.height, stroke=0, fill=1)
            x += w


class AppBar(Flowable):
    """Single thin progress bar used in the app-protection table (M365
    per-app backup ratio)."""

    def __init__(self, pct, width=160, height=7):
        super().__init__()
        self.pct = float(pct or 0)
        self.width = width
        self.height = height

    def wrap(self, availWidth, availHeight):
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        c.setFillColor(RULE)
        c.rect(0, 0, self.width, self.height, stroke=0, fill=1)
        c.setFillColor(FOREST)
        c.rect(0, 0, self.width * min(self.pct, 100) / 100.0, self.height, stroke=0, fill=1)


def donut_drawing(segments, size=118, hole_frac=0.56, center_lines=None):
    """Donut chart built from Wedge slices, sweeping clockwise from 12
    o'clock — the same visual convention as the original SVG
    stroke-dasharray donuts in the HTML template."""
    d = Drawing(size, size)
    cx = cy = size / 2.0
    r = size / 2.0 - 2
    segments = segments or []
    total = sum(float(s.get("value", 0)) for s in segments) or 1.0
    angle = 90.0
    for seg in segments:
        frac = float(seg.get("value", 0)) / total
        if frac <= 0:
            continue
        sweep = frac * 360.0
        a0 = angle - sweep
        d.add(Wedge(cx, cy, r, a0, angle, fillColor=HexColor(seg["color"]), strokeColor=None))
        angle = a0
    d.add(Wedge(cx, cy, r * hole_frac, 0, 360, fillColor=PAPER, strokeColor=None))
    if center_lines:
        y = cy + (len(center_lines) - 1) * 6
        for text, fsize, color, bold in center_lines:
            d.add(
                String(
                    cx, y, text,
                    fontName="Helvetica-Bold" if bold else "Helvetica",
                    fontSize=fsize, fillColor=color, textAnchor="middle",
                )
            )
            y -= fsize + 4
    return d


def _cell_pad(t, top=0, bottom=0, left=0, right=0):
    t.setStyle(TableStyle([
        ("TOPPADDING", (0, 0), (-1, -1), top),
        ("BOTTOMPADDING", (0, 0), (-1, -1), bottom),
        ("LEFTPADDING", (0, 0), (-1, -1), left),
        ("RIGHTPADDING", (0, 0), (-1, -1), right),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def stat_row(stats, styles, gap=18):
    """A row of {value, label[, flag]} stat blocks, matching .stat-row."""
    if not stats:
        return None
    cells = []
    for s in stats:
        val_style = styles["stat_num_flag"] if s.get("flag") else styles["stat_num"]
        inner = Table([[Paragraph(str(s["value"]), val_style)], [Paragraph(s["label"], styles["stat_cap"])]])
        _cell_pad(inner, bottom=2)
        cells.append(inner)
    col_width = (CONTENT_WIDTH - gap * (len(cells) - 1)) / len(cells) if len(cells) > 1 else CONTENT_WIDTH
    row, widths = [], []
    for i, cell in enumerate(cells):
        row.append(cell)
        widths.append(col_width)
        if i < len(cells) - 1:
            row.append("")
            widths.append(gap)
    t = Table([row], colWidths=widths)
    _cell_pad(t)
    return t


def legend_paragraph(segments, styles, value_key="value", suffix=""):
    if not segments:
        return None
    parts = []
    for seg in segments:
        val = seg.get(value_key, seg.get("pct", ""))
        parts.append(f'<font color="{seg["color"]}">\u2022</font> {seg["label"]} \u2014 {val}{suffix}')
    return Paragraph("&nbsp;&nbsp;&nbsp;&nbsp;".join(parts), styles["legend"])


def plain_table(header, rows, col_flags=None, styles=None, col_widths=None):
    """A simple ruled data table: header row + N data rows. `col_flags`
    is an optional list of per-column booleans marking numeric columns
    that should right-align and flag-color when the row is flagged."""
    styles = styles or _styles()
    data = [[Paragraph(h, styles["th"]) for h in header]]
    for row in rows:
        cells = []
        for i, val in enumerate(row):
            cells.append(Paragraph(str(val), styles["td"]))
        data.append(cells)
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        ("LINEBELOW", (0, 0), (-1, 0), 1, INK),
        ("LINEBELOW", (0, 1), (-1, -2), 0.5, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    if col_flags:
        for i, is_num in enumerate(col_flags):
            if is_num:
                style.append(("ALIGN", (i, 0), (i, -1), "RIGHT"))
    t.setStyle(TableStyle(style))
    return t


# --------------------------------------------------------------- sections
def _section_header(title, source_label, styles):
    t = Table([[Paragraph(title, styles["h2"]), Paragraph(_nz(source_label), styles["section_source"])]],
              colWidths=[CONTENT_WIDTH * 0.7, CONTENT_WIDTH * 0.3])
    _cell_pad(t, bottom=10)
    return t


def _build_masthead(ctx, styles):
    flow = []
    brand = Paragraph(ctx.get("msp_name") or "", styles["brand"])
    period = Paragraph(_nz(ctx.get("report_period_label")), styles["period"])
    head = Table([[brand, period]], colWidths=[CONTENT_WIDTH * 0.6, CONTENT_WIDTH * 0.4])
    _cell_pad(head, bottom=6)
    head.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, 0), 1.4, FOREST), ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
    flow.append(head)
    flow.append(Paragraph(ctx.get("client_name") or "", styles["client_name"]))
    flow.append(Paragraph("Monthly Technology Report", styles["report_title"]))
    flow.append(Paragraph(_nz(ctx.get("headline")), styles["headline"]))
    return flow


def _build_kpi_strip(kpis, styles):
    if not kpis:
        return []
    cells, widths = [], []
    col_w = CONTENT_WIDTH / len(kpis)
    for k in kpis:
        val_style = styles["kpi_value_flag"] if k.get("flag") else styles["kpi_value"]
        inner = Table([[Paragraph(str(k["value"]), val_style)], [Paragraph(k["label"], styles["kpi_label"])]])
        _cell_pad(inner, top=10, bottom=10)
        cells.append(inner)
        widths.append(col_w)
    t = Table([cells], colWidths=widths)
    t.setStyle(TableStyle([
        ("LINEABOVE", (0, 0), (-1, 0), 0.75, RULE),
        ("LINEBELOW", (0, 0), (-1, 0), 0.75, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return [t, Spacer(1, 22)]


def _build_autotask(a, styles):
    if not a:
        return []
    flow = [_section_header("Service Desk", "Autotask", styles), Paragraph(a.get("prose", ""), styles["body"])]
    stats = [
        {"value": a.get("tickets_resolved", 0), "label": "tickets resolved"},
        {"value": a.get("hours_worked_total", 0), "label": "hours worked"},
        {"value": f"{a.get('first_response_met_pct', 0)}%", "label": "first response met"},
        {"value": f"{a.get('resolution_met_pct', 0)}%", "label": "resolution met"},
    ]
    row = stat_row(stats, styles)
    if row:
        flow.append(row)
    hbc = a.get("hours_by_category")
    if hbc:
        flow.append(Spacer(1, 10))
        rows = [(cat, hours) for cat, hours in hbc]
        flow.append(plain_table(["Category", "Hours"], rows, col_flags=[False, True], styles=styles,
                                 col_widths=[CONTENT_WIDTH * 0.7, CONTENT_WIDTH * 0.3]))
    flow.append(Spacer(1, 26))
    return [KeepTogether(flow[:2])] + flow[2:]


def _build_ninjaone(n, styles):
    if not n:
        return []
    flow = [_section_header("Devices & Patching", "NinjaOne", styles), Paragraph(n.get("prose", ""), styles["body"])]
    if n.get("compliance_segments"):
        segs = n["compliance_segments"]
        flow.append(SegmentedBar(segs))
        flow.append(Spacer(1, 6))
        flow.append(legend_paragraph(segs, styles, value_key="pct", suffix="%"))
    else:
        stats = [{"value": n.get("installed", 0), "label": "patches installed this month"}]
        if n.get("failed"):
            stats.append({"value": n["failed"], "label": "patches failed", "flag": True})
        row = stat_row(stats, styles)
        if row:
            flow.append(row)
    if n.get("os_segments"):
        segs = n["os_segments"]
        flow.append(KeepTogether([
            Paragraph("Windows versions", styles["subhead"]),
            SegmentedBar(segs), Spacer(1, 6), legend_paragraph(segs, styles),
        ]))
    flow.append(Spacer(1, 26))
    return flow


def _build_addigy(a, styles):
    if not a:
        return []
    flow = [_section_header("Apple Devices", "Addigy", styles), Paragraph(a.get("prose", ""), styles["body"])]
    if a.get("device_mix_segments"):
        segs = a["device_mix_segments"]
        flow.append(SegmentedBar(segs))
        flow.append(Spacer(1, 6))
        flow.append(legend_paragraph(segs, styles))
    if a.get("stats"):
        flow.append(Spacer(1, 10))
        row = stat_row(a["stats"], styles)
        if row:
            flow.append(row)
    if a.get("os_segments"):
        segs = a["os_segments"]
        flow.append(KeepTogether([
            Paragraph("macOS versions", styles["subhead"]),
            SegmentedBar(segs), Spacer(1, 6), legend_paragraph(segs, styles),
        ]))
    flow.append(Spacer(1, 26))
    return flow


def _build_security(s, styles):
    if not s:
        return []
    flow = [_section_header("Security", s.get("source_label"), styles), Paragraph(s.get("prose", ""), styles["body"])]
    row = stat_row(s.get("stats"), styles)
    if row:
        flow.append(row)
    if s.get("endpoint_segments"):
        segs = s["endpoint_segments"]
        flow.append(Spacer(1, 10))
        flow.append(SegmentedBar(segs))
        flow.append(Spacer(1, 6))
        flow.append(legend_paragraph(segs, styles))
    if s.get("email_threat_segments"):
        segs = s["email_threat_segments"]
        flow.append(KeepTogether([
            Paragraph("Email threats blocked, by type", styles["subhead"]),
            SegmentedBar(segs), Spacer(1, 6), legend_paragraph(segs, styles),
        ]))
    if s.get("activity_donut"):
        segs = s["activity_donut"]
        d = donut_drawing(segs, size=112)
        legend = legend_paragraph(segs, styles)
        t = Table([[d, legend]], colWidths=[130, CONTENT_WIDTH - 130])
        _cell_pad(t)
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        flow.append(KeepTogether([Paragraph("Endpoint activity status", styles["subhead"]), t]))
    flow.append(Spacer(1, 26))
    return flow


def _direction_block(label, block, styles):
    flow = [Paragraph(label, styles["subhead"])]
    row = stat_row(block.get("stats"), styles)
    if row:
        flow.append(row)
    if block.get("segments"):
        segs = block["segments"]
        flow.append(Spacer(1, 8))
        flow.append(SegmentedBar(segs))
        flow.append(Spacer(1, 6))
        flow.append(legend_paragraph(segs, styles))
    return flow


def _build_sophos_email(e, styles):
    if not e:
        return []
    flow = [_section_header("Email Security", "Sophos Email", styles), Paragraph(e.get("prose", ""), styles["body"])]
    if e.get("inbound"):
        flow += _direction_block("Inbound", e["inbound"], styles)
    if e.get("outbound"):
        flow += _direction_block("Outbound", e["outbound"], styles)
    intelix = e.get("intelix")
    if intelix:
        segs = intelix.get("segments") or []
        d = donut_drawing(
            segs, size=112,
            center_lines=[(str(intelix.get("total_analyzed", "")), 17, INK, True),
                          ("emails analyzed", 7, INK, False)],
        )
        legend = legend_paragraph(segs, styles)
        t = Table([[d, legend]], colWidths=[130, CONTENT_WIDTH - 130])
        _cell_pad(t)
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        flow.append(KeepTogether([Paragraph("Intelix threat analysis", styles["subhead"]), t]))
    at_risk = e.get("at_risk_users")
    if at_risk:
        flow.append(Paragraph("At-risk users", styles["subhead"]))
        rows = [(u["email"], u["risk_index"], u["impersonations"], u["risky_clicks"]) for u in at_risk]
        flow.append(plain_table(
            ["User", "Risk index", "Impersonations", "Risky clicks"], rows,
            col_flags=[False, True, True, True], styles=styles,
            col_widths=[CONTENT_WIDTH * 0.4, CONTENT_WIDTH * 0.2, CONTENT_WIDTH * 0.2, CONTENT_WIDTH * 0.2],
        ))
    flow.append(Spacer(1, 26))
    return flow


def _build_data_protection(dp, styles):
    if not dp:
        return []
    flow = [_section_header("Data Protection", dp.get("source_label"), styles), Paragraph(dp.get("prose", ""), styles["body"])]
    m365 = dp.get("m365")
    if m365:
        flow.append(Paragraph("Microsoft 365 backup", styles["subhead"]))
        row = stat_row(m365.get("stats"), styles)
        if row:
            flow.append(row)
        app_rows = m365.get("app_rows")
        if app_rows:
            flow.append(Spacer(1, 8))
            data = [[Paragraph(r["name"], styles["app_name"]), AppBar(r["pct"]), Paragraph(r["ratio"], styles["app_ratio"])]
                    for r in app_rows]
            t = Table(data, colWidths=[100, CONTENT_WIDTH - 100 - 60, 60])
            _cell_pad(t, top=5, bottom=5, right=10)
            t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
            flow.append(t)
    bcdr = dp.get("bcdr")
    if bcdr:
        flow.append(Paragraph("On-site backup appliance", styles["subhead"]))
        row = stat_row(bcdr.get("stats"), styles)
        if row:
            flow.append(row)
        donut = bcdr.get("storage_donut")
        if donut:
            d = donut_drawing(
                donut, size=112,
                center_lines=[(bcdr.get("storage_total_label", ""), 13, INK, True),
                              ("most recent backups", 7, INK, False)],
            )
            legend = legend_paragraph(donut, styles, value_key="pct", suffix="%")
            t = Table([[d, legend]], colWidths=[130, CONTENT_WIDTH - 130])
            _cell_pad(t)
            t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
            flow.append(KeepTogether([Spacer(1, 8), t]))
    flow.append(Spacer(1, 26))
    return flow


def _build_close_section(what_we_did, recommended_next, styles):
    left = [Paragraph("What we did", styles["close_h3"])]
    for item in (what_we_did or []):
        left.append(Paragraph(f"\u2022 {item}", styles["close_li"]))
    right = [Paragraph("Recommended next month", styles["close_h3"])]
    if recommended_next:
        for item in recommended_next:
            right.append(Paragraph(f"\u2022 {item}", styles["close_li"]))
    else:
        right.append(Paragraph("Nothing outstanding \u2014 everything's in good shape.", styles["close_empty"]))
    col_w = (CONTENT_WIDTH - 24) / 2
    body = Table([[left, right]], colWidths=[col_w, col_w])
    _cell_pad(body, right=24)
    outer = Table([[Paragraph("This month & next", styles["close_h2"])], [body]], colWidths=[CONTENT_WIDTH - 40])
    outer.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.75, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 20),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 20),
        ("LEFTPADDING", (0, 0), (-1, -1), 20),
        ("RIGHTPADDING", (0, 0), (-1, -1), 20),
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#FFFFFF")),
    ]))
    return outer


def _footer(canvas, doc, msp_name, client_name):
    canvas.saveState()
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.75)
    y = PAGE_MARGIN - 24
    canvas.line(PAGE_MARGIN, y, LETTER[0] - PAGE_MARGIN, y)
    canvas.setFont("Helvetica", 8.3)
    canvas.setFillColor(INK)
    canvas.drawString(PAGE_MARGIN, y - 14, msp_name or "")
    canvas.drawRightString(LETTER[0] - PAGE_MARGIN, y - 14, f"Prepared for {client_name or ''}")
    canvas.restoreState()


def generate_pdf(context: dict, output_path: str) -> None:
    """Render `context` (as produced by render_report.build_context) to a
    PDF at `output_path` using reportlab only — no native dependencies."""
    styles = _styles()
    doc = SimpleDocTemplate(
        output_path, pagesize=LETTER,
        leftMargin=PAGE_MARGIN, rightMargin=PAGE_MARGIN,
        topMargin=PAGE_MARGIN, bottomMargin=PAGE_MARGIN + 0.15 * inch,
        title=f"Monthly Technology Report \u2014 {context.get('client_name', '')}",
    )

    story = []
    story += _build_masthead(context, styles)
    story += _build_kpi_strip(context.get("kpis"), styles)
    story += _build_autotask(context.get("autotask"), styles)
    story += _build_ninjaone(context.get("ninjaone"), styles)
    story += _build_addigy(context.get("addigy"), styles)
    story += _build_security(context.get("security"), styles)
    story += _build_sophos_email(context.get("sophos_email"), styles)
    story += _build_data_protection(context.get("data_protection"), styles)
    story.append(KeepTogether([_build_close_section(context.get("what_we_did"), context.get("recommended_next"), styles)]))

    def _on_page(canvas, doc_):
        _footer(canvas, doc_, context.get("msp_name"), context.get("client_name"))

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)

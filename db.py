"""Postgres persistence for generated monthly reports.

Mirrors aiassessment's simple pattern: plain SQLAlchemy models, no Alembic,
`init_db()` calls `Base.metadata.create_all()` on startup. Reuses the same
shared "db" Postgres database on the DigitalOcean App (DATABASE_URL env var
points at the same cluster aiassessment uses) — this module's table
(`reports`) lives alongside aiassessment's own tables in that one database.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    delete,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    client_slug = Column(String(64), nullable=False, index=True)
    client_name = Column(String(255), nullable=False)
    month = Column(String(7), nullable=False, index=True)  # "YYYY-MM"
    generated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    context = Column(JSONB, nullable=True)  # full build_context() dict, for reproducibility/debugging
    pdf = Column(LargeBinary, nullable=False)
    emailed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (UniqueConstraint("client_slug", "month", name="uq_reports_client_month"),)


class SophosWebEvent(Base):
    """One Sophos Endpoint WebControlViolation event (warned/bypassed/blocked
    site visit), as returned by the SIEM events API. The SIEM API only keeps
    24 hours of history, so these are harvested continuously by
    collect_sophos_web.py and accumulate here. Keyed on Sophos's own event id
    so overlapping harvest windows can't double-count."""
    __tablename__ = "sophos_web_events"

    event_id = Column(String(64), primary_key=True)
    client_slug = Column(String(64), nullable=False, index=True)
    occurred_at = Column(DateTime(timezone=True), nullable=False, index=True)
    month = Column(String(7), nullable=False, index=True)  # report-timezone "YYYY-MM"
    action = Column(String(16), nullable=True)  # warned / bypassed / blocked / other
    url = Column(Text, nullable=True)
    domain = Column(String(255), nullable=True, index=True)
    category = Column(String(255), nullable=True)  # only present on block events
    ai_tool = Column(String(64), nullable=True, index=True)  # None = not a known AI domain
    user_name = Column(String(255), nullable=True)
    device_name = Column(String(255), nullable=True)
    endpoint_id = Column(String(64), nullable=True)
    raw = Column(JSONB, nullable=True)


class SophosWebHarvest(Base):
    """Per-client harvest bookkeeping: when we last pulled, and how far the
    pulled window reached, so the next pull starts where the last left off."""
    __tablename__ = "sophos_web_harvests"

    client_slug = Column(String(64), primary_key=True)
    first_harvest_at = Column(DateTime(timezone=True), nullable=True)
    last_harvest_at = Column(DateTime(timezone=True), nullable=True)
    last_window_end = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)


class AiUsageMonthly(Base):
    """Month-to-date AI site visit counts at tool x user x device grain,
    rebuilt from sophos_web_events after every harvest. Any rollup (by tool,
    by user, by device) is a GROUP BY over this table."""
    __tablename__ = "ai_usage_monthly"

    id = Column(Integer, primary_key=True)
    client_slug = Column(String(64), nullable=False, index=True)
    month = Column(String(7), nullable=False, index=True)
    ai_tool = Column(String(64), nullable=False)
    user_name = Column(String(255), nullable=True)
    device_name = Column(String(255), nullable=True)
    visits = Column(Integer, nullable=False)  # distinct 5-minute windows with activity
    active_days = Column(Integer, nullable=False)  # distinct days with >=1 visit
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


_engine = None
_SessionLocal = None


def _get_database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set — cannot connect to Postgres.")
    # DigitalOcean's managed Postgres connection strings use "postgresql://";
    # SQLAlchemy's psycopg2 driver accepts that scheme directly, no rewrite needed.
    return url


def init_db():
    """Create the engine (once) and ensure tables exist. Safe to call repeatedly."""
    global _engine, _SessionLocal
    if _engine is None:
        _engine = create_engine(_get_database_url(), pool_pre_ping=True)
        _SessionLocal = sessionmaker(bind=_engine)
        Base.metadata.create_all(_engine)
    return _engine


def get_session():
    if _SessionLocal is None:
        init_db()
    return _SessionLocal()


def report_exists(client_slug: str, month: str) -> bool:
    """True if a report for this client/month has already been generated and stored."""
    session = get_session()
    try:
        return (
            session.query(Report.id)
            .filter(Report.client_slug == client_slug, Report.month == month)
            .first()
            is not None
        )
    finally:
        session.close()


def save_report(client_slug: str, client_name: str, month: str, context: dict, pdf_bytes: bytes) -> Report:
    """Insert (or replace) the stored report for this client/month."""
    session = get_session()
    try:
        existing = (
            session.query(Report)
            .filter(Report.client_slug == client_slug, Report.month == month)
            .first()
        )
        if existing:
            existing.client_name = client_name
            existing.context = context
            existing.pdf = pdf_bytes
            existing.generated_at = datetime.now(timezone.utc)
            session.commit()
            session.refresh(existing)
            return existing
        report = Report(
            client_slug=client_slug,
            client_name=client_name,
            month=month,
            context=context,
            pdf=pdf_bytes,
        )
        session.add(report)
        session.commit()
        session.refresh(report)
        return report
    finally:
        session.close()


def mark_emailed(report_id: int) -> None:
    session = get_session()
    try:
        report = session.query(Report).get(report_id)
        if report:
            report.emailed_at = datetime.now(timezone.utc)
            session.commit()
    finally:
        session.close()


def get_report(client_slug: str, month: str) -> Report | None:
    session = get_session()
    try:
        return (
            session.query(Report)
            .filter(Report.client_slug == client_slug, Report.month == month)
            .first()
        )
    finally:
        session.close()


def list_reports(month: str | None = None):
    session = get_session()
    try:
        q = session.query(Report.id, Report.client_slug, Report.client_name, Report.month, Report.generated_at, Report.emailed_at)
        if month:
            q = q.filter(Report.month == month)
        return q.order_by(Report.client_name).all()
    finally:
        session.close()


# --- Sophos web / AI usage -------------------------------------------------

def get_web_harvest(client_slug: str) -> SophosWebHarvest | None:
    session = get_session()
    try:
        return session.get(SophosWebHarvest, client_slug)
    finally:
        session.close()


def record_web_harvest(client_slug: str, window_end, error: str | None = None) -> None:
    """Success (error=None) advances last_window_end; a failure only records
    the error so the next attempt retries the same window."""
    session = get_session()
    try:
        row = session.get(SophosWebHarvest, client_slug)
        now = datetime.now(timezone.utc)
        if row is None:
            row = SophosWebHarvest(client_slug=client_slug)
            session.add(row)
        if error is None:
            row.first_harvest_at = row.first_harvest_at or now
            row.last_harvest_at = now
            row.last_window_end = window_end
        row.last_error = error
        session.commit()
    finally:
        session.close()


def save_web_events(rows: list[dict]) -> int:
    """Upsert events by event_id. Returns how many were new."""
    if not rows:
        return 0
    from sqlalchemy.dialects.postgresql import insert
    session = get_session()
    try:
        stmt = insert(SophosWebEvent).values(rows).on_conflict_do_nothing(index_elements=["event_id"])
        result = session.execute(stmt)
        session.commit()
        return result.rowcount or 0
    finally:
        session.close()


def rebuild_ai_usage(client_slug: str, month: str) -> int:
    """Recompute ai_usage_monthly for one client/month from raw events."""
    from sqlalchemy import cast, Date
    session = get_session()
    try:
        E = SophosWebEvent
        q = (
            session.query(
                E.ai_tool, E.user_name, E.device_name,
                # One "visit" = a 5-minute window with any events for that
                # tool/user/device -- collapses the warned+bypassed pair and
                # sub-resource loads (claude.ai + assets.claude.ai) into one.
                func.count(func.distinct(func.floor(func.extract("epoch", E.occurred_at) / 300))),
                func.count(func.distinct(cast(func.timezone(os.environ.get("REPORT_TIMEZONE", "America/New_York"), E.occurred_at), Date))),
                func.min(E.occurred_at), func.max(E.occurred_at),
            )
            .filter(E.client_slug == client_slug, E.month == month, E.ai_tool.isnot(None))
            .group_by(E.ai_tool, E.user_name, E.device_name)
        )
        rows = q.all()
        session.execute(delete(AiUsageMonthly).where(AiUsageMonthly.client_slug == client_slug, AiUsageMonthly.month == month))
        now = datetime.now(timezone.utc)
        for tool, user, device, visits, days, first, last in rows:
            session.add(AiUsageMonthly(
                client_slug=client_slug, month=month, ai_tool=tool, user_name=user, device_name=device,
                visits=visits, active_days=days, first_seen=first, last_seen=last, updated_at=now,
            ))
        session.commit()
        return len(rows)
    finally:
        session.close()


def ai_usage_summary(client_slug: str, month: str) -> dict:
    """Month-to-date AI usage rollups for the report: by tool, by user, by
    device, plus totals and when tracking started for this client."""
    session = get_session()
    try:
        A = AiUsageMonthly
        rows = session.query(A).filter(A.client_slug == client_slug, A.month == month).all()
        harvest = session.get(SophosWebHarvest, client_slug)
        non_ai = (
            session.query(func.count(SophosWebEvent.event_id))
            .filter(SophosWebEvent.client_slug == client_slug, SophosWebEvent.month == month, SophosWebEvent.ai_tool.is_(None))
            .scalar()
        )
    finally:
        session.close()

    def rollup(key):
        agg = {}
        for r in rows:
            k = getattr(r, key) or "(unknown)"
            a = agg.setdefault(k, {"name": k, "visits": 0, "users": set(), "devices": set(), "tools": set()})
            a["visits"] += r.visits
            a["users"].add(r.user_name or "(unknown)")
            a["devices"].add(r.device_name or "(unknown)")
            a["tools"].add(r.ai_tool)
        out = []
        for a in agg.values():
            out.append({"name": a["name"], "visits": a["visits"], "users": len(a["users"]),
                        "devices": len(a["devices"]), "tools": sorted(a["tools"])})
        return sorted(out, key=lambda x: -x["visits"])

    return {
        "month": month,
        "tracking_since": harvest.first_harvest_at.isoformat() if harvest and harvest.first_harvest_at else None,
        "last_harvest_at": harvest.last_harvest_at.isoformat() if harvest and harvest.last_harvest_at else None,
        "total_visits": sum(r.visits for r in rows),
        "by_tool": rollup("ai_tool"),
        "by_user": rollup("user_name"),
        "by_device": rollup("device_name"),
        "non_ai_events": non_ai or 0,
    }


def web_event_rows(client_slug: str, month: str):
    """(occurred_at, domain, category, user_name, device_name) for every
    stored web event for this client/month -- for report-time rollups."""
    session = get_session()
    try:
        E = SophosWebEvent
        return (
            session.query(E.occurred_at, E.domain, E.category, E.user_name, E.device_name)
            .filter(E.client_slug == client_slug, E.month == month)
            .all()
        )
    finally:
        session.close()

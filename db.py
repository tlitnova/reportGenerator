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
    UniqueConstraint,
    create_engine,
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

"""SMTP delivery for finished report PDFs.

Same env-var names and connection pattern as aiassessment's own
`_smtp_connect()` (SMTP_HOST/PORT/USERNAME/PASSWORD/USE_TLS/FROM/TO), so the
two components can point at the same mail relay if convenient — but each
DigitalOcean App component has its own independent env vars, so these must
be set on reportGenerator's Worker config too, even if the values match
aiassessment's.
"""
from __future__ import annotations

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage

logger = logging.getLogger(__name__)


def _connect_with(host: str, port: int, username: str, password: str, use_tls: bool) -> smtplib.SMTP:
    server = smtplib.SMTP(host, port, timeout=30)
    server.ehlo()
    if use_tls:
        server.starttls(context=ssl.create_default_context())
        server.ehlo()
    server.login(username, password)
    return server


def _smtp_connect() -> smtplib.SMTP:
    """Connects using the primary SMTP_* relay, falling back to SMTP2GO_*
    (SMTP2GO_HOST/PORT/USERNAME/PASSWORD, TLS assumed true) if the primary
    relay is unreachable or rejects auth. Raises RuntimeError only if
    neither is configured, or both fail.
    """
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_username = os.environ.get("SMTP_USERNAME")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    smtp_use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"

    fallback_host = os.environ.get("SMTP2GO_HOST", "mail.smtp2go.com")
    fallback_port = int(os.environ.get("SMTP2GO_PORT", "587"))
    fallback_username = os.environ.get("SMTP2GO_USERNAME")
    fallback_password = os.environ.get("SMTP2GO_PASSWORD")

    primary_configured = all([smtp_host, smtp_username, smtp_password])
    fallback_configured = all([fallback_username, fallback_password])

    if not primary_configured and not fallback_configured:
        raise RuntimeError(
            "No SMTP settings configured (need SMTP_HOST/USERNAME/PASSWORD, "
            "or SMTP2GO_USERNAME/PASSWORD as a fallback)."
        )

    if primary_configured:
        try:
            return _connect_with(smtp_host, smtp_port, smtp_username, smtp_password, smtp_use_tls)
        except Exception as exc:
            logger.warning("Primary SMTP relay (%s) failed: %s", smtp_host, exc)
            if not fallback_configured:
                raise

    return _connect_with(fallback_host, fallback_port, fallback_username, fallback_password, True)


def send_report_email(client_name: str, month: str, pdf_bytes: bytes, filename: str) -> None:
    """Emails one finished report PDF as an attachment to SMTP_TO.

    Raises RuntimeError if SMTP_FROM/SMTP_TO aren't configured, so the
    caller can log-and-continue rather than crash the whole monthly run
    over one missing env var.
    """
    smtp_from = os.environ.get("SMTP_FROM")
    smtp_to = os.environ.get("SMTP_TO")
    if not smtp_from or not smtp_to:
        raise RuntimeError("SMTP_FROM or SMTP_TO missing; skipping report email.")

    message = EmailMessage()
    message["Subject"] = f"Monthly Report — {client_name} ({month})"
    message["From"] = smtp_from
    message["To"] = smtp_to
    message.set_content(
        f"Attached: the {month} monthly technology report for {client_name}.\n\n"
        f"This report was generated and stored automatically by reportGenerator."
    )
    message.add_attachment(
        pdf_bytes,
        maintype="application",
        subtype="pdf",
        filename=filename,
    )

    server = _smtp_connect()
    try:
        server.send_message(message)
    finally:
        server.quit()


def send_collector_failure_alert(month: str, failures: list[dict]) -> None:
    """Emails a summary of collector failures from one monthly run to SMTP_TO.

    Call only when `failures` is non-empty — one email per run, not per
    failure, so a bad token that affects several clients doesn't spam the
    inbox. Each dict in `failures` has keys: client, source, script, error.

    Raises RuntimeError if SMTP_FROM/SMTP_TO aren't configured, mirroring
    send_report_email's behavior so the caller can log-and-continue rather
    than crash the monthly run over a missing env var.
    """
    smtp_from = os.environ.get("SMTP_FROM")
    smtp_to = os.environ.get("SMTP_TO")
    if not smtp_from or not smtp_to:
        raise RuntimeError("SMTP_FROM or SMTP_TO missing; skipping collector failure alert.")

    lines = [
        f"The {month} monthly report run hit {len(failures)} collector issue(s).",
        "Affected report(s) were still generated, but may be missing data for these sections:",
        "",
    ]
    for failure in failures:
        lines.append(f"- {failure['client']} / {failure['source']} ({failure['script']})")
        lines.append(f"    {failure['error']}")
        lines.append("")
    lines.append(
        "This alert is generated automatically by reportGenerator's run_monthly.py "
        "whenever one or more collect_*.py scripts exit non-zero (expired token, "
        "upstream API down, etc.). No action is needed if this resolves itself next "
        "month; if it keeps recurring for the same integration, the credential likely "
        "needs to be refreshed."
    )

    message = EmailMessage()
    message["Subject"] = f"[reportGenerator] {month}: {len(failures)} collector issue(s)"
    message["From"] = smtp_from
    message["To"] = smtp_to
    message.set_content("\n".join(lines))

    server = _smtp_connect()
    try:
        server.send_message(message)
    finally:
        server.quit()

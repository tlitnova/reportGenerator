"""SMTP delivery for finished report PDFs.

Same env-var names and connection pattern as aiassessment's own
`_smtp_connect()` (SMTP_HOST/PORT/USERNAME/PASSWORD/USE_TLS/FROM/TO), so the
two components can point at the same mail relay if convenient — but each
DigitalOcean App component has its own independent env vars, so these must
be set on reportGenerator's Worker config too, even if the values match
aiassessment's.
"""
from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage


def _smtp_connect() -> smtplib.SMTP:
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_username = os.environ.get("SMTP_USERNAME")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    smtp_use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"

    if not all([smtp_host, smtp_username, smtp_password]):
        raise RuntimeError("SMTP settings are incomplete (need SMTP_HOST, SMTP_USERNAME, SMTP_PASSWORD).")

    server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
    server.ehlo()
    if smtp_use_tls:
        server.starttls(context=ssl.create_default_context())
        server.ehlo()
    server.login(smtp_username, smtp_password)
    return server


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

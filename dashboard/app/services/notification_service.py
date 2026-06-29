from __future__ import annotations

import logging
import smtplib
from datetime import datetime
from email.message import EmailMessage
from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from ..integration import (
    email_settings_configured,
    graph_email_configured,
    smtp_email_configured,
)
from ..models import Company, Device, DeviceEvent, IntegrationSettings
from ..security.secrets import decrypt_secret
from ..services.common import clean_optional, get_or_create_integration_settings
from ..web import format_datetime

logger = logging.getLogger(__name__)


def send_smtp_email(
    integration_settings: IntegrationSettings, to_email: str, subject: str, body: str
) -> None:
    smtp_host = integration_settings.smtp_host
    smtp_port = integration_settings.smtp_port
    smtp_from = integration_settings.smtp_from
    if not smtp_host or smtp_port is None or not smtp_from:
        raise RuntimeError("SMTP settings are incomplete")
    message = EmailMessage()
    message["From"] = smtp_from
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as smtp:
        smtp_password = decrypt_secret(integration_settings.smtp_password)
        if integration_settings.smtp_username and smtp_password:
            smtp.login(integration_settings.smtp_username, smtp_password)
        smtp.send_message(message)


def send_graph_email(
    integration_settings: IntegrationSettings, to_email: str, subject: str, body: str
) -> None:
    token_url = (
        "https://login.microsoftonline.com/"
        f"{integration_settings.graph_tenant_id}/oauth2/v2.0/token"
    )
    with httpx.Client(timeout=20) as client:
        token_response = client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": integration_settings.graph_client_id,
                "client_secret": decrypt_secret(
                    integration_settings.graph_client_secret
                ),
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        token_response.raise_for_status()
        access_token = token_response.json()["access_token"]
        send_response = client.post(
            "https://graph.microsoft.com/v1.0/users/"
            f"{quote(str(integration_settings.graph_sender), safe='')}/sendMail",
            headers={"Authorization": f"Bearer {access_token}"},
            json={
                "message": {
                    "subject": subject,
                    "body": {"contentType": "Text", "content": body},
                    "toRecipients": [{"emailAddress": {"address": to_email}}],
                }
            },
        )
        send_response.raise_for_status()


def send_notification_email(
    db: Session, to_email: str, subject: str, body: str
) -> None:
    integration_settings = get_or_create_integration_settings(db)
    if smtp_email_configured(integration_settings):
        send_smtp_email(integration_settings, to_email, subject, body)
        return
    if graph_email_configured(integration_settings):
        send_graph_email(integration_settings, to_email, subject, body)
        return
    raise RuntimeError("email settings are not configured")


def health_notification_status_label(status: str) -> str:
    return "critical" if status == "offline" else status


def should_notify_for_health_status(device: Device, new_status: str) -> bool:
    if new_status == "warning":
        return device.email_notify_on_warning
    if new_status == "offline":
        return device.email_notify_on_critical
    return False


def build_health_notification_email(
    device: Device,
    company: Company | None,
    previous_status: str,
    new_status: str,
    current_time: datetime,
) -> tuple[str, str]:
    display_status = health_notification_status_label(new_status)
    subject = f"[OPNsense Hub] Firewall status {display_status}: {device.hostname}"
    body = "\n".join(
        [
            f"Firewall: {device.hostname}",
            f"Company: {company.name if company else 'Unknown'}",
            f"Status: {display_status}",
            f"Previous status: {previous_status}",
            f"Tunnel IP: {device.wg_tunnel_ip}",
            "Last seen: "
            + (
                format_datetime(device.last_seen_at, include_tz=True)
                if device.last_seen_at
                else "Never"
            ),
            f"Time: {format_datetime(current_time, include_tz=True)}",
            "",
            "This alert was sent because email notifications are enabled for this firewall in OPNsense Hub.",
        ]
    )
    return subject, body


def maybe_send_health_notification(
    db: Session,
    device: Device,
    previous_status: str,
    new_status: str,
    current_time: datetime,
    email_sender=None,
) -> bool:
    if device.revoked_at or previous_status == new_status:
        return False
    if not device.email_notifications_enabled:
        return False
    if not should_notify_for_health_status(device, new_status):
        return False
    recipient = clean_optional(device.email_notification_recipient)
    if not recipient:
        return False
    integration_settings = get_or_create_integration_settings(db)
    if not email_settings_configured(integration_settings):
        return False
    company = db.get(Company, device.company_id)
    subject, body = build_health_notification_email(
        device, company, previous_status, new_status, current_time
    )
    sender = email_sender or send_notification_email
    try:
        sender(db, recipient, subject, body)
    except Exception as exc:
        db.add(
            DeviceEvent(
                device_id=device.id,
                event_type="email_notification_failed",
                message=(
                    "Could not send health status email notification: "
                    f"{exc.__class__.__name__}"
                )[:1000],
            )
        )
        logger.warning(
            "Health status notification failed for device %s: %s",
            device.id,
            exc.__class__.__name__,
        )
        return False
    device.email_last_notified_status = new_status
    device.email_last_notified_at = current_time
    db.add(
        DeviceEvent(
            device_id=device.id,
            event_type="email_notification_sent",
            message=(
                f"Health status notification sent for {health_notification_status_label(new_status)}"
            )[:1000],
        )
    )
    return True

from __future__ import annotations

import logging
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..integration import (
    email_settings_configured,
    graph_email_configured,
    smtp_email_configured,
)
from ..models import AuditLog, Company, Device, DeviceEvent, IntegrationSettings
from ..security.secrets import decrypt_secret
from ..services.common import clean_optional, get_or_create_integration_settings
from ..web import format_datetime

settings = get_settings()

logger = logging.getLogger(__name__)


def send_security_alert_email(db: Session, subject: str, body: str) -> bool:
    if not settings.security_alert_email_enabled:
        return False
    target = clean_optional(settings.initial_admin_email)
    if not target:
        return False
    try:
        send_notification_email(db, target, subject, body)
    except Exception as exc:
        logger.warning("Security alert email failed: %s", exc.__class__.__name__)
        return False
    return True


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


def maintenance_window_active(
    device: Device, current_time: datetime | None = None
) -> bool:
    if not device.maintenance_until:
        return False
    now = current_time or datetime.now(timezone.utc)
    maintenance_until = device.maintenance_until
    if maintenance_until.tzinfo is None:
        maintenance_until = maintenance_until.replace(tzinfo=timezone.utc)
    return maintenance_until.astimezone(timezone.utc) > now.astimezone(timezone.utc)


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
    if maintenance_window_active(device, current_time):
        return False
    recipient = clean_optional(device.email_notification_recipient)
    if not recipient:
        return False
    integration_settings = get_or_create_integration_settings(db)
    if not email_settings_configured(integration_settings):
        return False
    if not should_notify_for_health_status(device, new_status):
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


def _device_rule_recipient(
    db: Session, device: Device, integration_settings: IntegrationSettings
) -> str | None:
    if not device.email_notifications_enabled:
        return None
    if not email_settings_configured(integration_settings):
        return None
    return clean_optional(device.email_notification_recipient)


def _send_device_rule_notification(
    db: Session,
    device: Device,
    current_time: datetime,
    *,
    subject: str,
    body: str,
    event_message: str,
    failure_context: str,
) -> bool:
    recipient = clean_optional(device.email_notification_recipient)
    if not recipient:
        return False
    try:
        send_notification_email(db, recipient, subject, body)
    except Exception as exc:
        db.add(
            DeviceEvent(
                device_id=device.id,
                event_type="email_notification_failed",
                message=(
                    f"Could not send {failure_context} notification: {exc.__class__.__name__}"
                )[:1000],
            )
        )
        logger.warning(
            "Rule notification failed for device %s: %s",
            device.id,
            exc.__class__.__name__,
        )
        return False
    device.email_last_notified_status = event_message[:30]
    device.email_last_notified_at = current_time
    db.add(
        DeviceEvent(
            device_id=device.id,
            event_type="email_notification_sent",
            message=event_message[:1000],
        )
    )
    return True


def maybe_send_phase2_device_notifications(
    db: Session,
    device: Device,
    *,
    backup_overdue: bool,
    license_expiring: bool,
    firmware_available: bool,
    current_time: datetime,
) -> None:
    if device.revoked_at or maintenance_window_active(device, current_time):
        return
    integration_settings = get_or_create_integration_settings(db)
    recipient = _device_rule_recipient(db, device, integration_settings)
    if not recipient:
        return
    company = db.get(Company, device.company_id)
    if backup_overdue:
        if (
            device.email_notify_on_backup_overdue
            and device.backup_overdue_notified_at is None
        ):
            subject = f"[OPNsense Hub] Backup overdue: {device.hostname}"
            body = "\n".join(
                [
                    f"Firewall: {device.hostname}",
                    f"Company: {company.name if company else 'Unknown'}",
                    "Backup status: overdue",
                    "Last backup: "
                    + (
                        format_datetime(device.backup_last_uploaded_at, include_tz=True)
                        if device.backup_last_uploaded_at
                        else "Never"
                    ),
                    f"Time: {format_datetime(current_time, include_tz=True)}",
                ]
            )
            if _send_device_rule_notification(
                db,
                device,
                current_time,
                subject=subject,
                body=body,
                event_message="Backup overdue notification sent",
                failure_context="backup overdue",
            ):
                device.backup_overdue_notified_at = current_time
    else:
        device.backup_overdue_notified_at = None

    if license_expiring:
        should_send_license = device.email_notify_on_license_expiring and (
            device.license_expiring_notified_at is None
            or (
                device.license_expires_at
                and device.license_expiring_notified_at < device.license_expires_at
            )
        )
        if should_send_license:
            subject = f"[OPNsense Hub] License expiring: {device.hostname}"
            body = "\n".join(
                [
                    f"Firewall: {device.hostname}",
                    f"Company: {company.name if company else 'Unknown'}",
                    "License expiration: "
                    + (
                        format_datetime(device.license_expires_at, include_tz=True)
                        if device.license_expires_at
                        else "Unknown"
                    ),
                    f"Time: {format_datetime(current_time, include_tz=True)}",
                ]
            )
            if _send_device_rule_notification(
                db,
                device,
                current_time,
                subject=subject,
                body=body,
                event_message="License expiring notification sent",
                failure_context="license expiring",
            ):
                device.license_expiring_notified_at = current_time
    else:
        device.license_expiring_notified_at = None

    if firmware_available:
        should_send_firmware = device.email_notify_on_firmware_available and (
            device.firmware_available_notified_at is None
            or (
                device.firmware_checked_at
                and device.firmware_available_notified_at < device.firmware_checked_at
            )
        )
        if should_send_firmware:
            subject = f"[OPNsense Hub] Firmware available: {device.hostname}"
            body = "\n".join(
                [
                    f"Firewall: {device.hostname}",
                    f"Company: {company.name if company else 'Unknown'}",
                    f"Firmware status: {device.firmware_status}",
                    f"Current version: {device.firmware_current_version or 'Unknown'}",
                    f"Available version: {device.firmware_available_version or 'Unknown'}",
                    f"Time: {format_datetime(current_time, include_tz=True)}",
                ]
            )
            if _send_device_rule_notification(
                db,
                device,
                current_time,
                subject=subject,
                body=body,
                event_message="Firmware available notification sent",
                failure_context="firmware available",
            ):
                device.firmware_available_notified_at = current_time
    else:
        device.firmware_available_notified_at = None


def maybe_notify_for_repeated_auth_failures(
    db: Session,
    action: str,
    detail: str | None,
    current_time: datetime | None = None,
) -> bool:
    integration_settings = get_or_create_integration_settings(db)
    if integration_settings.notify_on_repeated_auth_failures is False:
        return False
    if not action.startswith("auth.") or not action.endswith(".failed"):
        return False
    now = current_time or datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=15)
    recent_failures = db.scalars(
        select(AuditLog)
        .where(
            AuditLog.action == action,
            AuditLog.created_at >= cutoff,
        )
        .order_by(AuditLog.created_at.desc())
    ).all()
    count = len(recent_failures)
    if count < 5 or count % 5 != 0:
        return False
    subject = f"[OPNsense Hub] Repeated auth failures: {action}"
    body = "\n".join(
        [
            f"Action: {action}",
            f"Recent failures in the last 15 minutes: {count}",
            f"Latest detail: {detail or action}",
            f"Time: {format_datetime(now, include_tz=True)}",
        ]
    )
    return send_security_alert_email(db, subject, body)

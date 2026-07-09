from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .backups import backup_due, backup_request_pending
from .config import get_settings
from .integration import email_settings_configured
from .models import (
    AuditLog,
    Company,
    CompanyUser,
    Device,
    DeviceEvent,
    IntegrationSettings,
    User,
    UserAttentionAcknowledgement,
    UserDashboardFilter,
)
from .rbac import is_global_admin
from .security import utc_now
from .services.notification_service import maintenance_window_active

DASHBOARD_EVENT_LIMIT = 25
HEALTH_LIST_LIMIT = 5
ATTENTION_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}
STATUS_COLORS = {
    "online": "var(--chart-success)",
    "warning": "var(--chart-warning)",
    "critical": "var(--chart-danger)",
    "revoked": "var(--chart-neutral)",
    "other": "var(--chart-info)",
}
settings = get_settings()


def accessible_companies_for_user(db: Session, user: User) -> list[Company]:
    statement = select(Company).order_by(Company.name)
    if not is_global_admin(user):
        statement = statement.join(CompanyUser).where(CompanyUser.user_id == user.id)
    return list(db.scalars(statement).all())


def accessible_devices_for_user(db: Session, user: User) -> list[Device]:
    statement = (
        select(Device)
        .options(selectinload(Device.company))
        .join(Company)
        .order_by(Company.name, Device.hostname)
    )
    if not is_global_admin(user):
        statement = statement.join(
            CompanyUser, CompanyUser.company_id == Device.company_id
        ).where(CompanyUser.user_id == user.id)
    return list(db.scalars(statement).all())


def normalized_status(device: Device) -> str:
    if device.revoked_at is not None or (device.status or "").lower() == "revoked":
        return "revoked"
    status = (device.status or "unknown").lower()
    if status == "offline":
        return "critical"
    if status in {"online", "warning", "critical"}:
        if device.last_seen_at is not None:
            age = utc_now() - device.last_seen_at.astimezone(timezone.utc)
            warning_after = timedelta(
                seconds=max(1, settings.firewall_health_check_interval_seconds)
                * max(1, settings.firewall_health_warning_misses)
            )
            critical_after = timedelta(
                seconds=max(1, settings.firewall_health_check_interval_seconds)
                * max(1, settings.firewall_health_critical_misses)
            )
            if age >= critical_after:
                return "critical"
            if age >= warning_after and status == "online":
                return "warning"
        return status
    return "other"


def active_device(device: Device) -> bool:
    return normalized_status(device) != "revoked"


def interval_display(device: Device) -> str:
    value = max(1, int(device.backup_interval_value or 1))
    unit = (device.backup_interval_unit or "hours").capitalize()
    return f"{value} {unit}"


def dashboard_backup_status(device: Device, now: datetime) -> dict[str, str | bool]:
    if not device.backup_enabled:
        return {"label": "Disabled", "class": "text-muted", "actionable": False}
    if backup_request_pending(device):
        return {"label": "Pending", "class": "text-warning", "actionable": True}
    if device.backup_last_uploaded_at is None:
        return {"label": "Never backed up", "class": "text-danger", "actionable": True}
    if backup_due(device, now=now):
        return {"label": "Overdue", "class": "text-danger", "actionable": True}
    return {"label": "OK", "class": "text-success", "actionable": False}


def dashboard_firmware_status(device: Device) -> dict[str, str | bool]:
    status = (device.firmware_status or "unknown").lower()
    if status == "none":
        return {"label": "Up to date", "class": "text-success", "attention": False}
    if status == "update":
        return {"label": "Updates available", "class": "text-info", "attention": True}
    if status == "upgrade":
        return {
            "label": "Upgrade available",
            "class": "text-warning",
            "attention": True,
        }
    if status == "error":
        return {"label": "Check failed", "class": "text-danger", "attention": True}
    return {
        "label": "Unknown",
        "class": "text-muted",
        "attention": active_device(device),
    }


def dashboard_license_status(device: Device, now: datetime) -> dict[str, object]:
    if (device.license_type or "").lower() != "business":
        return {
            "label": "Community",
            "days_left": None,
            "expired": False,
            "expiring_soon": False,
        }
    if not device.license_expires_at:
        return {
            "label": "Business",
            "days_left": None,
            "expired": False,
            "expiring_soon": False,
        }
    expiration = device.license_expires_at.astimezone(timezone.utc).date()
    days_left = (expiration - now.astimezone(timezone.utc).date()).days
    return {
        "label": "Business",
        "days_left": days_left,
        "expired": days_left < 0,
        "expiring_soon": days_left <= 30,
    }


def status_filter_matches(device: Device, status_filter: str | None) -> bool:
    if not status_filter:
        return True
    target = status_filter.lower()
    device_status = normalized_status(device)
    if target == "critical":
        return device_status == "critical"
    if target == "revoked":
        return device_status == "revoked"
    if target == "other":
        return device_status == "other"
    return device_status == target


def build_status_chart(counts: dict[str, int]) -> tuple[str, list[dict[str, object]]]:
    total = sum(counts.values())
    legend = []
    for key, label in (
        ("online", "Online"),
        ("warning", "Warning"),
        ("critical", "Critical"),
        ("revoked", "Revoked"),
        ("other", "Other / Unknown"),
    ):
        count = counts.get(key, 0)
        percentage = (count / total) * 100 if total else 0
        legend.append(
            {
                "key": key,
                "label": label,
                "count": count,
                "percentage": round(percentage, 1),
                "color": STATUS_COLORS[key],
            }
        )
    if total <= 0:
        return "conic-gradient(#dfe7f3 0deg 360deg)", legend
    start = 0.0
    segments = []
    for item in legend:
        count = item["count"]
        if count <= 0:
            continue
        end = start + (count / total) * 360
        segments.append(f"{item['color']} {start:.2f}deg {end:.2f}deg")
        start = end
    return f"conic-gradient({', '.join(segments)})", legend


def device_supports_email_notifications() -> bool:
    return hasattr(Device, "email_notifications_enabled")


def _attention_key_part(value: object | None) -> str:
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime):
        normalized = (
            value.astimezone(timezone.utc)
            if value.tzinfo
            else value.replace(tzinfo=timezone.utc)
        )
        return normalized.isoformat()
    return str(value)


def attention_key(*parts: object | None) -> str:
    return ":".join(_attention_key_part(part) for part in parts)


def build_attention_item(
    key: str,
    severity: str,
    category: str,
    firewall: str | None,
    company: str | None,
    description: str,
    action: str,
    link: str,
) -> dict[str, str]:
    return {
        "key": key,
        "severity": severity,
        "category": category,
        "firewall": firewall or "-",
        "company": company or "-",
        "description": description,
        "action": action,
        "link": link,
    }


def _device_link(device: Device) -> str:
    return f"/devices/{device.id}"


def _status_sort_key(device: Device) -> tuple[int, str]:
    return (
        ATTENTION_SEVERITY_ORDER.get(
            "critical" if normalized_status(device) == "critical" else "warning",
            2,
        ),
        device.hostname.lower(),
    )


def _timestamp_value(value: object | None) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if value is not None and hasattr(value, "created_at"):
        candidate = getattr(value, "created_at")
        if isinstance(candidate, datetime):
            return candidate
    return None


def dashboard_revision_token(
    db: Session, user: User, filters: dict[str, str | None]
) -> str:
    devices = accessible_devices_for_user(db, user)
    selected_company_id = (filters.get("company_id") or "").strip()
    selected_status = (filters.get("status") or "").strip().lower()
    filtered_devices = [
        device
        for device in devices
        if (not selected_company_id or str(device.company_id) == selected_company_id)
        and status_filter_matches(device, selected_status or None)
    ]
    timestamps: list[datetime] = []
    for device in filtered_devices:
        if device.created_at is not None:
            timestamps.append(device.created_at)
        for value in (
            device.last_seen_at,
            device.backup_last_requested_at,
            device.backup_last_uploaded_at,
            device.firmware_checked_at,
            device.firmware_check_requested_at,
            device.health_acknowledged_at,
            device.revoked_at,
        ):
            if value is not None:
                timestamps.append(value)
    device_ids = [device.id for device in filtered_devices]
    if device_ids:
        latest_event = _timestamp_value(
            db.scalar(
                select(DeviceEvent.created_at)
                .where(DeviceEvent.device_id.in_(device_ids))
                .order_by(DeviceEvent.created_at.desc())
                .limit(1)
            )
        )
        if latest_event is not None:
            timestamps.append(latest_event)
        latest_audit = _timestamp_value(
            db.scalar(
                select(AuditLog.created_at)
                .where(AuditLog.device_id.in_(device_ids))
                .order_by(AuditLog.created_at.desc())
                .limit(1)
            )
        )
        if latest_audit is not None:
            timestamps.append(latest_audit)
    latest_saved_filter = _timestamp_value(
        db.scalar(
            select(UserDashboardFilter.created_at)
            .where(UserDashboardFilter.user_id == user.id)
            .order_by(UserDashboardFilter.created_at.desc())
            .limit(1)
        )
    )
    if latest_saved_filter is not None:
        timestamps.append(latest_saved_filter)
    latest_attention_acknowledgement = _timestamp_value(
        db.scalar(
            select(UserAttentionAcknowledgement.created_at)
            .where(UserAttentionAcknowledgement.user_id == user.id)
            .order_by(UserAttentionAcknowledgement.created_at.desc())
            .limit(1)
        )
    )
    if latest_attention_acknowledgement is not None:
        timestamps.append(latest_attention_acknowledgement)
    if not timestamps:
        return "0"
    latest = max(
        value.astimezone(timezone.utc)
        if value.tzinfo
        else value.replace(tzinfo=timezone.utc)
        for value in timestamps
    )
    return latest.isoformat()


def build_dashboard_context(
    db: Session, user: User, filters: dict[str, str | None]
) -> dict[str, object]:
    now = utc_now()
    integration_settings = db.get(IntegrationSettings, 1)
    email_ready = email_settings_configured(integration_settings)

    companies = accessible_companies_for_user(db, user)

    devices = accessible_devices_for_user(db, user)

    selected_company_id = (filters.get("company_id") or "").strip()
    selected_status = (filters.get("status") or "").strip().lower()

    filtered_devices = [
        device
        for device in devices
        if (not selected_company_id or str(device.company_id) == selected_company_id)
        and status_filter_matches(device, selected_status or None)
    ]

    visible_company_ids = {device.company_id for device in filtered_devices}
    filtered_companies = [
        company
        for company in companies
        if company.id in visible_company_ids or str(company.id) == selected_company_id
    ]

    status_counts = {"online": 0, "warning": 0, "critical": 0, "revoked": 0, "other": 0}
    for device in filtered_devices:
        status_counts[normalized_status(device)] += 1

    active_devices = [device for device in filtered_devices if active_device(device)]
    maintenance_devices = [
        device for device in active_devices if maintenance_window_active(device, now)
    ]
    warning_critical_devices = [
        device
        for device in active_devices
        if normalized_status(device) in {"warning", "critical"}
        and not maintenance_window_active(device, now)
    ]
    warning_critical_devices.sort(key=_status_sort_key)

    backup_rows = []
    backups_enabled_count = 0
    backups_disabled_count = 0
    backups_overdue_count = 0
    backups_never_count = 0
    last_successful_backup: Device | None = None
    for device in active_devices:
        backup_status = dashboard_backup_status(device, now)
        if device.backup_enabled:
            backups_enabled_count += 1
        else:
            backups_disabled_count += 1
        if backup_status["label"] == "Overdue":
            backups_overdue_count += 1
        if backup_status["label"] == "Never backed up":
            backups_never_count += 1
        last_uploaded_at = device.backup_last_uploaded_at
        if last_uploaded_at and (
            last_successful_backup is None
            or last_successful_backup.backup_last_uploaded_at is None
            or last_uploaded_at > last_successful_backup.backup_last_uploaded_at
        ):
            last_successful_backup = device
        if backup_status["label"] in {
            "Overdue",
            "Never backed up",
            "Pending",
            "Disabled",
        }:
            backup_rows.append(
                {
                    "device": device,
                    "company": device.company,
                    "backup_status": backup_status,
                    "retention": device.backup_retention_count,
                    "interval": interval_display(device),
                    "action_link": _device_link(device),
                }
            )

    firmware_summary = {
        "up_to_date": 0,
        "updates": 0,
        "upgrades": 0,
        "check_failed": 0,
        "unknown": 0,
    }
    firmware_attention_rows = []
    for device in active_devices:
        firmware = dashboard_firmware_status(device)
        status = (device.firmware_status or "unknown").lower()
        if status == "none":
            firmware_summary["up_to_date"] += 1
        elif status == "update":
            firmware_summary["updates"] += 1
        elif status == "upgrade":
            firmware_summary["upgrades"] += 1
        elif status == "error":
            firmware_summary["check_failed"] += 1
        else:
            firmware_summary["unknown"] += 1
        if (
            status in {"update", "upgrade", "error", "unknown"}
            or device.firmware_reboot_required
        ):
            firmware_attention_rows.append(
                {
                    "device": device,
                    "company": device.company,
                    "firmware": firmware,
                    "action_link": _device_link(device),
                }
            )

    license_rows = []
    license_summary = {
        "business": 0,
        "community": 0,
        "expired": 0,
        "within_30_days": 0,
        "within_7_days": 0,
    }
    for device in active_devices:
        license_status = dashboard_license_status(device, now)
        if license_status["label"] == "Business":
            license_summary["business"] += 1
        else:
            license_summary["community"] += 1
        if license_status["days_left"] is None:
            continue
        if license_status["expired"]:
            license_summary["expired"] += 1
        if license_status["expiring_soon"]:
            license_summary["within_30_days"] += 1
        days_left = license_status["days_left"]
        assert isinstance(days_left, int)
        if days_left <= 7:
            license_summary["within_7_days"] += 1
        if days_left <= 30:
            license_rows.append(
                {
                    "device": device,
                    "company": device.company,
                    "license_status": license_status,
                    "action_link": _device_link(device),
                }
            )
    license_rows.sort(
        key=lambda row: (
            0 if row["license_status"]["expired"] else 1,
            row["license_status"]["days_left"],
            row["device"].hostname.lower(),
        )
    )

    device_ids = [device.id for device in filtered_devices]
    events = []
    all_notification_failures = []
    event_failures_count = 0
    last_notification_sent = None
    if device_ids:
        events = db.scalars(
            select(DeviceEvent)
            .where(DeviceEvent.device_id.in_(device_ids))
            .order_by(DeviceEvent.created_at.desc())
            .limit(DASHBOARD_EVENT_LIMIT)
        ).all()
        all_notification_failures = db.scalars(
            select(DeviceEvent)
            .where(
                DeviceEvent.device_id.in_(device_ids),
                DeviceEvent.event_type == "email_notification_failed",
            )
            .order_by(DeviceEvent.created_at.desc())
        ).all()
        last_notification_sent = db.scalar(
            select(DeviceEvent)
            .where(
                DeviceEvent.device_id.in_(device_ids),
                DeviceEvent.event_type == "email_notification_sent",
            )
            .order_by(DeviceEvent.created_at.desc())
        )

    acknowledged_attention_keys = set(
        db.scalars(
            select(UserAttentionAcknowledgement.attention_key).where(
                UserAttentionAcknowledgement.user_id == user.id
            )
        ).all()
    )

    device_lookup = {device.id: device for device in devices}
    notification_failure_rows = []
    for event in all_notification_failures:
        failure_key = attention_key("notifications", "email-failure-event", event.id)
        if failure_key in acknowledged_attention_keys:
            continue
        device = device_lookup.get(event.device_id)
        if device is None:
            continue
        notification_failure_rows.append(
            {
                "event": event,
                "device": device,
                "company": device.company,
                "link": _device_link(device),
                "acknowledgement_key": failure_key,
            }
        )
    event_failures_count = len(notification_failure_rows)

    recent_events = []
    for event in events:
        device = device_lookup.get(event.device_id)
        if device is None:
            continue
        recent_events.append(
            {
                "event": event,
                "device": device,
                "company": device.company,
                "link": _device_link(device),
            }
        )

    health_events = [
        item for item in recent_events if item["event"].event_type == "health_check"
    ]
    recently_offline = []
    recovered_recently = []
    twenty_four_hours_ago = now - timedelta(hours=24)
    for item in health_events:
        if item["event"].created_at < twenty_four_hours_ago:
            continue
        message = (item["event"].message or "").lower()
        if (
            "unreachable" in message
            and active_device(item["device"])
            and not maintenance_window_active(item["device"], now)
        ):
            recently_offline.append(item)
        if "reachable" in message and normalized_status(item["device"]) == "online":
            recovered_recently.append(item)
    recently_offline = recently_offline[:HEALTH_LIST_LIMIT]
    recovered_recently = recovered_recently[:HEALTH_LIST_LIMIT]
    missed_checks = sorted(
        [
            device
            for device in active_devices
            if device.health_missed_checks > 0
            and not maintenance_window_active(device, now)
        ],
        key=lambda device: (-device.health_missed_checks, device.hostname.lower()),
    )[:HEALTH_LIST_LIMIT]

    attention_items = []
    for device in warning_critical_devices:
        status = normalized_status(device)
        attention_items.append(
            build_attention_item(
                attention_key("health", device.id, status),
                "critical" if status == "critical" else "warning",
                "Health",
                device.hostname,
                device.company.name if device.company else None,
                f"Firewall status is {status}.",
                "Review firewall details",
                _device_link(device),
            )
        )
    for row in backup_rows:
        if row["backup_status"]["label"] not in {"Overdue", "Never backed up"}:
            continue
        attention_items.append(
            build_attention_item(
                attention_key(
                    "backup",
                    row["device"].id,
                    row["backup_status"]["label"],
                    row["device"].backup_last_uploaded_at,
                ),
                "warning" if row["backup_status"]["label"] == "Overdue" else "info",
                "Backups",
                row["device"].hostname,
                row["company"].name if row["company"] else None,
                f"Backup status is {row['backup_status']['label'].lower()}.",
                "Review backup settings",
                row["action_link"],
            )
        )
    for row in firmware_attention_rows:
        label = row["firmware"]["label"]
        if label == "Check failed":
            severity = "warning"
        elif label == "Upgrade available":
            severity = "warning"
        elif label == "Updates available":
            severity = "info"
        else:
            severity = "info"
        attention_items.append(
            build_attention_item(
                attention_key(
                    "firmware",
                    row["device"].id,
                    row["device"].firmware_status,
                    row["device"].firmware_available_version,
                    row["device"].firmware_reboot_required,
                ),
                severity,
                "Firmware",
                row["device"].hostname,
                row["company"].name if row["company"] else None,
                f"Firmware state: {label}.",
                "Review firmware details",
                row["action_link"],
            )
        )
    for row in license_rows:
        days_left = row["license_status"]["days_left"]
        attention_items.append(
            build_attention_item(
                attention_key(
                    "license",
                    row["device"].id,
                    row["device"].license_expires_at,
                    row["license_status"]["expired"],
                ),
                "critical" if row["license_status"]["expired"] else "warning",
                "License",
                row["device"].hostname,
                row["company"].name if row["company"] else None,
                "License expired."
                if row["license_status"]["expired"]
                else f"License expires in {days_left} days.",
                "Review firewall details",
                row["action_link"],
            )
        )
    for device in active_devices:
        if device.last_seen_at is None:
            attention_items.append(
                build_attention_item(
                    attention_key("enrollment", device.id, "never-seen"),
                    "info",
                    "Enrollment",
                    device.hostname,
                    device.company.name if device.company else None,
                    "Firewall has never been seen after enrollment.",
                    "Review firewall details",
                    _device_link(device),
                )
            )
    notifications_supported = device_supports_email_notifications()
    enabled_notification_devices = []
    missing_recipient_count = 0
    if notifications_supported:
        for device in active_devices:
            if getattr(device, "email_notifications_enabled", False):
                enabled_notification_devices.append(device)
                if not getattr(device, "email_notification_recipient", None):
                    missing_recipient_count += 1
        if enabled_notification_devices and not email_ready:
            attention_items.append(
                build_attention_item(
                    attention_key(
                        "notifications",
                        "hub-email-settings-missing",
                        len(enabled_notification_devices),
                    ),
                    "warning",
                    "Notifications",
                    None,
                    None,
                    "Hub email settings are not configured while firewall notifications are enabled.",
                    "Open Hub email settings",
                    "/settings/email-settings",
                )
            )
    if event_failures_count:
        latest_failure_created_at = notification_failure_rows[0]["event"].created_at
        attention_items.append(
            build_attention_item(
                attention_key(
                    "notifications",
                    "email-failures",
                    event_failures_count,
                    latest_failure_created_at,
                ),
                "warning",
                "Notifications",
                None,
                None,
                f"{event_failures_count} email notification send failures were recorded.",
                "Review recent events",
                "#dashboard-recent-events-card",
            )
        )
    attention_items = [
        item
        for item in attention_items
        if item["key"] not in acknowledged_attention_keys
    ]
    attention_items.sort(
        key=lambda item: (
            ATTENTION_SEVERITY_ORDER[item["severity"]],
            item["category"],
            item["firewall"],
        )
    )

    company_overview = []
    for company in filtered_companies:
        company_devices = [
            device for device in filtered_devices if device.company_id == company.id
        ]
        if not company_devices and not selected_company_id:
            continue
        active_company_devices = [
            device for device in company_devices if active_device(device)
        ]
        company_overview.append(
            {
                "company": company,
                "firewalls": len(company_devices),
                "online": sum(
                    1
                    for device in company_devices
                    if normalized_status(device) == "online"
                ),
                "warning": sum(
                    1
                    for device in company_devices
                    if normalized_status(device) == "warning"
                ),
                "critical": sum(
                    1
                    for device in company_devices
                    if normalized_status(device) == "critical"
                ),
                "revoked": sum(
                    1
                    for device in company_devices
                    if normalized_status(device) == "revoked"
                ),
                "backups_overdue": sum(
                    1
                    for device in active_company_devices
                    if dashboard_backup_status(device, now)["label"] == "Overdue"
                ),
                "firmware_attention": sum(
                    1
                    for device in active_company_devices
                    if dashboard_firmware_status(device)["attention"]
                ),
                "licenses_expiring": sum(
                    1
                    for device in active_company_devices
                    if (
                        isinstance(
                            (
                                license_days_left := dashboard_license_status(
                                    device, now
                                )["days_left"]
                            ),
                            int,
                        )
                        and license_days_left <= 30
                    )
                ),
            }
        )

    last_notification_sent_row = None
    if last_notification_sent:
        notified_device = device_lookup.get(last_notification_sent.device_id)
        last_notification_sent_row = {
            "event": last_notification_sent,
            "device": notified_device,
            "company": notified_device.company if notified_device else None,
        }

    notification_health = {
        "email_settings_configured": email_ready,
        "supported": notifications_supported,
        "enabled_count": len(enabled_notification_devices),
        "missing_recipient_count": missing_recipient_count,
        "last_notification_sent": last_notification_sent_row,
        "failure_count": event_failures_count,
        "failure_rows": notification_failure_rows,
    }

    chart_style, chart_legend = build_status_chart(status_counts)
    device_filter_options = {
        "hostnames": sorted({device.hostname for device in devices}),
        "companies": [company.name for company in companies],
        "statuses": ["online", "warning", "critical", "revoked", "other"],
    }
    return {
        "filters": {
            "company_id": selected_company_id,
            "status": selected_status,
        },
        "filter_companies": companies,
        "summary": {
            "total_firewalls": len(filtered_devices),
            "online": status_counts["online"],
            "warning": status_counts["warning"],
            "critical": status_counts["critical"],
            "revoked": status_counts["revoked"],
            "backups_overdue": backups_overdue_count,
            "firmware_updates_available": firmware_summary["updates"],
            "firmware_upgrades_available": firmware_summary["upgrades"],
            "firmware_check_failures": firmware_summary["check_failed"],
            "licenses_expiring_soon": license_summary["within_30_days"],
            "email_notification_failures": event_failures_count,
        },
        "status_chart_style": chart_style,
        "status_chart_legend": chart_legend,
        "health_overview": {
            "recently_offline": recently_offline,
            "most_missed": missed_checks,
            "recovered_recently": recovered_recently,
            "warning_critical": warning_critical_devices[:10],
        },
        "backup_summary": {
            "enabled": backups_enabled_count,
            "disabled": backups_disabled_count,
            "overdue": backups_overdue_count,
            "never": backups_never_count,
            "last_successful_backup": last_successful_backup,
        },
        "backup_rows": backup_rows,
        "firmware_summary": firmware_summary,
        "firmware_attention_rows": firmware_attention_rows,
        "recent_events": recent_events,
        "attention_items": attention_items,
        "company_overview": company_overview,
        "license_summary": license_summary,
        "license_rows": license_rows,
        "notification_health": notification_health,
        "email_settings_configured": email_ready,
        "visible_device_count": len(filtered_devices),
        "filtered_devices": filtered_devices,
        "maintenance_device_count": len(maintenance_devices),
        "device_filter_options": device_filter_options,
    }

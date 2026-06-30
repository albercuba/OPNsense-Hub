from __future__ import annotations

import asyncio
import io
import json
import logging
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..hardening import (
    MAX_LOG_RETENTION_DELETE_BATCH_SIZE,
    MAX_LOG_RETENTION_SWEEP_INTERVAL_HOURS,
)
from ..models import AuditLog, DeviceEvent
from ..security import utc_now
from ..web import app_timezone_info, settings
from .backup_service import encrypt_backup_payload, serialize_model_row

logger = logging.getLogger(__name__)
LOG_ARCHIVE_FORMAT_VERSION = 1


@dataclass(frozen=True)
class LogRetentionConfig:
    enabled: bool
    run_on_startup: bool
    audit_log_retention_days: int
    device_event_retention_days: int
    sweep_interval_hours: int
    delete_batch_size: int
    audit_log_min_retention_days: int
    device_event_min_retention_days: int


@dataclass(frozen=True)
class TableRetentionSummary:
    total_rows: int
    oldest_row_at: datetime | None
    rows_older_than_cutoff: int
    cutoff_at: datetime


@dataclass(frozen=True)
class LogRetentionResult:
    skipped: bool
    reason: str | None
    audit_logs_deleted: int
    device_events_deleted: int
    audit_logs_cutoff_at: datetime
    device_events_cutoff_at: datetime


@dataclass(frozen=True)
class LogArchiveSelection:
    cutoff_at: datetime
    include_audit_logs: bool
    include_device_events: bool


def _is_production() -> bool:
    return settings.app_env.strip().lower() == "production"


def _clamp(value: int, lower: int, upper: int) -> int:
    return max(lower, min(value, upper))


def log_retention_config() -> LogRetentionConfig:
    if _is_production():
        audit_days = settings.audit_log_retention_days
        device_days = settings.device_event_retention_days
        sweep_interval_hours = settings.log_retention_sweep_interval_hours
        delete_batch_size = settings.log_retention_delete_batch_size
    else:
        audit_days = max(
            settings.audit_log_retention_days, settings.audit_log_min_retention_days
        )
        device_days = max(
            settings.device_event_retention_days,
            settings.device_event_min_retention_days,
        )
        sweep_interval_hours = _clamp(
            settings.log_retention_sweep_interval_hours,
            1,
            MAX_LOG_RETENTION_SWEEP_INTERVAL_HOURS,
        )
        delete_batch_size = _clamp(
            settings.log_retention_delete_batch_size,
            1,
            MAX_LOG_RETENTION_DELETE_BATCH_SIZE,
        )
    return LogRetentionConfig(
        enabled=settings.log_retention_enabled,
        run_on_startup=settings.log_retention_run_on_startup,
        audit_log_retention_days=audit_days,
        device_event_retention_days=device_days,
        sweep_interval_hours=sweep_interval_hours,
        delete_batch_size=delete_batch_size,
        audit_log_min_retention_days=settings.audit_log_min_retention_days,
        device_event_min_retention_days=settings.device_event_min_retention_days,
    )


def log_retention_cutoffs(
    now: datetime | None = None,
    *,
    config: LogRetentionConfig | None = None,
) -> dict[str, datetime]:
    current_time = now or utc_now()
    active_config = config or log_retention_config()
    return {
        "audit_logs": current_time
        - timedelta(days=active_config.audit_log_retention_days),
        "device_events": current_time
        - timedelta(days=active_config.device_event_retention_days),
    }


def _table_retention_summary(
    db: Session,
    model: type[AuditLog] | type[DeviceEvent],
    cutoff_at: datetime,
) -> TableRetentionSummary:
    total_rows = int(db.scalar(select(func.count()).select_from(model)) or 0)
    oldest_row_at = db.scalar(select(func.min(model.created_at)))
    rows_older_than_cutoff = int(
        db.scalar(
            select(func.count()).select_from(model).where(model.created_at < cutoff_at)
        )
        or 0
    )
    return TableRetentionSummary(
        total_rows=total_rows,
        oldest_row_at=oldest_row_at,
        rows_older_than_cutoff=rows_older_than_cutoff,
        cutoff_at=cutoff_at,
    )


def get_log_retention_summary(
    db: Session, now: datetime | None = None
) -> dict[str, Any]:
    config = log_retention_config()
    cutoffs = log_retention_cutoffs(now, config=config)
    return {
        "config": config,
        "audit_logs": _table_retention_summary(db, AuditLog, cutoffs["audit_logs"]),
        "device_events": _table_retention_summary(
            db, DeviceEvent, cutoffs["device_events"]
        ),
    }


def _delete_rows_in_batches(
    db: Session,
    model: type[AuditLog] | type[DeviceEvent],
    cutoff_at: datetime,
    batch_size: int,
) -> int:
    deleted_rows = 0
    while True:
        ids = list(
            db.scalars(
                select(model.id)
                .where(model.created_at < cutoff_at)
                .order_by(model.created_at.asc())
                .limit(batch_size)
            )
        )
        if not ids:
            return deleted_rows
        db.execute(delete(model).where(model.id.in_(ids)))
        db.commit()
        deleted_rows += len(ids)
        if len(ids) < batch_size:
            return deleted_rows


def run_log_retention_once(
    db: Session, now: datetime | None = None
) -> LogRetentionResult:
    config = log_retention_config()
    cutoffs = log_retention_cutoffs(now, config=config)
    if not config.enabled:
        return LogRetentionResult(
            skipped=True,
            reason="disabled",
            audit_logs_deleted=0,
            device_events_deleted=0,
            audit_logs_cutoff_at=cutoffs["audit_logs"],
            device_events_cutoff_at=cutoffs["device_events"],
        )
    device_events_deleted = _delete_rows_in_batches(
        db,
        DeviceEvent,
        cutoffs["device_events"],
        config.delete_batch_size,
    )
    audit_logs_deleted = _delete_rows_in_batches(
        db,
        AuditLog,
        cutoffs["audit_logs"],
        config.delete_batch_size,
    )
    logger.info(
        "Log retention sweep completed: device_events_deleted=%s audit_logs_deleted=%s device_events_cutoff=%s audit_logs_cutoff=%s",
        device_events_deleted,
        audit_logs_deleted,
        cutoffs["device_events"].isoformat(),
        cutoffs["audit_logs"].isoformat(),
    )
    return LogRetentionResult(
        skipped=False,
        reason=None,
        audit_logs_deleted=audit_logs_deleted,
        device_events_deleted=device_events_deleted,
        audit_logs_cutoff_at=cutoffs["audit_logs"],
        device_events_cutoff_at=cutoffs["device_events"],
    )


def _run_log_retention_in_session() -> None:
    with SessionLocal() as db:
        run_log_retention_once(db)


async def log_retention_loop() -> None:
    config = log_retention_config()
    if config.run_on_startup:
        await asyncio.sleep(1)
        try:
            await asyncio.to_thread(_run_log_retention_in_session)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Initial log retention sweep failed")
    while True:
        config = log_retention_config()
        await asyncio.sleep(config.sweep_interval_hours * 3600)
        try:
            await asyncio.to_thread(_run_log_retention_in_session)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Scheduled log retention sweep failed")


def parse_log_archive_cutoff(value: str) -> datetime:
    raw_value = value.strip()
    if not raw_value:
        raise HTTPException(
            status_code=400, detail="archive cutoff timestamp is required"
        )
    try:
        parsed = datetime.fromisoformat(raw_value)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="archive cutoff timestamp must be a valid date or date-time",
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=app_timezone_info())
    return parsed.astimezone(timezone.utc)


def create_log_archive_selection(
    cutoff_value: str,
    *,
    include_audit_logs: bool,
    include_device_events: bool,
) -> LogArchiveSelection:
    if not include_audit_logs and not include_device_events:
        raise HTTPException(
            status_code=400,
            detail="select audit logs, device events, or both before exporting",
        )
    return LogArchiveSelection(
        cutoff_at=parse_log_archive_cutoff(cutoff_value),
        include_audit_logs=include_audit_logs,
        include_device_events=include_device_events,
    )


def _jsonl_bytes(rows: list[dict[str, Any]]) -> bytes:
    return "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode(
        "utf-8"
    )


def _archive_manifest(
    selection: LogArchiveSelection,
    *,
    audit_log_count: int,
    device_event_count: int,
) -> dict[str, Any]:
    included_tables: list[str] = []
    if selection.include_audit_logs:
        included_tables.append("audit_logs")
    if selection.include_device_events:
        included_tables.append("device_events")
    return {
        "format_version": LOG_ARCHIVE_FORMAT_VERSION,
        "created_at": utc_now().isoformat(),
        "selected_cutoff_at": selection.cutoff_at.isoformat(),
        "included_tables": included_tables,
        "row_counts": {
            "audit_logs": audit_log_count,
            "device_events": device_event_count,
        },
        "app_name": settings.app_name,
        "app_version": None,
    }


def export_log_archive(
    db: Session,
    selection: LogArchiveSelection,
    *,
    passphrase: str | None = None,
) -> tuple[bytes, str, str, dict[str, Any]]:
    audit_logs_rows: list[dict[str, Any]] = []
    device_event_rows: list[dict[str, Any]] = []
    if selection.include_audit_logs:
        audit_logs_rows = [
            serialize_model_row(row)
            for row in db.scalars(
                select(AuditLog)
                .where(AuditLog.created_at <= selection.cutoff_at)
                .order_by(AuditLog.created_at.asc())
            ).all()
        ]
    if selection.include_device_events:
        device_event_rows = [
            serialize_model_row(row)
            for row in db.scalars(
                select(DeviceEvent)
                .where(DeviceEvent.created_at <= selection.cutoff_at)
                .order_by(DeviceEvent.created_at.asc())
            ).all()
        ]
    manifest = _archive_manifest(
        selection,
        audit_log_count=len(audit_logs_rows),
        device_event_count=len(device_event_rows),
    )
    archive_name = f"opnsense-hub-log-archive-{utc_now().strftime('%Y%m%d-%H%M%S')}"
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "manifest.json", json.dumps(manifest, indent=2, sort_keys=True)
        )
        if selection.include_audit_logs:
            archive.writestr("audit_logs.jsonl", _jsonl_bytes(audit_logs_rows))
        if selection.include_device_events:
            archive.writestr("device_events.jsonl", _jsonl_bytes(device_event_rows))
    raw_archive = content.getvalue()
    if passphrase and passphrase.strip():
        return (
            encrypt_backup_payload(raw_archive, passphrase.strip()),
            archive_name + ".opnhub",
            "application/octet-stream",
            manifest,
        )
    return raw_archive, archive_name + ".zip", "application/zip", manifest

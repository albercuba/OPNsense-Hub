import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    desc,
)
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        String(320), unique=True, nullable=False, index=True
    )
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    first_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    auth_provider: Mapped[str | None] = mapped_column(String(30), nullable=True)
    role: Mapped[str] = mapped_column(String(30), default="user", nullable=False)
    mfa_enabled: Mapped[bool] = mapped_column(default=False, nullable=False)
    mfa_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False
    )

    companies: Mapped[list["CompanyUser"]] = relationship(back_populates="user")
    saved_dashboard_filters: Mapped[list["UserDashboardFilter"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class SessionToken(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped[User] = relationship()


class IntegrationSettings(Base):
    __tablename__ = "integration_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    smtp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    smtp_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    smtp_username: Mapped[str | None] = mapped_column(String(320), nullable=True)
    smtp_password: Mapped[str | None] = mapped_column(Text, nullable=True)
    smtp_from: Mapped[str | None] = mapped_column(String(320), nullable=True)
    graph_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    graph_tenant_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    graph_client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    graph_client_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    graph_sender: Mapped[str | None] = mapped_column(String(320), nullable=True)
    microsoft_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    microsoft_tenant_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    microsoft_client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    microsoft_client_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    microsoft_audience: Mapped[str | None] = mapped_column(String(255), nullable=True)
    microsoft_authority: Mapped[str | None] = mapped_column(String(255), nullable=True)
    microsoft_admin_group_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    microsoft_admin_group_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    microsoft_user_group_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    microsoft_user_group_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    ad_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ad_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ad_base_dn: Mapped[str | None] = mapped_column(String(500), nullable=True)
    ad_bind_dn: Mapped[str | None] = mapped_column(String(500), nullable=True)
    admin_login_allowlist: Mapped[str | None] = mapped_column(Text, nullable=True)
    branding_logo_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    notify_on_offline: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    notify_on_backup_overdue: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    notify_on_license_expiring: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    notify_on_firmware_available: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    notify_on_repeated_auth_failures: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False
    )


class Company(Base):
    __tablename__ = "companies"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False
    )

    users: Mapped[list["CompanyUser"]] = relationship(
        back_populates="company", cascade="all, delete-orphan"
    )
    devices: Mapped[list["Device"]] = relationship(back_populates="company")


class CompanyUser(Base):
    __tablename__ = "company_users"
    __table_args__ = (
        UniqueConstraint("company_id", "user_id", name="uq_company_user"),
    )

    company_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("companies.id", ondelete="CASCADE"),
        primary_key=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False
    )

    company: Mapped[Company] = relationship(back_populates="users")
    user: Mapped[User] = relationship(back_populates="companies")


class UserDashboardFilter(Base):
    __tablename__ = "user_dashboard_filters"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    company_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("companies.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False
    )

    user: Mapped[User] = relationship(back_populates="saved_dashboard_filters")
    company: Mapped[Company | None] = relationship()


class EnrollmentCode(Base):
    __tablename__ = "enrollment_codes"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    company_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("companies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    code_hash: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False
    )


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    company_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("companies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    opnsense_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    plugin_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    license_type: Mapped[str | None] = mapped_column(String(30), nullable=True)
    license_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    wg_public_key: Mapped[str] = mapped_column(String(80), nullable=False)
    wg_tunnel_ip: Mapped[str] = mapped_column(INET, nullable=False, unique=True)
    device_token_hash: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="pending", nullable=False)
    health_missed_checks: Mapped[int] = mapped_column(default=0, nullable=False)
    health_success_checks: Mapped[int] = mapped_column(default=0, nullable=False)
    firmware_status: Mapped[str] = mapped_column(
        String(30), default="unknown", nullable=False
    )
    firmware_update_available: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    firmware_update_type: Mapped[str | None] = mapped_column(String(30), nullable=True)
    firmware_current_version: Mapped[str | None] = mapped_column(
        String(80), nullable=True
    )
    firmware_available_version: Mapped[str | None] = mapped_column(
        String(80), nullable=True
    )
    firmware_update_count: Mapped[int] = mapped_column(default=0, nullable=False)
    firmware_reboot_required: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    firmware_status_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    firmware_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    firmware_check_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    firmware_check_request_reason: Mapped[str | None] = mapped_column(
        String(30), nullable=True
    )
    backup_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    backup_retention_count: Mapped[int] = mapped_column(
        Integer, default=3, nullable=False
    )
    backup_interval_value: Mapped[int] = mapped_column(
        Integer, default=24, nullable=False
    )
    backup_interval_unit: Mapped[str] = mapped_column(
        String(20), default="hours", nullable=False
    )
    backup_interval_hours: Mapped[int] = mapped_column(
        Integer, default=24, nullable=False
    )
    backup_last_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    backup_last_uploaded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    email_notifications_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    email_notification_recipient: Mapped[str | None] = mapped_column(
        String(320), nullable=True
    )
    email_notify_on_warning: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    email_notify_on_critical: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    email_notify_on_backup_overdue: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    email_notify_on_license_expiring: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    email_notify_on_firmware_available: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    email_last_notified_status: Mapped[str | None] = mapped_column(
        String(30), nullable=True
    )
    email_last_notified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    backup_overdue_notified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    license_expiring_notified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    firmware_available_notified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    runbook_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    runbook_owner: Mapped[str | None] = mapped_column(String(200), nullable=True)
    runbook_contact: Mapped[str | None] = mapped_column(String(320), nullable=True)
    runbook_site: Mapped[str | None] = mapped_column(String(200), nullable=True)
    support_contract_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    escalation_hint: Mapped[str | None] = mapped_column(Text, nullable=True)
    maintenance_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    health_acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    health_acknowledged_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    health_acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False
    )

    company: Mapped[Company] = relationship(back_populates="devices")
    backups: Mapped[list["DeviceBackup"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )


class DeviceBackup(Base):
    __tablename__ = "device_backups"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False
    )

    device: Mapped[Device] = relationship(back_populates="backups")


class DeviceEvent(Base):
    __tablename__ = "device_events"
    __table_args__ = (
        Index("idx_device_events_created_at", "created_at"),
        Index(
            "idx_device_events_device_created_at",
            "device_id",
            desc("created_at"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("idx_audit_logs_created_at", "created_at"),
        Index("idx_audit_logs_action_created_at", "action", desc("created_at")),
        Index(
            "idx_audit_logs_device_created_at",
            "device_id",
            desc("created_at"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    company_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("companies.id", ondelete="SET NULL"),
        nullable=True,
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False
    )

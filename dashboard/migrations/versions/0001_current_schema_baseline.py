"""Current schema baseline

Revision ID: 0001_current_schema_baseline
Revises: None
Create Date: 2026-06-29 00:00:00
"""

from __future__ import annotations

from importlib import import_module

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

op = import_module("alembic.op")

# revision identifiers, used by Alembic.
revision = "0001_current_schema_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("first_name", sa.String(length=120), nullable=True),
        sa.Column("last_name", sa.String(length=120), nullable=True),
        sa.Column("role", sa.String(length=30), nullable=False),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_sessions_token_hash", "sessions", ["token_hash"], unique=True)

    op.create_table(
        "integration_settings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("smtp_enabled", sa.Boolean(), nullable=False),
        sa.Column("smtp_host", sa.String(length=255), nullable=True),
        sa.Column("smtp_port", sa.Integer(), nullable=True),
        sa.Column("smtp_username", sa.String(length=320), nullable=True),
        sa.Column("smtp_password", sa.Text(), nullable=True),
        sa.Column("smtp_from", sa.String(length=320), nullable=True),
        sa.Column("graph_enabled", sa.Boolean(), nullable=False),
        sa.Column("graph_tenant_id", sa.String(length=255), nullable=True),
        sa.Column("graph_client_id", sa.String(length=255), nullable=True),
        sa.Column("graph_client_secret", sa.Text(), nullable=True),
        sa.Column("graph_sender", sa.String(length=320), nullable=True),
        sa.Column("microsoft_enabled", sa.Boolean(), nullable=False),
        sa.Column("microsoft_tenant_id", sa.String(length=255), nullable=True),
        sa.Column("microsoft_client_id", sa.String(length=255), nullable=True),
        sa.Column("microsoft_client_secret", sa.Text(), nullable=True),
        sa.Column("microsoft_audience", sa.String(length=255), nullable=True),
        sa.Column("microsoft_authority", sa.String(length=255), nullable=True),
        sa.Column("microsoft_admin_group_name", sa.String(length=255), nullable=True),
        sa.Column("microsoft_admin_group_id", sa.String(length=255), nullable=True),
        sa.Column("microsoft_user_group_name", sa.String(length=255), nullable=True),
        sa.Column("microsoft_user_group_id", sa.String(length=255), nullable=True),
        sa.Column("ad_enabled", sa.Boolean(), nullable=False),
        sa.Column("ad_host", sa.String(length=255), nullable=True),
        sa.Column("ad_base_dn", sa.String(length=500), nullable=True),
        sa.Column("ad_bind_dn", sa.String(length=500), nullable=True),
        sa.Column("branding_logo_url", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "companies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "company_users",
        sa.Column(
            "company_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("companies.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("company_id", "user_id", name="uq_company_user"),
    )

    op.create_table(
        "enrollment_codes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "company_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("companies.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("code_hash", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_enrollment_codes_company_id", "enrollment_codes", ["company_id"]
    )

    op.create_table(
        "devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "company_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("companies.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=200), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("opnsense_version", sa.String(length=80), nullable=True),
        sa.Column("plugin_version", sa.String(length=80), nullable=True),
        sa.Column("license_type", sa.String(length=30), nullable=True),
        sa.Column("license_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("wg_public_key", sa.String(length=80), nullable=False),
        sa.Column("wg_tunnel_ip", postgresql.INET(), nullable=False),
        sa.Column("device_token_hash", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("health_missed_checks", sa.Integer(), nullable=False),
        sa.Column("health_success_checks", sa.Integer(), nullable=False),
        sa.Column("firmware_status", sa.String(length=30), nullable=False),
        sa.Column("firmware_update_available", sa.Boolean(), nullable=False),
        sa.Column("firmware_update_type", sa.String(length=30), nullable=True),
        sa.Column("firmware_current_version", sa.String(length=80), nullable=True),
        sa.Column("firmware_available_version", sa.String(length=80), nullable=True),
        sa.Column("firmware_update_count", sa.Integer(), nullable=False),
        sa.Column("firmware_reboot_required", sa.Boolean(), nullable=False),
        sa.Column("firmware_status_message", sa.Text(), nullable=True),
        sa.Column("firmware_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("firmware_check_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("firmware_check_request_reason", sa.String(length=30), nullable=True),
        sa.Column("backup_enabled", sa.Boolean(), nullable=False),
        sa.Column("backup_retention_count", sa.Integer(), nullable=False),
        sa.Column("backup_interval_value", sa.Integer(), nullable=False),
        sa.Column("backup_interval_unit", sa.String(length=20), nullable=False),
        sa.Column("backup_interval_hours", sa.Integer(), nullable=False),
        sa.Column("backup_last_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("backup_last_uploaded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("email_notifications_enabled", sa.Boolean(), nullable=False),
        sa.Column("email_notification_recipient", sa.String(length=320), nullable=True),
        sa.Column("email_notify_on_warning", sa.Boolean(), nullable=False),
        sa.Column("email_notify_on_critical", sa.Boolean(), nullable=False),
        sa.Column("email_last_notified_status", sa.String(length=30), nullable=True),
        sa.Column("email_last_notified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("wg_tunnel_ip", name="uq_devices_wg_tunnel_ip"),
    )
    op.create_index("ix_devices_company_id", "devices", ["company_id"])

    op.create_table(
        "device_backups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "device_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_device_backups_device_id", "device_backups", ["device_id"])

    op.create_table(
        "device_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "device_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_device_events_device_id", "device_events", ["device_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("company_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="SET NULL"),
    )


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_index("ix_device_events_device_id", table_name="device_events")
    op.drop_table("device_events")
    op.drop_index("ix_device_backups_device_id", table_name="device_backups")
    op.drop_table("device_backups")
    op.drop_index("ix_devices_company_id", table_name="devices")
    op.drop_table("devices")
    op.drop_index("ix_enrollment_codes_company_id", table_name="enrollment_codes")
    op.drop_table("enrollment_codes")
    op.drop_table("company_users")
    op.drop_table("companies")
    op.drop_table("integration_settings")
    op.drop_index("ix_sessions_token_hash", table_name="sessions")
    op.drop_table("sessions")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")

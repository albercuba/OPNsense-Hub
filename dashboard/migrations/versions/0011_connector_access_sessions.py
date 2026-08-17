"""Permit connector access sessions

Revision ID: 0011_connector_access_sessions
Revises: 0010_device_proxy_sessions
Create Date: 2026-08-16 00:00:00
"""

from __future__ import annotations

from importlib import import_module

op = import_module("alembic.op")

revision = "0011_connector_access_sessions"
down_revision = "0010_device_proxy_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE device_proxy_sessions "
        "DROP CONSTRAINT ck_device_proxy_sessions_phase"
    )
    op.execute(
        "ALTER TABLE device_proxy_sessions "
        "ADD CONSTRAINT ck_device_proxy_sessions_phase "
        "CHECK (phase IN ('grant', 'session', 'connector'))"
    )
    op.execute(
        "ALTER TABLE device_proxy_sessions "
        "ADD COLUMN dashboard_session_id uuid NULL "
        "REFERENCES sessions(id) ON DELETE CASCADE"
    )
    op.execute(
        "CREATE INDEX idx_device_proxy_sessions_dashboard_session_id "
        "ON device_proxy_sessions(dashboard_session_id)"
    )


def downgrade() -> None:
    op.execute("DELETE FROM device_proxy_sessions WHERE phase = 'connector'")
    op.execute("DROP INDEX idx_device_proxy_sessions_dashboard_session_id")
    op.execute(
        "ALTER TABLE device_proxy_sessions DROP COLUMN dashboard_session_id"
    )
    op.execute(
        "ALTER TABLE device_proxy_sessions "
        "DROP CONSTRAINT ck_device_proxy_sessions_phase"
    )
    op.execute(
        "ALTER TABLE device_proxy_sessions "
        "ADD CONSTRAINT ck_device_proxy_sessions_phase "
        "CHECK (phase IN ('grant', 'session'))"
    )

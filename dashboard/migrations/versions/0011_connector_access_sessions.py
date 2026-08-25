"""Permit connector access sessions

Revision ID: 0011_connector_access_sessions
Revises: 0010_device_proxy_sessions
Create Date: 2026-08-16 00:00:00
"""

from __future__ import annotations

from importlib import import_module

import sqlalchemy as sa

op = import_module("alembic.op")
context = import_module("alembic.context")

revision = "0011_connector_access_sessions"
down_revision = "0010_device_proxy_sessions"
branch_labels = None
depends_on = None

_PHASE_CONSTRAINT = "ck_device_proxy_sessions_phase"
_SESSION_INDEX = "idx_device_proxy_sessions_dashboard_session_id"


def _inspector():
    return sa.inspect(op.get_bind())


def _phase_constraint() -> dict[str, object] | None:
    for constraint in _inspector().get_check_constraints("device_proxy_sessions"):
        if constraint.get("name") == _PHASE_CONSTRAINT:
            return constraint
    return None


def upgrade() -> None:
    if context.is_offline_mode():
        op.drop_constraint(_PHASE_CONSTRAINT, "device_proxy_sessions", type_="check")
        op.create_check_constraint(
            _PHASE_CONSTRAINT,
            "device_proxy_sessions",
            "phase IN ('grant', 'session', 'connector')",
        )
        op.add_column(
            "device_proxy_sessions",
            sa.Column(
                "dashboard_session_id",
                sa.Uuid(),
                sa.ForeignKey("sessions.id", ondelete="CASCADE"),
                nullable=True,
            ),
        )
        op.create_index(
            _SESSION_INDEX,
            "device_proxy_sessions",
            ["dashboard_session_id"],
        )
        return

    phase_constraint = _phase_constraint()
    phase_sql = str((phase_constraint or {}).get("sqltext") or "").lower()
    if "connector" not in phase_sql:
        if phase_constraint is not None:
            op.drop_constraint(
                _PHASE_CONSTRAINT, "device_proxy_sessions", type_="check"
            )
        op.create_check_constraint(
            _PHASE_CONSTRAINT,
            "device_proxy_sessions",
            "phase IN ('grant', 'session', 'connector')",
        )

    columns = {
        column["name"]
        for column in _inspector().get_columns("device_proxy_sessions")
    }
    if "dashboard_session_id" not in columns:
        op.add_column(
            "device_proxy_sessions",
            sa.Column(
                "dashboard_session_id",
                sa.Uuid(),
                sa.ForeignKey("sessions.id", ondelete="CASCADE"),
                nullable=True,
            ),
        )
    indexes = {
        index["name"]
        for index in _inspector().get_indexes("device_proxy_sessions")
    }
    if _SESSION_INDEX not in indexes:
        op.create_index(
            _SESSION_INDEX,
            "device_proxy_sessions",
            ["dashboard_session_id"],
        )


def downgrade() -> None:
    op.execute("DELETE FROM device_proxy_sessions WHERE phase = 'connector'")
    if context.is_offline_mode():
        op.drop_index(_SESSION_INDEX, table_name="device_proxy_sessions")
        op.drop_column("device_proxy_sessions", "dashboard_session_id")
        op.drop_constraint(_PHASE_CONSTRAINT, "device_proxy_sessions", type_="check")
        op.create_check_constraint(
            _PHASE_CONSTRAINT,
            "device_proxy_sessions",
            "phase IN ('grant', 'session')",
        )
        return

    indexes = {
        index["name"]
        for index in _inspector().get_indexes("device_proxy_sessions")
    }
    if _SESSION_INDEX in indexes:
        op.drop_index(_SESSION_INDEX, table_name="device_proxy_sessions")
    columns = {
        column["name"]
        for column in _inspector().get_columns("device_proxy_sessions")
    }
    if "dashboard_session_id" in columns:
        op.drop_column("device_proxy_sessions", "dashboard_session_id")

    phase_constraint = _phase_constraint()
    phase_sql = str((phase_constraint or {}).get("sqltext") or "").lower()
    if "connector" in phase_sql or phase_constraint is None:
        if phase_constraint is not None:
            op.drop_constraint(
                _PHASE_CONSTRAINT, "device_proxy_sessions", type_="check"
            )
        op.create_check_constraint(
            _PHASE_CONSTRAINT,
            "device_proxy_sessions",
            "phase IN ('grant', 'session')",
        )

"""Add device proxy sessions

Revision ID: 0010_device_proxy_sessions
Revises: 0009_attention_acks
Create Date: 2026-08-16 00:00:00
"""

from __future__ import annotations

from importlib import import_module

op = import_module("alembic.op")

revision = "0010_device_proxy_sessions"
down_revision = "0009_attention_acks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS device_proxy_sessions (
          id uuid PRIMARY KEY,
          user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
          token_hash varchar(64) NOT NULL,
          phase varchar(16) NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          expires_at timestamptz NOT NULL,
          consumed_at timestamptz NULL,
          CONSTRAINT uq_device_proxy_sessions_token_hash UNIQUE (token_hash),
          CONSTRAINT ck_device_proxy_sessions_phase CHECK (phase IN ('grant', 'session'))
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_device_proxy_sessions_expires_at ON device_proxy_sessions(expires_at)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_device_proxy_sessions_device_id ON device_proxy_sessions(device_id)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS device_proxy_sessions")

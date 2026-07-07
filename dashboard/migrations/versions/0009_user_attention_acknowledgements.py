"""Add user dashboard attention acknowledgements

Revision ID: 0009_user_attention_acknowledgements
Revises: 0008_device_email_rule_overrides
Create Date: 2026-07-07 00:00:05
"""

from __future__ import annotations

from importlib import import_module

op = import_module("alembic.op")

revision = "0009_user_attention_acknowledgements"
down_revision = "0008_device_email_rule_overrides"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS user_attention_acknowledgements (
          id uuid PRIMARY KEY,
          user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          attention_key text NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now(),
          CONSTRAINT uq_user_attention_ack UNIQUE (user_id, attention_key)
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_attention_ack_unique ON user_attention_acknowledgements(user_id, attention_key)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS user_attention_acknowledgements")

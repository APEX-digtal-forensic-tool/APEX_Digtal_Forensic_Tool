"""Add current_refresh_jti column to user_sessions for token rotation tracking.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "user_sessions",
        sa.Column("current_refresh_jti", sa.String(36), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("user_sessions", "current_refresh_jti")

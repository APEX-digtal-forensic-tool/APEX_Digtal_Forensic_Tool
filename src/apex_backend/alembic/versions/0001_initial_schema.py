"""Initial schema — users, case_tenancy, user_sessions, confirmation_grants.

Revision ID: 0001
Revises:
Create Date: 2026-09-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("email", "tenant_id", name="uq_users_email_tenant"),
    )

    op.create_table(
        "case_tenancy",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "actor_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("case_id", sa.String(255), nullable=False),
        sa.Column("role", sa.String(50), nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("actor_id", "case_id", name="uq_case_tenancy_actor_case"),
    )
    op.create_index("ix_case_tenancy_actor_id", "case_tenancy", ["actor_id"])

    op.create_table(
        "user_sessions",
        sa.Column("session_id", sa.String(36), primary_key=True),
        sa.Column(
            "actor_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_user_sessions_actor_id", "user_sessions", ["actor_id"])

    op.create_table(
        "confirmation_grants",
        sa.Column("grant_id", sa.String(36), primary_key=True),
        sa.Column("actor_id", sa.String(36), nullable=False),
        sa.Column("session_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(255), nullable=False),
        sa.Column("tool_name", sa.String(255), nullable=False),
        sa.Column("request_fingerprint", sa.String(255), nullable=False),
        sa.Column("target_ids", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_uses", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("uses_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index(
        "ix_confirmation_grants_session_id", "confirmation_grants", ["session_id"]
    )


def downgrade() -> None:
    op.drop_table("confirmation_grants")
    op.drop_table("user_sessions")
    op.drop_table("case_tenancy")
    op.drop_table("users")

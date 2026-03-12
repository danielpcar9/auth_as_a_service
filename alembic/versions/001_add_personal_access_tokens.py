"""Add personal_access_tokens table

Revision ID: 001_add_personal_access_tokens
Revises:
Create Date: 2026-03-11
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision: str = "001_add_personal_access_tokens"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "personal_access_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False, server_default="default"),
        sa.Column("token", sa.String(64), unique=True, nullable=False),
        sa.Column("abilities", sa.JSON(), nullable=False, server_default='["*"]'),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # Indexes for fast lookups
    op.create_index("idx_pat_token_hash", "personal_access_tokens", ["token"], unique=True)
    op.create_index("idx_pat_user_id", "personal_access_tokens", ["user_id"])


def downgrade() -> None:
    op.drop_index("idx_pat_user_id", table_name="personal_access_tokens")
    op.drop_index("idx_pat_token_hash", table_name="personal_access_tokens")
    op.drop_table("personal_access_tokens")

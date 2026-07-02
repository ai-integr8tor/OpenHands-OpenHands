"""Create api_key_scopes table.

Phase 1 foundation for scoped (reduced-privilege) API credentials.

Stores opaque, namespaced scope strings attached to an API key. A key with no
rows here is treated as carrying the implicit ``full`` scope, so existing keys
keep their current behavior (no behavior change on rollout).

Revision ID: 125
Revises: 124
Create Date: 2026-06-20 00:00:00.000000
"""

from typing import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '125'
down_revision: str | None = '124'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'api_key_scopes',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('api_key_id', sa.Integer(), nullable=False),
        sa.Column('scope', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(
            ['api_key_id'],
            ['api_keys.id'],
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('api_key_id', 'scope', name='uq_api_key_scopes_key_scope'),
    )
    op.create_index(
        op.f('ix_api_key_scopes_api_key_id'),
        'api_key_scopes',
        ['api_key_id'],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f('ix_api_key_scopes_api_key_id'), table_name='api_key_scopes'
    )
    op.drop_table('api_key_scopes')

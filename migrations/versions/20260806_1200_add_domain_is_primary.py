"""add domain.is_primary (primary domain per account)

Revision ID: d3f6a1b8c920
Revises: c7d1e4f9a208
Create Date: 2026-08-06 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd3f6a1b8c920'
down_revision: Union[str, None] = 'c7d1e4f9a208'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('domains', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_primary', sa.Boolean(), nullable=False,
                                      server_default=sa.false()))

    # Back-fill: mark each account's oldest domain as its primary, so existing
    # accounts keep exactly one protected main domain.
    op.execute(
        "UPDATE domains SET is_primary = 1 WHERE id IN "
        "(SELECT MIN(id) FROM domains GROUP BY owner_id)"
    )


def downgrade() -> None:
    with op.batch_alter_table('domains', schema=None) as batch_op:
        batch_op.drop_column('is_primary')

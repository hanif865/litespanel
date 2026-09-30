"""add cloudflare_credentials

Revision ID: e5c2a7f1b9d4
Revises: d4b9e1f3c5a7
Create Date: 2026-09-30 10:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e5c2a7f1b9d4'
down_revision: Union[str, None] = 'd4b9e1f3c5a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Per-account Cloudflare API token, so each client mirrors their own
    # domains' DNS to their own Cloudflare account.
    op.create_table(
        'cloudflare_credentials',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('token_enc', sa.String(length=255), nullable=True),
        sa.Column('enabled', sa.Boolean(), server_default='0', nullable=False),
        sa.Column('proxied', sa.Boolean(), server_default='0', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('owner_id', name='uq_cloudflare_owner'),
    )
    with op.batch_alter_table('cloudflare_credentials', schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f('ix_cloudflare_credentials_owner_id'), ['owner_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('cloudflare_credentials', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_cloudflare_credentials_owner_id'))
    op.drop_table('cloudflare_credentials')

"""add mail_filters

Revision ID: d4b9e1f3c5a7
Revises: c3a8f1e2b4d6
Create Date: 2026-08-21 10:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd4b9e1f3c5a7'
down_revision: Union[str, None] = 'c3a8f1e2b4d6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Per-mailbox cPanel-style email filters, compiled to Sieve by the provider.
    op.create_table(
        'mail_filters',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('domain_id', sa.Integer(), nullable=False),
        sa.Column('local_part', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('enabled', sa.Boolean(), server_default='1', nullable=False),
        sa.Column('priority', sa.Integer(), server_default='0', nullable=False),
        sa.Column('rules', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('domain_id', 'local_part', 'name', name='uq_mailfilter'),
    )
    with op.batch_alter_table('mail_filters', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_mail_filters_domain_id'), ['domain_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('mail_filters', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_mail_filters_domain_id'))
    op.drop_table('mail_filters')

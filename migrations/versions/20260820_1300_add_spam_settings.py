"""add spam_settings

Revision ID: c3a8f1e2b4d6
Revises: b2f7c4e9a1d3
Create Date: 2026-08-20 13:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3a8f1e2b4d6'
down_revision: Union[str, None] = 'b2f7c4e9a1d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Per-domain spam filtering (Rspamd) preferences — tag-only.
    op.create_table(
        'spam_settings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('domain_id', sa.Integer(), nullable=False),
        sa.Column('enabled', sa.Boolean(), server_default='1', nullable=False),
        sa.Column('threshold', sa.Integer(), server_default='6', nullable=False),
        sa.Column('rewrite_subject', sa.Boolean(), server_default='1', nullable=False),
        sa.Column('whitelist', sa.JSON(), nullable=True),
        sa.Column('blacklist', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('domain_id', name='uq_spam_domain'),
    )
    with op.batch_alter_table('spam_settings', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_spam_settings_domain_id'), ['domain_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('spam_settings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_spam_settings_domain_id'))
    op.drop_table('spam_settings')

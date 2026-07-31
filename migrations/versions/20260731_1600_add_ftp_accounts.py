"""add ftp_accounts

Revision ID: e1c7b2f6a9d3
Revises: d8f1a3c9e4b2
Create Date: 2026-07-31 16:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e1c7b2f6a9d3'
down_revision: Union[str, None] = 'd8f1a3c9e4b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'ftp_accounts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=128), nullable=False),
        sa.Column('password_enc', sa.String(length=255), nullable=True),
        sa.Column('home_dir', sa.String(length=500), nullable=False),
        sa.Column('quota_mb', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username', name='uq_ftp_username'),
    )
    with op.batch_alter_table('ftp_accounts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_ftp_accounts_owner_id'), ['owner_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_ftp_accounts_username'), ['username'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('ftp_accounts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_ftp_accounts_username'))
        batch_op.drop_index(batch_op.f('ix_ftp_accounts_owner_id'))
    op.drop_table('ftp_accounts')

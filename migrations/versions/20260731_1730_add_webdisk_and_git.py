"""add webdisk_accounts and git_repos

Revision ID: f3a9d2c7b510
Revises: e1c7b2f6a9d3
Create Date: 2026-07-31 17:30:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f3a9d2c7b510'
down_revision: Union[str, None] = 'e1c7b2f6a9d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'webdisk_accounts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=128), nullable=False),
        sa.Column('password_enc', sa.String(length=255), nullable=True),
        sa.Column('home_dir', sa.String(length=500), nullable=False),
        sa.Column('read_only', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username', name='uq_webdisk_username'),
    )
    with op.batch_alter_table('webdisk_accounts', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_webdisk_accounts_owner_id'), ['owner_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_webdisk_accounts_username'), ['username'], unique=False)

    op.create_table(
        'git_repos',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('path', sa.String(length=500), nullable=False),
        sa.Column('clone_url', sa.String(length=500), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_pull_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('owner_id', 'path', name='uq_git_owner_path'),
    )
    with op.batch_alter_table('git_repos', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_git_repos_owner_id'), ['owner_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('git_repos', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_git_repos_owner_id'))
    op.drop_table('git_repos')
    with op.batch_alter_table('webdisk_accounts', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_webdisk_accounts_username'))
        batch_op.drop_index(batch_op.f('ix_webdisk_accounts_owner_id'))
    op.drop_table('webdisk_accounts')

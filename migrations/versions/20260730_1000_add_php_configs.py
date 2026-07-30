"""add php_configs

Revision ID: b2f4c7a91d05
Revises: 8e6db64bebf2
Create Date: 2026-07-30 10:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2f4c7a91d05'
down_revision: Union[str, None] = '8e6db64bebf2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'php_configs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('domain_id', sa.Integer(), nullable=True),
        sa.Column('php_version', sa.String(length=16), nullable=False, server_default='8.3'),
        sa.Column('extensions', sa.JSON(), nullable=False),
        sa.Column('directives', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id']),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('owner_id', 'domain_id', name='uq_phpconfig_scope'),
    )
    with op.batch_alter_table('php_configs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_php_configs_owner_id'), ['owner_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_php_configs_domain_id'), ['domain_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('php_configs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_php_configs_domain_id'))
        batch_op.drop_index(batch_op.f('ix_php_configs_owner_id'))
    op.drop_table('php_configs')

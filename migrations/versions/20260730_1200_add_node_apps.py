"""add node_apps

Revision ID: c3a5d8e21f47
Revises: b2f4c7a91d05
Create Date: 2026-07-30 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c3a5d8e21f47'
down_revision: Union[str, None] = 'b2f4c7a91d05'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'node_apps',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('domain_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('node_version', sa.String(length=16), nullable=False, server_default='20'),
        sa.Column('entrypoint', sa.String(length=255), nullable=False, server_default='server.js'),
        sa.Column('app_dir', sa.String(length=500), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id']),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('domain_id', name='uq_nodeapp_domain'),
    )
    with op.batch_alter_table('node_apps', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_node_apps_owner_id'), ['owner_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('node_apps', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_node_apps_owner_id'))
    op.drop_table('node_apps')

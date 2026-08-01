"""add pg_databases

Revision ID: a4b8c1d9e2f7
Revises: f3a9d2c7b510
Create Date: 2026-08-01 10:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a4b8c1d9e2f7'
down_revision: Union[str, None] = 'f3a9d2c7b510'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'pg_databases',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('db_user', sa.String(length=64), nullable=False),
        sa.Column('db_password_enc', sa.String(length=255), nullable=True),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name', name='uq_pg_database_name'),
    )
    with op.batch_alter_table('pg_databases', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pg_databases_name'), ['name'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('pg_databases', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_pg_databases_name'))
    op.drop_table('pg_databases')

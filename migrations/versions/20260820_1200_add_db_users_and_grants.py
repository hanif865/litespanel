"""add database_users, database_grants, pg_users, pg_grants

Revision ID: b2f7c4e9a1d3
Revises: a7e4c1b9d2f8
Create Date: 2026-08-20 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b2f7c4e9a1d3'
down_revision: Union[str, None] = 'a7e4c1b9d2f8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Standalone MySQL users.
    op.create_table(
        'database_users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=64), nullable=False),
        sa.Column('db_password_enc', sa.String(length=255), nullable=True),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username', name='uq_db_user_username'),
    )
    with op.batch_alter_table('database_users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_database_users_username'), ['username'], unique=False)

    # MySQL user-to-database grants.
    op.create_table(
        'database_grants',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('database_id', sa.Integer(), nullable=False),
        sa.Column('privileges', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['database_users.id']),
        sa.ForeignKeyConstraint(['database_id'], ['databases.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'database_id', name='uq_db_grant'),
    )

    # Standalone PostgreSQL roles.
    op.create_table(
        'pg_users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=64), nullable=False),
        sa.Column('db_password_enc', sa.String(length=255), nullable=True),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username', name='uq_pg_user_username'),
    )
    with op.batch_alter_table('pg_users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_pg_users_username'), ['username'], unique=False)

    # PostgreSQL role-to-database grants.
    op.create_table(
        'pg_grants',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('database_id', sa.Integer(), nullable=False),
        sa.Column('privileges', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['pg_users.id']),
        sa.ForeignKeyConstraint(['database_id'], ['pg_databases.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'database_id', name='uq_pg_grant'),
    )


def downgrade() -> None:
    op.drop_table('pg_grants')
    with op.batch_alter_table('pg_users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_pg_users_username'))
    op.drop_table('pg_users')
    op.drop_table('database_grants')
    with op.batch_alter_table('database_users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_database_users_username'))
    op.drop_table('database_users')

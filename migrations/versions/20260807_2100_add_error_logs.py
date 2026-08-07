"""add error_logs

A table of persisted unhandled server exceptions, populated by the catch-all
handler in app/main.py and viewed at the admin-only /errors page. user_id is a
plain integer (no FK) so a log survives deletion of the user who triggered it.

Revision ID: a7e4c1b9d2f8
Revises: f2b3c4d5e6a7
Create Date: 2026-08-07 21:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7e4c1b9d2f8'
down_revision: Union[str, None] = 'f2b3c4d5e6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'error_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('method', sa.String(length=8), nullable=False),
        sa.Column('path', sa.String(length=500), nullable=False),
        sa.Column('exc_type', sa.String(length=255), nullable=False),
        sa.Column('exc_message', sa.Text(), nullable=False),
        sa.Column('traceback', sa.Text(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('username', sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('error_logs')

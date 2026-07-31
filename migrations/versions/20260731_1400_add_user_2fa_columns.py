"""add user 2fa columns

Revision ID: d8f1a3c9e4b2
Revises: c3a5d8e21f47
Create Date: 2026-07-31 14:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd8f1a3c9e4b2'
down_revision: Union[str, None] = 'c3a5d8e21f47'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('totp_enabled', sa.Boolean(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('totp_secret_enc', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('recovery_codes', sa.JSON(), nullable=False, server_default='[]'))


def downgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('recovery_codes')
        batch_op.drop_column('totp_secret_enc')
        batch_op.drop_column('totp_enabled')

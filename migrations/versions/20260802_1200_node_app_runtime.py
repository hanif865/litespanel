"""node app runtime: app_root, start_command, env_vars

Revision ID: c7d1e4f9a208
Revises: a4b8c1d9e2f7
Create Date: 2026-08-02 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c7d1e4f9a208'
down_revision: Union[str, None] = 'a4b8c1d9e2f7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Additive: existing NodeApp rows stay valid via server defaults.
    with op.batch_alter_table('node_apps', schema=None) as batch_op:
        batch_op.add_column(sa.Column('app_root', sa.String(length=255),
                                      nullable=False, server_default=''))
        batch_op.add_column(sa.Column('start_command', sa.String(length=128),
                                      nullable=False, server_default=''))
        batch_op.add_column(sa.Column('env_vars', sa.Text(),
                                      nullable=False, server_default=''))


def downgrade() -> None:
    with op.batch_alter_table('node_apps', schema=None) as batch_op:
        batch_op.drop_column('env_vars')
        batch_op.drop_column('start_command')
        batch_op.drop_column('app_root')

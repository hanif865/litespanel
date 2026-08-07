"""wordpress install on a subdomain

Revision ID: e1a2b3c4d5f6
Revises: d3f6a1b8c920
Create Date: 2026-08-07 09:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e1a2b3c4d5f6'
down_revision: Union[str, None] = 'd3f6a1b8c920'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('wordpress_apps', schema=None) as batch_op:
        batch_op.add_column(sa.Column('subdomain_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            'fk_wordpress_apps_subdomain_id', 'subdomains',
            ['subdomain_id'], ['id'], ondelete='CASCADE',
        )


def downgrade() -> None:
    with op.batch_alter_table('wordpress_apps', schema=None) as batch_op:
        batch_op.drop_constraint('fk_wordpress_apps_subdomain_id', type_='foreignkey')
        batch_op.drop_column('subdomain_id')

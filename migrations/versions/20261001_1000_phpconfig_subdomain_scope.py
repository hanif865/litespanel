"""per-subdomain PHP config scope

Adds php_configs.subdomain_id so the PHP Selector can target a single subdomain
(its own PHP version / extensions / php.ini), mirroring the existing per-domain
scope. The uniqueness key widens from (owner_id, domain_id) to
(owner_id, domain_id, subdomain_id) so an account can hold one profile per scope.
SQLite allows many NULLs, so account-global and per-domain rows still coexist.

Revision ID: a7d1e9c3f215
Revises: e5c2a7f1b9d4
Create Date: 2026-10-01 10:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7d1e9c3f215'
down_revision: Union[str, None] = 'e5c2a7f1b9d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('php_configs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('subdomain_id', sa.Integer(), nullable=True))
        batch_op.create_index('ix_php_configs_subdomain_id', ['subdomain_id'])
        batch_op.create_foreign_key(
            'fk_php_configs_subdomain_id', 'subdomains',
            ['subdomain_id'], ['id'], ondelete='CASCADE',
        )
        # Replace the old (owner_id, domain_id) key with one that also spans
        # subdomain_id, so a per-subdomain row doesn't collide with the account
        # profile (both have domain_id NULL).
        batch_op.drop_constraint('uq_phpconfig_scope', type_='unique')
        batch_op.create_unique_constraint(
            'uq_phpconfig_scope', ['owner_id', 'domain_id', 'subdomain_id']
        )


def downgrade() -> None:
    with op.batch_alter_table('php_configs', schema=None) as batch_op:
        batch_op.drop_constraint('uq_phpconfig_scope', type_='unique')
        batch_op.create_unique_constraint('uq_phpconfig_scope', ['owner_id', 'domain_id'])
        batch_op.drop_constraint('fk_php_configs_subdomain_id', type_='foreignkey')
        batch_op.drop_index('ix_php_configs_subdomain_id')
        batch_op.drop_column('subdomain_id')

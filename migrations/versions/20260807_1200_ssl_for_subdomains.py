"""ssl certificates for subdomains

Lets a Certificate attach to a Subdomain as well as a Domain: domain_id becomes
nullable and a nullable-unique subdomain_id is added. Exactly one of the two is
set per row; SQLite allows many NULLs so both unique constraints coexist.

Revision ID: f2b3c4d5e6a7
Revises: e1a2b3c4d5f6
Create Date: 2026-08-07 12:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f2b3c4d5e6a7'
down_revision: Union[str, None] = 'e1a2b3c4d5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # naming_convention names the pre-existing *unnamed* UNIQUE(domain_id) so it
    # survives SQLite's batch table-recreate (reflection needs a name to copy it).
    with op.batch_alter_table(
        'certificates', schema=None,
        naming_convention={"uq": "uq_%(table_name)s_%(column_0_name)s"},
    ) as batch_op:
        batch_op.alter_column('domain_id', existing_type=sa.Integer(), nullable=True)
        batch_op.add_column(sa.Column('subdomain_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            'fk_certificates_subdomain_id', 'subdomains',
            ['subdomain_id'], ['id'], ondelete='CASCADE',
        )
        batch_op.create_unique_constraint('uq_certificates_subdomain_id', ['subdomain_id'])


def downgrade() -> None:
    with op.batch_alter_table(
        'certificates', schema=None,
        naming_convention={"uq": "uq_%(table_name)s_%(column_0_name)s"},
    ) as batch_op:
        batch_op.drop_constraint('uq_certificates_subdomain_id', type_='unique')
        batch_op.drop_constraint('fk_certificates_subdomain_id', type_='foreignkey')
        batch_op.drop_column('subdomain_id')
        batch_op.alter_column('domain_id', existing_type=sa.Integer(), nullable=False)

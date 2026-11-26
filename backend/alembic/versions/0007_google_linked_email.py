"""google linked email

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-26 12:18:27.803348

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0007'
down_revision: Union[str, Sequence[str], None] = '0006'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("ALTER TYPE email_purpose ADD VALUE 'google_linked'")


def downgrade() -> None:
    """Downgrade schema."""
    bind = op.get_bind()
    pending = bind.scalar(
        sa.text(
            "SELECT count(*) FROM email_jobs"
            " WHERE purpose = 'google_linked' AND status = 'pending'"
        )
    )
    if pending:
        raise RuntimeError(f"Cannot downgrade: {pending} google_linked emails are still pending")
    op.execute("DELETE FROM email_jobs WHERE purpose = 'google_linked'")
    op.execute("ALTER TYPE email_purpose RENAME TO email_purpose_old")
    op.execute(
        "CREATE TYPE email_purpose AS ENUM ('email_confirm', 'password_reset', 'already_registered')"
    )
    op.execute(
        "ALTER TABLE email_jobs ALTER COLUMN purpose TYPE email_purpose"
        " USING purpose::text::email_purpose"
    )
    op.execute("DROP TYPE email_purpose_old")

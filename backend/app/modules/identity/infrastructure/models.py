import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, IdMixin, TimestampMixin
from app.modules.identity.domain.enums import IdentityProvider, WorkspaceRole, WorkspaceTheme


class User(IdMixin, TimestampMixin, Base):
    """Model of user"""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(nullable=False)
    display_name: Mapped[str] = mapped_column(nullable=False)
    avatar_url: Mapped[str | None]
    telegram_chat_id: Mapped[int | None] = mapped_column(BigInteger, unique=True)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("users_email_lower_idx", func.lower(email), unique=True),)


class UserIdentity(IdMixin, TimestampMixin, Base):
    """Model of user identity verification"""

    __tablename__ = "user_identities"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider: Mapped[IdentityProvider] = mapped_column(
        Enum(
            IdentityProvider,
            name="identity_provider",
            values_callable=lambda e: [m.value for m in e],
        ),
        nullable=False,
    )
    subject: Mapped[str] = mapped_column(nullable=False)

    __table_args__ = (
        UniqueConstraint("provider", "subject", name="user_identities_provider_subject_key"),
        UniqueConstraint("user_id", "provider", name="user_identities_user_id_provider_key"),
    )


class Workspace(IdMixin, TimestampMixin, Base):
    """Model of user's workspace"""

    __tablename__ = "workspaces"

    name: Mapped[str] = mapped_column(nullable=False)
    theme: Mapped[str] = mapped_column(
        String(32), server_default=WorkspaceTheme.LIGHT.value, nullable=False
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )


class Membership(Base):
    """Model of user's memberships in workspaces"""

    __tablename__ = "memberships"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        primary_key=True,
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[WorkspaceRole] = mapped_column(
        Enum(WorkspaceRole, name="workspace_role", values_callable=lambda e: [m.value for m in e]),
        nullable=False,
    )
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Invite(IdMixin, TimestampMixin, Base):
    """Model of invites sent to users to join workspace"""

    __tablename__ = "invites"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    email: Mapped[str | None]
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    used_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, IdMixin, TimestampMixin
from app.modules.identity.domain.enums import (
    EmailJobStatus,
    EmailPurpose,
    IdentityProvider,
    WorkspaceRole,
    WorkspaceTheme,
)


class User(IdMixin, TimestampMixin, Base):
    """Model of user"""

    __tablename__ = "users"

    email: Mapped[str]
    nickname: Mapped[str | None] = mapped_column(unique=True)
    display_name: Mapped[str]
    avatar_url: Mapped[str | None]
    telegram_chat_id: Mapped[int | None] = mapped_column(BigInteger, unique=True)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("users_email_lower_idx", func.lower("email"), unique=True),
        CheckConstraint("nickname = lower(nickname)", name="nickname_lowercase"),
    )


class PasswordCredential(TimestampMixin, Base):
    """Model of user's passwords (hash)"""

    __tablename__ = "password_credentials"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    password_hash: Mapped[str]


class ReleasedNickname(Base):
    """Quarantine model for used nicknames"""

    __tablename__ = "released_nicknames"

    nickname: Mapped[str] = mapped_column(primary_key=True)
    released_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    released_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (CheckConstraint("nickname = lower(nickname)", name="nickname_lowercase"),)


class UserIdentity(IdMixin, TimestampMixin, Base):
    """Model of user identity verification"""

    __tablename__ = "user_identities"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
    )
    provider: Mapped[IdentityProvider] = mapped_column(
        Enum(
            IdentityProvider,
            name="identity_provider",
            values_callable=lambda e: [m.value for m in e],
        ),
    )
    subject: Mapped[str]

    __table_args__ = (
        UniqueConstraint("provider", "subject", name="user_identities_provider_subject_key"),
        UniqueConstraint("user_id", "provider", name="user_identities_user_id_provider_key"),
    )


class Workspace(IdMixin, TimestampMixin, Base):
    """Model of user's workspace"""

    __tablename__ = "workspaces"

    name: Mapped[str]
    theme: Mapped[str] = mapped_column(
        String(32),
        server_default=WorkspaceTheme.LIGHT.value,
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
    )


class Membership(Base):
    """Model of user's memberships in workspaces"""

    __tablename__ = "memberships"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        index=True,
    )
    role: Mapped[WorkspaceRole] = mapped_column(
        Enum(WorkspaceRole, name="workspace_role", values_callable=lambda e: [m.value for m in e]),
    )
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Invite(IdMixin, TimestampMixin, Base):
    """Model of invites sent to users to join workspace"""

    __tablename__ = "invites"

    workspace_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"),
        index=True,
    )
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    email: Mapped[str | None]
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    used_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EmailJob(IdMixin, TimestampMixin, Base):
    """Queued email sending job"""

    __tablename__ = "email_jobs"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    purpose: Mapped[EmailPurpose] = mapped_column(
        Enum(EmailPurpose, name="email_purpose", values_callable=lambda e: [m.value for m in e]),
    )
    status: Mapped[EmailJobStatus] = mapped_column(
        Enum(
            EmailJobStatus, name="email_job_status", values_callable=lambda e: [m.value for m in e]
        ),
        default=EmailJobStatus.PENDING.value,
        server_default=EmailJobStatus.PENDING.value,
    )
    attempts: Mapped[int] = mapped_column(default=0, server_default=text("0"))
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None]

    __table_args__ = (
        Index(
            "email_jobs_user_id_purpose_pending_key",
            "user_id",
            "purpose",
            unique=True,
            postgresql_where=text("status = 'pending'"),
        ),
        Index(
            "email_jobs_available_at_pending_idx",
            "available_at",
            postgresql_where=text("status = 'pending'"),
        ),
    )

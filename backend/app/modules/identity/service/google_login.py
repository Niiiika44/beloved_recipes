import base64
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from uuid import UUID

from app.modules.identity.domain.enums import (
    EmailPurpose,
    IdentityProvider,
    LoginMethod,
    TokenPurpose,
)
from app.modules.identity.domain.exceptions import InvalidDisplayNameError, InvalidTokenError
from app.modules.identity.domain.limits import GOOGLE_CALLBACK_IP_LIMIT, GOOGLE_LOGIN_START_IP_LIMIT
from app.modules.identity.domain.oidc import LOGIN_STATE_TTL
from app.modules.identity.domain.profile import DISPLAY_NAME_MAX_LENGTH, normalize_display_name
from app.modules.identity.domain.redirects import safe_next
from app.modules.identity.service.dto import (
    GoogleCallbackDTO,
    GoogleLoginResultDTO,
    GoogleLoginStartDTO,
    OidcIdentityDTO,
    PendingLoginDTO,
    ProviderRejectionDTO,
    UserDTO,
)
from app.modules.identity.service.exceptions import GoogleRejectedError, GoogleRejectionCode
from app.modules.identity.service.ports import (
    LoginStateStore,
    OidcProvider,
    OneTimeTokenStore,
    RateLimiter,
    SecurityEvents,
    SessionStore,
    UnitOfWork,
)

GOOGLE_LOGIN_START_IP_PREFIX = "google_login_ip:"
GOOGLE_CALLBACK_IP_PREFIX = "google_callback_ip:"
UNKNOWN_IP = "unknown"


async def start_google_login(
    next_path: str | None,
    client_ip: str | None,
    provider: OidcProvider,
    states: LoginStateStore,
    limiter: RateLimiter,
    events: SecurityEvents,
) -> GoogleLoginStartDTO:
    await _check_limits(client_ip=client_ip, limiter=limiter, events=events)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(32)
    browser_binding = secrets.token_urlsafe(32)
    code_challenge = (
        base64.urlsafe_b64encode(sha256(code_verifier.encode()).digest())
        .decode("utf-8")
        .rstrip("=")
    )
    pending = PendingLoginDTO(
        code_verifier=code_verifier,
        nonce=nonce,
        next=safe_next(next_path),
        browser_binding_hash=sha256(browser_binding.encode()).hexdigest(),
    )
    await states.save(state, pending, LOGIN_STATE_TTL)
    authorization_url = provider.authorization_url(
        state=state, nonce=nonce, code_challenge=code_challenge
    )
    return GoogleLoginStartDTO(authorization_url=authorization_url, browser_binding=browser_binding)


async def _check_limits(
    client_ip: str | None, limiter: RateLimiter, events: SecurityEvents
) -> None:
    ip_key = GOOGLE_LOGIN_START_IP_PREFIX + (client_ip or UNKNOWN_IP)
    retry_after = await limiter.hit(ip_key, GOOGLE_LOGIN_START_IP_LIMIT)
    if retry_after is not None:
        events.rate_limited("google_login", "ip")
        raise GoogleRejectedError("rate_limited")


@dataclass(frozen=True, slots=True)
class _SignedIn:
    user: UserDTO
    credentials_version: int
    record: Callable[[], None]


class GoogleLoginService:
    def __init__(
        self,
        uow: UnitOfWork,
        provider: OidcProvider,
        states: LoginStateStore,
        sessions: SessionStore,
        events: SecurityEvents,
        limiter: RateLimiter,
    ):
        self._uow = uow
        self._provider = provider
        self._states = states
        self._sessions = sessions
        self._events = events
        self._limiter = limiter

    async def complete(self, callback: GoogleCallbackDTO) -> GoogleLoginResultDTO:
        await self._check_limits(callback.client_ip)
        pending = await self._take_pending(callback)
        identity = await self._exchange(callback.code, pending)
        signed_in = await self._find_or_link(identity)
        signed_in.record()
        if callback.current_token is not None:
            await self._sessions.revoke(callback.current_token)
        token = await self._sessions.create(signed_in.user.id, signed_in.credentials_version)
        self._events.login_succeeded(signed_in.user.id, LoginMethod.GOOGLE)
        return GoogleLoginResultDTO(token=token, next=pending.next)

    async def _check_limits(self, client_ip: str | None) -> None:
        ip_key = GOOGLE_CALLBACK_IP_PREFIX + (client_ip or UNKNOWN_IP)
        retry_after = await self._limiter.hit(ip_key, GOOGLE_CALLBACK_IP_LIMIT)
        if retry_after is not None:
            self._events.rate_limited("google_callback", "ip")
            raise self._reject("rate_limited")

    async def _take_pending(self, callback: GoogleCallbackDTO) -> PendingLoginDTO:
        pending = await self._states.pop(callback.state)
        if pending is None or callback.browser_binding is None:
            raise self._reject("state")
        binding_hash = sha256(callback.browser_binding.encode()).hexdigest()
        if not hmac.compare_digest(binding_hash, pending.browser_binding_hash):
            raise self._reject("state")
        return pending

    async def _exchange(self, code: str, pending: PendingLoginDTO) -> OidcIdentityDTO:
        result = await self._provider.exchange_code(code, pending.code_verifier)
        if isinstance(result, ProviderRejectionDTO):
            raise self._reject("provider", reason=f"provider:{result.reason}")
        if not hmac.compare_digest(result.nonce, pending.nonce):
            raise self._reject("nonce")
        if not result.email_verified:
            raise self._reject("email_unverified")
        return result

    async def _find_or_link(self, identity: OidcIdentityDTO) -> _SignedIn:
        async with self._uow:
            user = await self._uow.users.find_by_identity(IdentityProvider.GOOGLE, identity.subject)
            if user is not None:
                signed_in = await self._refresh_profile(user, identity)
            else:
                signed_in = await self._link_by_email(identity)
            await self._uow.commit()
        return signed_in

    async def _refresh_profile(self, user: UserDTO, identity: OidcIdentityDTO) -> _SignedIn:
        if identity.email.lower() != user.email.lower():
            owner = await self._uow.users.find_by_email(identity.email)
            if owner is not None and owner.id != user.id:
                raise self._reject("email_conflict", user_id=user.id)
        await self._uow.users.update_profile(
            user.id, identity.email, user.display_name, user.avatar_url or identity.picture
        )
        return _SignedIn(user, user.credentials_version, _nothing)

    async def _link_by_email(self, identity: OidcIdentityDTO) -> _SignedIn:
        found = await self._uow.users.find_by_email(identity.email)
        if found is None:
            created = await self._create(identity)
            if created is not None:
                return created
            found = await self._uow.users.find_by_email(identity.email)
            if found is None:
                raise self._reject("state")
        user = await self._uow.users.get_for_update(found.id)
        if user is None:
            raise self._reject("state")
        if user.email_verified_at is None:
            return await self._claim_unverified(user, identity)
        return await self._link_verified(user, identity)

    async def _create(self, identity: OidcIdentityDTO) -> _SignedIn | None:
        user_id = await self._uow.users.create(
            identity.email,
            _display_name(identity),
            avatar_url=identity.picture,
            email_verified=True,
        )
        if user_id is None:
            return None
        await self._uow.users.link_identity(user_id, IdentityProvider.GOOGLE, identity.subject)
        user = await self._uow.users.get(user_id)
        if user is None:
            raise self._reject("state")
        return _SignedIn(user, user.credentials_version, _nothing)

    async def _claim_unverified(self, user: UserDTO, identity: OidcIdentityDTO) -> _SignedIn:
        await self._uow.passwords.delete(user.id)
        await self._uow.users.mark_email_verified(user.id)
        await self._uow.users.link_identity(user.id, IdentityProvider.GOOGLE, identity.subject)
        await self._uow.users.update_profile(
            user.id, identity.email, _display_name(identity), identity.picture
        )
        version = await self._uow.users.bump_credentials_version(user.id)
        user_id = user.id
        return _SignedIn(user, version, lambda: self._events.unverified_account_claimed(user_id))

    async def _link_verified(self, user: UserDTO, identity: OidcIdentityDTO) -> _SignedIn:
        previous = await self._uow.users.get_identity_subject(user.id, IdentityProvider.GOOGLE)
        await self._uow.users.link_identity(user.id, IdentityProvider.GOOGLE, identity.subject)
        await self._uow.users.update_profile(
            user.id, identity.email, user.display_name, user.avatar_url or identity.picture
        )
        await self._uow.email_jobs.enqueue(EmailPurpose.GOOGLE_LINKED, user.id)
        user_id, subject = user.id, identity.subject
        if previous is None:
            return _SignedIn(
                user,
                user.credentials_version,
                lambda: self._events.google_linked(user_id, subject),
            )
        version = await self._uow.users.bump_credentials_version(user.id)
        return _SignedIn(
            user,
            version,
            lambda: self._events.account_relinked(user_id, previous, subject),
        )

    def _reject(
        self,
        code: GoogleRejectionCode,
        reason: str | None = None,
        user_id: UUID | None = None,
    ) -> GoogleRejectedError:
        self._events.google_login_rejected(user_id, reason or code)
        return GoogleRejectedError(code)


def _display_name(identity: OidcIdentityDTO) -> str:
    try:
        return normalize_display_name(identity.name)
    except InvalidDisplayNameError:
        return identity.email.split("@", 1)[0][:DISPLAY_NAME_MAX_LENGTH]


def _nothing() -> None:
    return None


async def disown_google_login(
    token: str, tokens: OneTimeTokenStore, uow: UnitOfWork, events: SecurityEvents
) -> None:
    user_token = await tokens.consume(TokenPurpose.GOOGLE_NOT_ME, token)
    if user_token is None:
        raise InvalidTokenError()
    async with uow:
        user = await uow.users.get_for_update(user_token.user_id)
        if user is None:
            raise InvalidTokenError()
        await uow.users.unlink_identity(user.id, IdentityProvider.GOOGLE)
        await uow.users.bump_credentials_version(user.id)
        await uow.commit()
    events.google_disowned(user.id)

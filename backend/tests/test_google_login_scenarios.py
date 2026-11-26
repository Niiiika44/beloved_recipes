import base64
import uuid
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256

import pytest
from fakes import (
    VERIFIED_AT,
    FakeEvents,
    FakeLimiter,
    FakeLoginStates,
    FakeOidcProvider,
    FakeSessions,
    FakeTokens,
    FakeUnitOfWork,
    FakeUsers,
    make_user,
)

from app.core.exceptions import DependencyUnavailableError
from app.modules.identity.domain.enums import EmailPurpose, IdentityProvider, TokenPurpose
from app.modules.identity.domain.exceptions import InvalidTokenError
from app.modules.identity.domain.limits import GOOGLE_CALLBACK_IP_LIMIT, GOOGLE_LOGIN_START_IP_LIMIT
from app.modules.identity.service.dto import (
    GoogleCallbackDTO,
    GoogleLoginStartDTO,
    OidcIdentityDTO,
    PendingLoginDTO,
    ProviderRejectionDTO,
    UserDTO,
)
from app.modules.identity.service.exceptions import GoogleRejectedError
from app.modules.identity.service.google_login import (
    GoogleLoginService,
    disown_google_login,
    start_google_login,
)

GOOGLE = IdentityProvider.GOOGLE
IP = "203.0.113.7"
STATE = "S" * 43
BINDING = "B" * 43
NONCE = "N" * 43
VERIFIER = "V" * 43
CURRENT_TOKEN = "C" * 43
NOT_ME_TOKEN = "T" * 43


def _identity(**overrides: object) -> OidcIdentityDTO:
    values: dict[str, object] = {
        "subject": "sub-anna",
        "email": "anna@example.org",
        "email_verified": True,
        "name": "Anna Google",
        "picture": "https://google/anna.png",
        "nonce": NONCE,
    }
    return OidcIdentityDTO(**(values | overrides))  # type: ignore[arg-type]


def _user(email: str = "anna@example.org", **overrides: object) -> UserDTO:
    return replace(make_user("Anna"), email=email, **overrides)  # type: ignore[arg-type]


class World:
    def __init__(
        self,
        *users: UserDTO,
        answer: OidcIdentityDTO | ProviderRejectionDTO | None = None,
        retry_after: int | None = None,
    ) -> None:
        self.uow = FakeUnitOfWork(users)
        self.provider = FakeOidcProvider(answer or _identity(), uow=self.uow)
        self.states = FakeLoginStates()
        self.sessions = FakeSessions(self.uow, live={CURRENT_TOKEN: uuid.uuid7()})
        self.events = FakeEvents()
        self.limiter = FakeLimiter(self.uow, retry_after=retry_after)
        self.service = GoogleLoginService(
            uow=self.uow,
            provider=self.provider,
            states=self.states,
            sessions=self.sessions,
            events=self.events,
            limiter=self.limiter,
        )

    def pending(self, next_path: str = "/recipes/42", binding: str = BINDING) -> None:
        self.states.saved[STATE] = PendingLoginDTO(
            code_verifier=VERIFIER,
            nonce=NONCE,
            next=next_path,
            browser_binding_hash=sha256(binding.encode()).hexdigest(),
        )

    def callback(self, **overrides: object) -> GoogleCallbackDTO:
        values: dict[str, object] = {
            "code": "code-from-google",
            "state": STATE,
            "browser_binding": BINDING,
            "current_token": None,
            "client_ip": IP,
        }
        return GoogleCallbackDTO(**(values | overrides))  # type: ignore[arg-type]

    async def complete(self, **overrides: object) -> str:
        self.pending()
        result = await self.service.complete(self.callback(**overrides))
        return result.token

    async def rejected(self, **overrides: object) -> str:
        with pytest.raises(GoogleRejectedError) as caught:
            await self.service.complete(self.callback(**overrides))
        return caught.value.code

    def stored(self, email: str = "anna@example.org") -> UserDTO:
        user = self.uow.find_email(email)
        assert user is not None
        return user

    def rejections(self) -> list[tuple[str, ...]]:
        return [event for event in self.events.recorded if event[0] == "google_login_rejected"]


async def _start(
    next_path: str | None = "/recipes/42",
    limiter: FakeLimiter | None = None,
    states: FakeLoginStates | None = None,
    events: FakeEvents | None = None,
    provider: FakeOidcProvider | None = None,
) -> tuple[GoogleLoginStartDTO, FakeOidcProvider, FakeLoginStates]:
    provider = provider or FakeOidcProvider()
    states = states or FakeLoginStates()
    start = await start_google_login(
        next_path, IP, provider, states, limiter or FakeLimiter(), events or FakeEvents()
    )
    return start, provider, states


async def test_start_saves_a_pending_login_under_the_state_sent_to_google() -> None:
    start, provider, states = await _start()

    [(state, nonce, _)] = provider.authorized
    pending = states.saved[state]
    assert start.authorization_url == f"https://accounts.example/auth?state={state}"
    assert pending.nonce == nonce
    assert pending.next == "/recipes/42"
    assert states.ttls == [timedelta(minutes=10)]


async def test_start_sends_the_s256_challenge_of_the_saved_verifier() -> None:
    _, provider, states = await _start()

    [(state, _, challenge)] = provider.authorized
    verifier = states.saved[state].code_verifier
    expected = base64.urlsafe_b64encode(sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert challenge == expected
    assert "=" not in challenge


async def test_start_keeps_only_the_hash_of_the_browser_binding() -> None:
    start, provider, states = await _start()

    pending = states.saved[provider.authorized[0][0]]
    assert pending.browser_binding_hash == sha256(start.browser_binding.encode()).hexdigest()
    assert start.browser_binding not in repr(start)
    assert pending.code_verifier not in repr(pending)


async def test_every_start_gets_fresh_secrets() -> None:
    first, provider, states = await _start()
    second, _, _ = await _start(provider=provider, states=states)

    (state1, nonce1, _), (state2, nonce2, _) = provider.authorized
    assert len({state1, state2, nonce1, nonce2}) == 4
    assert first.browser_binding != second.browser_binding
    assert first.browser_binding != states.saved[state1].code_verifier
    assert states.saved[state1].code_verifier != states.saved[state2].code_verifier


@pytest.mark.parametrize(
    "next_path", ["https://evil.example/login", "//evil.example", "\\\\evil", None, ""]
)
async def test_start_saves_only_a_safe_next(next_path: str | None) -> None:
    _, provider, states = await _start(next_path)

    assert states.saved[provider.authorized[0][0]].next == "/"


async def test_start_counts_its_own_limit_by_ip() -> None:
    limiter = FakeLimiter()

    await _start(limiter=limiter)

    [(key, limit)] = limiter.hits
    assert key == f"google_login_ip:{IP}"
    assert limit is GOOGLE_LOGIN_START_IP_LIMIT


async def test_exceeded_start_limit_is_a_rejection_before_anything_is_saved() -> None:
    events = FakeEvents()
    provider, states = FakeOidcProvider(), FakeLoginStates()

    with pytest.raises(GoogleRejectedError) as caught:
        await _start(
            limiter=FakeLimiter(retry_after=30), states=states, events=events, provider=provider
        )

    assert caught.value.code == "rate_limited"
    assert events.recorded == [("rate_limited", "google_login", "ip")]
    assert states.saved == {}
    assert provider.authorized == []


async def test_state_store_outage_at_start_is_reported() -> None:
    outage = DependencyUnavailableError("Login state store is unavailable")

    with pytest.raises(DependencyUnavailableError) as caught:
        await _start(states=FakeLoginStates(failure=outage))

    assert caught.value is outage


async def test_first_login_creates_a_verified_user_with_the_google_profile() -> None:
    world = World()

    token = await world.complete()

    user = world.stored()
    assert user.email_verified_at is not None
    assert user.display_name == "Anna Google"
    assert user.avatar_url == "https://google/anna.png"
    assert user.nickname is None
    assert world.uow.identities == {(user.id, GOOGLE): "sub-anna"}
    assert world.uow.jobs == []
    assert world.sessions.created == [(user.id, token)]
    assert world.sessions.versions[token] == 0
    assert world.uow.commits == 1


async def test_login_returns_the_saved_next() -> None:
    world = World()
    world.pending(next_path="/recipes/7")

    result = await world.service.complete(world.callback())

    assert result.next == "/recipes/7"
    assert result.token not in repr(result)


async def test_successful_login_is_an_event() -> None:
    world = World()

    await world.complete()

    assert world.events.recorded[-1] == ("login_succeeded", str(world.stored().id), "google")


async def test_known_subject_signs_in_without_creating_anyone() -> None:
    anna = _user(email_verified_at=VERIFIED_AT, credentials_version=4)
    world = World(anna)
    world.uow.identities[(anna.id, GOOGLE)] = "sub-anna"

    token = await world.complete()

    assert world.uow.created == []
    assert world.sessions.created == [(anna.id, token)]
    assert world.sessions.versions[token] == 4
    assert "bump_credentials_version" not in world.uow.calls
    assert world.uow.jobs == []


async def test_known_subject_takes_the_email_but_keeps_the_own_name_and_avatar() -> None:
    anna = _user(display_name="Аня-кулинар", avatar_url="https://my/own.png")
    world = World(anna, answer=_identity(email="Anna.New@example.org", name="Renamed"))
    world.uow.identities[(anna.id, GOOGLE)] = "sub-anna"

    await world.complete()

    stored = world.uow.stored[anna.id]
    assert stored.email == "Anna.New@example.org"
    assert stored.display_name == "Аня-кулинар"
    assert stored.avatar_url == "https://my/own.png"


async def test_same_email_in_another_case_is_not_a_conflict() -> None:
    anna = _user()
    world = World(anna, answer=_identity(email="ANNA@Example.org"))
    world.uow.identities[(anna.id, GOOGLE)] = "sub-anna"

    await world.complete()

    assert world.uow.stored[anna.id].email == "ANNA@Example.org"


async def test_missing_avatar_is_filled_from_google() -> None:
    anna = _user(avatar_url=None)
    world = World(anna)
    world.uow.identities[(anna.id, GOOGLE)] = "sub-anna"

    await world.complete()

    assert world.uow.stored[anna.id].avatar_url == "https://google/anna.png"


async def test_new_email_taken_by_someone_else_is_a_conflict() -> None:
    anna = _user()
    boris = _user(email="boris@example.org")
    world = World(anna, boris, answer=_identity(email="BORIS@example.org"))
    world.uow.identities[(anna.id, GOOGLE)] = "sub-anna"
    world.pending()

    code = await world.rejected()

    assert code == "email_conflict"
    assert world.uow.stored[anna.id].email == "anna@example.org"
    assert world.uow.commits == 0
    assert world.sessions.created == []
    assert world.rejections() == [("google_login_rejected", str(anna.id), "email_conflict")]


async def test_first_google_on_a_verified_password_account_links_and_tells_the_owner() -> None:
    anna = _user(email_verified_at=VERIFIED_AT, display_name="Аня-кулинар")
    world = World(anna)
    world.uow.password_hashes[anna.id] = "$argon2id$own"

    token = await world.complete()

    assert world.uow.identities == {(anna.id, GOOGLE): "sub-anna"}
    assert world.uow.calls.index("get_for_update") < world.uow.calls.index("link_identity")
    assert world.uow.jobs == [(EmailPurpose.GOOGLE_LINKED, anna.id)]
    assert world.uow.password_hashes == {anna.id: "$argon2id$own"}
    assert world.uow.stored[anna.id].display_name == "Аня-кулинар"
    assert world.sessions.versions[token] == 0
    assert "bump_credentials_version" not in world.uow.calls
    assert ("google_linked", str(anna.id), "sub-anna") in world.events.recorded


async def test_recreated_google_account_relinks_and_revokes_old_sessions() -> None:
    anna = _user(email_verified_at=VERIFIED_AT, credentials_version=2)
    world = World(anna, answer=_identity(subject="sub-new"))
    world.uow.identities[(anna.id, GOOGLE)] = "sub-old"

    token = await world.complete()

    assert world.uow.identities == {(anna.id, GOOGLE): "sub-new"}
    assert world.uow.stored[anna.id].credentials_version == 3
    assert world.sessions.versions[token] == 3
    assert world.uow.jobs == [(EmailPurpose.GOOGLE_LINKED, anna.id)]
    assert ("account_relinked", str(anna.id), "sub-old", "sub-new") in world.events.recorded


async def test_unverified_password_registration_is_claimed_by_the_mailbox_owner() -> None:
    squatter = _user(display_name="Admin Support", avatar_url="https://attacker/x.png")
    world = World(squatter, answer=_identity(name="Real Owner"))
    world.uow.password_hashes[squatter.id] = "$argon2id$attacker"

    token = await world.complete()

    stored = world.uow.stored[squatter.id]
    assert world.uow.password_hashes == {}
    assert stored.email_verified_at is not None
    assert stored.display_name == "Real Owner"
    assert stored.avatar_url == "https://google/anna.png"
    assert stored.credentials_version == 1
    assert world.uow.identities == {(squatter.id, GOOGLE): "sub-anna"}
    assert world.sessions.versions[token] == 1
    assert world.uow.jobs == []
    assert ("unverified_account_claimed", str(squatter.id)) in world.events.recorded


class LateUsers(FakeUsers):
    def __init__(self, uow: FakeUnitOfWork, late: UserDTO) -> None:
        super().__init__(uow)
        self.late = late
        self.lookups = 0

    async def find_by_email(self, email: str) -> UserDTO | None:
        self.lookups += 1
        if self.lookups == 1:
            self._uow.record("find_by_email")
            self._uow.stored[self.late.id] = self.late
            return None
        return await super().find_by_email(email)


async def test_parallel_first_login_that_created_the_user_first_is_reused() -> None:
    earlier = _user(email_verified_at=VERIFIED_AT)
    world = World()
    world.uow.users = LateUsers(world.uow, earlier)

    token = await world.complete()

    assert world.uow.created == []
    assert world.sessions.created == [(earlier.id, token)]
    assert world.uow.identities == {(earlier.id, GOOGLE): "sub-anna"}


@pytest.mark.parametrize(
    ("name", "expected"),
    [("   ", "anna"), ("x" * 101, "anna"), ("Anna\x00Google", "anna"), (" Anna ", "Anna")],
    ids=["blank", "too_long", "control_character", "padded"],
)
async def test_unusable_google_name_falls_back_to_the_email(name: str, expected: str) -> None:
    world = World(answer=_identity(name=name))

    await world.complete()

    assert world.stored().display_name == expected


async def test_current_session_of_the_browser_is_revoked_before_the_new_one() -> None:
    world = World()

    token = await world.complete(current_token=CURRENT_TOKEN)

    assert world.sessions.revoked == [CURRENT_TOKEN]
    assert world.sessions.order[-2:] == ["revoke_session", "create_session"]
    assert token != CURRENT_TOKEN


async def test_google_and_session_store_are_used_outside_the_transaction() -> None:
    world = World()

    await world.complete(current_token=CURRENT_TOKEN)

    assert world.provider.exchanged_inside_uow == [False]
    assert not any(world.sessions.inside_uow)
    assert world.uow.calls.index("exchange_code") < world.uow.calls.index("find_by_identity")


async def test_code_is_exchanged_with_the_saved_verifier() -> None:
    world = World()

    await world.complete()

    assert world.provider.exchanged == [("code-from-google", VERIFIER)]


async def test_link_events_are_written_only_after_commit() -> None:
    anna = _user(email_verified_at=VERIFIED_AT)
    world = World(anna)

    async def broken_commit() -> None:
        raise RuntimeError("database went away")

    world.uow.commit = broken_commit  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await world.complete()

    assert [event for event in world.events.recorded if event[0] == "google_linked"] == []
    assert world.sessions.created == []


async def test_callback_limit_is_counted_by_ip() -> None:
    world = World()

    await world.complete()

    [(key, limit)] = world.limiter.hits
    assert key == f"google_callback_ip:{IP}"
    assert limit is GOOGLE_CALLBACK_IP_LIMIT


async def test_exceeded_callback_limit_is_rejected_before_the_state_is_used() -> None:
    world = World(retry_after=30)
    world.pending()

    code = await world.rejected()

    assert code == "rate_limited"
    assert world.states.popped == []
    assert world.provider.exchanged == []
    assert ("rate_limited", "google_callback", "ip") in world.events.recorded
    assert world.rejections() == [("google_login_rejected", "-", "rate_limited")]


@pytest.mark.parametrize(
    "overrides",
    [{"state": "W" * 43}, {"browser_binding": None}, {"browser_binding": "X" * 43}],
    ids=["unknown_state", "no_binding_cookie", "other_browser"],
)
async def test_callback_that_did_not_start_here_is_rejected_without_asking_google(
    overrides: dict[str, object],
) -> None:
    world = World()
    world.pending()

    code = await world.rejected(**overrides)

    assert code == "state"
    assert world.provider.exchanged == []
    assert world.sessions.created == []
    assert world.rejections() == [("google_login_rejected", "-", "state")]


async def test_the_same_callback_works_only_once() -> None:
    world = World()
    await world.complete()

    code = await world.rejected()

    assert code == "state"
    assert len(world.provider.exchanged) == 1


async def test_callback_from_another_browser_burns_the_pending_login() -> None:
    world = World()
    world.pending()
    await world.rejected(browser_binding="X" * 43)

    code = await world.rejected()

    assert code == "state"


async def test_provider_rejection_keeps_its_reason_in_the_event() -> None:
    world = World(answer=ProviderRejectionDTO("bad_signature"))
    world.pending()

    code = await world.rejected()

    assert code == "provider"
    assert world.rejections() == [("google_login_rejected", "-", "provider:bad_signature")]
    assert world.uow.calls.count("find_by_identity") == 0


async def test_token_issued_for_another_login_is_rejected_by_nonce() -> None:
    world = World(answer=_identity(nonce="other-nonce"))
    world.pending()

    code = await world.rejected()

    assert code == "nonce"
    assert world.uow.created == []


async def test_unverified_google_email_is_rejected() -> None:
    world = World(answer=_identity(email_verified=False))
    world.pending()

    code = await world.rejected()

    assert code == "email_unverified"
    assert world.uow.created == []


async def test_google_outage_is_reported_not_disguised() -> None:
    world = World()
    outage = DependencyUnavailableError("Google is unavailable")
    world.provider.failure = outage
    world.pending()

    with pytest.raises(DependencyUnavailableError) as caught:
        await world.service.complete(world.callback())

    assert caught.value is outage
    assert world.sessions.created == []


async def test_events_carry_no_code_binding_or_tokens() -> None:
    world = World()
    world.pending()

    await world.service.complete(world.callback(current_token=CURRENT_TOKEN))

    everything = repr(world.events.recorded)
    for secret in ("code-from-google", BINDING, VERIFIER, CURRENT_TOKEN, *world.sessions.live):
        assert secret not in everything


class NotMeWorld:
    def __init__(self, user: UserDTO | None = None) -> None:
        self.user = user or _user(credentials_version=5)
        self.uow = FakeUnitOfWork([self.user])
        self.uow.identities[(self.user.id, GOOGLE)] = "sub-attacker"
        self.tokens = FakeTokens(self.uow)
        self.tokens.plant(TokenPurpose.GOOGLE_NOT_ME, NOT_ME_TOKEN, self.user.id, 5)
        self.events = FakeEvents()

    async def disown(self, token: str = NOT_ME_TOKEN) -> None:
        await disown_google_login(token, self.tokens, self.uow, self.events)


async def test_not_me_unlinks_google_and_signs_out_everywhere() -> None:
    world = NotMeWorld()

    await world.disown()

    assert world.uow.identities == {}
    assert world.uow.stored[world.user.id].credentials_version == 6
    assert world.uow.calls.index("get_for_update") < world.uow.calls.index("unlink_identity")
    assert world.uow.commits == 1
    assert world.events.recorded == [("google_disowned", str(world.user.id))]


async def test_not_me_link_works_once() -> None:
    world = NotMeWorld()
    await world.disown()

    with pytest.raises(InvalidTokenError):
        await world.disown()

    assert world.uow.stored[world.user.id].credentials_version == 6


async def test_not_me_ignores_the_version_the_token_was_issued_with() -> None:
    world = NotMeWorld(_user(credentials_version=9))

    await world.disown()

    assert world.uow.identities == {}


@pytest.mark.parametrize("token", ["A" * 43, "short"], ids=["unknown", "malformed"])
async def test_not_me_with_an_unknown_token_changes_nothing(token: str) -> None:
    world = NotMeWorld()

    with pytest.raises(InvalidTokenError):
        await world.disown(token)

    assert world.uow.identities == {(world.user.id, GOOGLE): "sub-attacker"}
    assert world.uow.commits == 0


async def test_not_me_does_not_accept_a_token_of_another_purpose() -> None:
    world = NotMeWorld()
    world.tokens.live.clear()
    world.tokens.plant(TokenPurpose.PASSWORD_RESET, NOT_ME_TOKEN, world.user.id, 5)

    with pytest.raises(InvalidTokenError):
        await world.disown()


async def test_not_me_for_a_deleted_account_is_an_invalid_token() -> None:
    world = NotMeWorld()
    del world.uow.stored[world.user.id]

    with pytest.raises(InvalidTokenError):
        await world.disown()

    assert world.uow.commits == 0

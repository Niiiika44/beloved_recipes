import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
import structlog
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from app.modules.identity.domain.oidc import ProviderRejectionReason
from app.modules.identity.infrastructure.exceptions import IdentityProviderUnavailableError
from app.modules.identity.infrastructure.google_oidc_provider import (
    GOOGLE_JWKS_URL,
    GOOGLE_TOKEN_URL,
    GoogleOidcProvider,
    JwksCache,
)
from app.modules.identity.service.dto import OidcIdentityDTO, ProviderRejectionDTO

CLIENT_ID = "client-123.apps.googleusercontent.com"
CLIENT_SECRET = "client-secret-value"
REDIRECT_URI = "https://recipes.example/api/v1/auth/google/callback"
NONCE = "N" * 43

Handler = Callable[[httpx.Request], Awaitable[httpx.Response]]

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(kid: str, key: rsa.RSAPrivateKey = _KEY) -> dict[str, Any]:
    entry = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return entry | {"kid": kid, "alg": "RS256", "use": "sig"}


def _jwks_response(*kids: str, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        json={"keys": [_jwk(kid) for kid in kids]},
        headers={"cache-control": "public, max-age=300"} if headers is None else headers,
    )


class Clock:
    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class Google:
    def __init__(self) -> None:
        self.jwks: list[httpx.Response | Exception] = []
        self.token: httpx.Response | Exception = httpx.Response(500)
        self.requests: list[httpx.Request] = []
        self.delay = 0.0

    def jwks_requests(self) -> int:
        return sum(1 for request in self.requests if str(request.url) == GOOGLE_JWKS_URL)

    async def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        await asyncio.sleep(self.delay)
        if str(request.url) == GOOGLE_JWKS_URL:
            answer = self.jwks.pop(0) if len(self.jwks) > 1 else self.jwks[0]
        else:
            answer = self.token
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture
def google() -> Google:
    return Google()


@pytest.fixture
async def http(google: Google):  # type: ignore[no-untyped-def]
    async with httpx.AsyncClient(transport=httpx.MockTransport(google.handle)) as client:
        yield client


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def cache(http: httpx.AsyncClient, clock: Clock) -> JwksCache:
    return JwksCache(http, timeout_seconds=0.2, now=clock)


@pytest.fixture
def provider(http: httpx.AsyncClient, cache: JwksCache) -> GoogleOidcProvider:
    return GoogleOidcProvider(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
        http=http,
        jwks=cache,
        timeout_seconds=0.2,
    )


async def test_keys_are_fetched_once_while_fresh(
    cache: JwksCache, google: Google, clock: Clock
) -> None:
    google.jwks = [_jwks_response("k1")]

    first = await cache.get("k1")
    clock.advance(299)
    second = await cache.get("k1")

    assert first is not None
    assert first.key_id == "k1"
    assert second is first
    assert google.jwks_requests() == 1


async def test_expired_keys_are_fetched_again(
    cache: JwksCache, google: Google, clock: Clock
) -> None:
    google.jwks = [_jwks_response("k1"), _jwks_response("k2")]
    await cache.get("k1")
    clock.advance(301)

    assert await cache.get("k1") is None
    assert google.jwks_requests() == 2


async def test_freshness_counts_the_age_already_spent_in_caches(
    cache: JwksCache, google: Google, clock: Clock
) -> None:
    google.jwks = [_jwks_response("k1", headers={"cache-control": "max-age=300", "age": "100"})]
    await cache.get("k1")

    clock.advance(199)
    await cache.get("k1")
    assert google.jwks_requests() == 1
    clock.advance(2)
    await cache.get("k1")
    assert google.jwks_requests() == 2


@pytest.mark.parametrize(
    "headers",
    [{}, {"cache-control": "no-transform"}, {"cache-control": "max-age=300", "age": "soon"}],
    ids=["no_cache_control", "no_max_age", "bad_age"],
)
async def test_missing_or_odd_cache_headers_mean_five_minutes(
    cache: JwksCache, google: Google, clock: Clock, headers: dict[str, str]
) -> None:
    google.jwks = [_jwks_response("k1", headers=headers)]
    await cache.get("k1")

    clock.advance(299)
    await cache.get("k1")
    assert google.jwks_requests() == 1
    clock.advance(2)
    await cache.get("k1")
    assert google.jwks_requests() == 2


async def test_rotated_key_is_picked_up_but_not_more_than_once_a_minute(
    cache: JwksCache, google: Google, clock: Clock
) -> None:
    google.jwks = [_jwks_response("k1"), _jwks_response("k1", "k2")]
    await cache.get("k1")

    assert await cache.get("k2") is None
    clock.advance(30)
    assert await cache.get("k2") is None
    assert google.jwks_requests() == 1

    clock.advance(30)
    found = await cache.get("k2")
    assert found is not None
    assert found.key_id == "k2"
    assert google.jwks_requests() == 2


async def test_parallel_requests_share_one_fetch(cache: JwksCache, google: Google) -> None:
    google.jwks = [_jwks_response("k1")]
    google.delay = 0.01

    found = await asyncio.gather(*(cache.get("k1") for _ in range(5)))

    assert all(key is not None and key.key_id == "k1" for key in found)
    assert google.jwks_requests() == 1


@pytest.mark.parametrize(
    "failure",
    [
        httpx.Response(503),
        httpx.Response(500, json={"keys": [_jwk("k1")]}),
        httpx.Response(200, content=b"<html>"),
        httpx.Response(200, json={"keys": []}),
        httpx.Response(200, json={"keys": "k1"}),
        httpx.Response(200, json=["k1"]),
        httpx.ConnectError("refused"),
    ],
    ids=[
        "status",
        "error_with_keys",
        "not_json",
        "no_keys",
        "keys_not_a_list",
        "not_an_object",
        "network",
    ],
)
async def test_without_any_keys_google_failure_is_an_outage(
    cache: JwksCache, google: Google, failure: httpx.Response | Exception
) -> None:
    google.jwks = [failure]

    with pytest.raises(IdentityProviderUnavailableError):
        await cache.get("k1")


async def test_slow_google_is_an_outage(cache: JwksCache, google: Google) -> None:
    google.jwks = [_jwks_response("k1")]
    google.delay = 1.0

    with pytest.raises(IdentityProviderUnavailableError):
        await cache.get("k1")


@pytest.mark.parametrize(
    "failure",
    [httpx.Response(503), httpx.Response(200, json={"keys": []}), httpx.ConnectError("refused")],
    ids=["status", "no_keys", "network"],
)
async def test_known_key_is_served_stale_while_google_fails(
    cache: JwksCache, google: Google, clock: Clock, failure: httpx.Response | Exception
) -> None:
    google.jwks = [_jwks_response("k1"), failure]
    original = await cache.get("k1")
    clock.advance(3600)

    with structlog.testing.capture_logs() as records:
        found = await cache.get("k1")

    assert found is original
    assert records == [{"event": "jwks.stale_keys_served", "kid": "k1", "log_level": "warning"}]


async def test_failed_refresh_is_not_retried_within_a_minute(
    cache: JwksCache, google: Google, clock: Clock
) -> None:
    google.jwks = [_jwks_response("k1"), httpx.Response(503)]
    await cache.get("k1")
    clock.advance(301)
    await cache.get("k1")

    clock.advance(59)
    assert await cache.get("k1") is not None
    assert google.jwks_requests() == 2
    clock.advance(1)
    await cache.get("k1")
    assert google.jwks_requests() == 3


async def test_unknown_key_is_not_served_stale(
    cache: JwksCache, google: Google, clock: Clock
) -> None:
    google.jwks = [_jwks_response("k1"), httpx.Response(503)]
    await cache.get("k1")
    clock.advance(301)

    with pytest.raises(IdentityProviderUnavailableError):
        await cache.get("k2")


async def test_stale_keys_are_served_for_a_day_at_most(
    cache: JwksCache, google: Google, clock: Clock
) -> None:
    google.jwks = [_jwks_response("k1"), httpx.Response(503)]
    await cache.get("k1")
    clock.advance(300 + 86400)
    assert await cache.get("k1") is not None

    clock.advance(61)
    with pytest.raises(IdentityProviderUnavailableError):
        await cache.get("k1")


async def test_stale_day_counts_from_the_end_of_freshness(
    cache: JwksCache, google: Google, clock: Clock
) -> None:
    google.jwks = [
        _jwks_response("k1", headers={"cache-control": "max-age=300", "age": "999999"}),
        httpx.Response(503),
    ]
    await cache.get("k1")
    clock.advance(60)

    assert await cache.get("k1") is not None


async def test_junk_entries_are_skipped(cache: JwksCache, google: Google) -> None:
    google.jwks = [
        httpx.Response(
            200,
            json={
                "keys": [
                    "k0",
                    {"kid": "broken", "kty": "RSA"},
                    {"kid": "alien", "kty": "XYZ"},
                    {"kid": "no-type"},
                    {key: value for key, value in _jwk("x").items() if key != "kid"},
                    _jwk("k1"),
                ]
            },
        )
    ]

    assert await cache.get("k1") is not None
    for kid in ("broken", "alien", "no-type", "x"):
        assert await cache.get(kid) is None


async def test_keys_come_from_the_google_url(cache: JwksCache, google: Google) -> None:
    google.jwks = [_jwks_response("k1")]

    await cache.get("k1")

    [request] = google.requests
    assert request.method == "GET"
    assert str(request.url) == "https://www.googleapis.com/oauth2/v3/certs"


def test_authorization_url_asks_google_for_an_oidc_code_with_pkce(
    provider: GoogleOidcProvider,
) -> None:
    url = provider.authorization_url(state="st/ate", nonce="no&nce", code_challenge="ch=al")

    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == (
        "https://accounts.google.com/o/oauth2/v2/auth"
    )
    assert parse_qs(parts.query, strict_parsing=True) == {
        "response_type": ["code"],
        "client_id": [CLIENT_ID],
        "redirect_uri": [REDIRECT_URI],
        "scope": ["openid email profile"],
        "state": ["st/ate"],
        "nonce": ["no&nce"],
        "code_challenge": ["ch=al"],
        "code_challenge_method": ["S256"],
        "prompt": ["select_account"],
    }
    assert CLIENT_SECRET not in url


def _claims(**overrides: object) -> dict[str, object]:
    now = int(time.time())
    claims: dict[str, object] = {
        "iss": "https://accounts.google.com",
        "aud": CLIENT_ID,
        "sub": "1234567890",
        "email": "anna@example.org",
        "email_verified": True,
        "name": "Anna Google",
        "picture": "https://lh3.googleusercontent.com/a/anna",
        "nonce": NONCE,
        "iat": now,
        "exp": now + 3600,
    }
    return {key: value for key, value in (claims | overrides).items() if value is not None}


def _id_token(
    claims: dict[str, object] | None = None,
    kid: str | None = "k1",
    key: rsa.RSAPrivateKey = _KEY,
) -> str:
    headers = {"kid": kid} if kid is not None else {}
    return jwt.encode(claims or _claims(), key, algorithm="RS256", headers=headers)


def _token_answer(id_token: object) -> httpx.Response:
    return httpx.Response(
        200, json={"access_token": "ya29.x", "id_token": id_token, "token_type": "Bearer"}
    )


async def test_code_is_sent_in_a_form_body_with_the_verifier(
    provider: GoogleOidcProvider, google: Google
) -> None:
    google.jwks = [_jwks_response("k1")]
    google.token = _token_answer(_id_token())

    await provider.exchange_code("4/code", "verifier-value")

    request = google.requests[0]
    assert request.method == "POST"
    assert str(request.url) == GOOGLE_TOKEN_URL
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    assert parse_qs(request.content.decode(), strict_parsing=True) == {
        "grant_type": ["authorization_code"],
        "code": ["4/code"],
        "client_id": [CLIENT_ID],
        "client_secret": [CLIENT_SECRET],
        "redirect_uri": [REDIRECT_URI],
        "code_verifier": ["verifier-value"],
    }


async def test_valid_id_token_becomes_an_identity(
    provider: GoogleOidcProvider, google: Google
) -> None:
    google.jwks = [_jwks_response("k1")]
    google.token = _token_answer(_id_token())

    identity = await provider.exchange_code("4/code", "verifier")

    assert identity == OidcIdentityDTO(
        subject="1234567890",
        email="anna@example.org",
        email_verified=True,
        name="Anna Google",
        picture="https://lh3.googleusercontent.com/a/anna",
        nonce=NONCE,
    )


async def test_both_google_issuer_spellings_are_accepted(
    provider: GoogleOidcProvider, google: Google
) -> None:
    google.jwks = [_jwks_response("k1")]
    google.token = _token_answer(_id_token(_claims(iss="accounts.google.com")))

    identity = await provider.exchange_code("4/code", "verifier")

    assert isinstance(identity, OidcIdentityDTO)


@pytest.mark.parametrize("value", ["true", 1, None])
async def test_email_is_verified_only_by_a_real_true(
    provider: GoogleOidcProvider, google: Google, value: object
) -> None:
    google.jwks = [_jwks_response("k1")]
    google.token = _token_answer(_id_token(_claims(email_verified=value)))

    identity = await provider.exchange_code("4/code", "verifier")

    assert isinstance(identity, OidcIdentityDTO)
    assert identity.email_verified is False


async def test_missing_name_and_picture_are_tolerated(
    provider: GoogleOidcProvider, google: Google
) -> None:
    google.jwks = [_jwks_response("k1")]
    claims = {key: value for key, value in _claims().items() if key not in ("name", "picture")}
    google.token = _token_answer(_id_token(claims))

    identity = await provider.exchange_code("4/code", "verifier")

    assert isinstance(identity, OidcIdentityDTO)
    assert identity.name == ""
    assert identity.picture is None


@pytest.mark.parametrize(
    "name", [42, ["Anna"], {"given": "Anna"}], ids=["number", "list", "object"]
)
async def test_name_that_is_not_a_string_is_dropped(
    provider: GoogleOidcProvider, google: Google, name: object
) -> None:
    google.jwks = [_jwks_response("k1")]
    google.token = _token_answer(_id_token(_claims(name=name)))

    identity = await provider.exchange_code("4/code", "verifier")

    assert isinstance(identity, OidcIdentityDTO)
    assert identity.name == ""


async def test_used_or_expired_code_is_a_rejection(
    provider: GoogleOidcProvider, google: Google
) -> None:
    google.token = httpx.Response(400, json={"error": "invalid_grant", "error_description": "Bad"})

    assert await provider.exchange_code("4/code", "verifier") == ProviderRejectionDTO(
        "invalid_grant"
    )


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (httpx.Response(400, json={"error": "redirect_uri_mismatch"}), "400 redirect_uri_mismatch"),
        (httpx.Response(401, json={"error": "invalid_client"}), "401 invalid_client"),
        (httpx.Response(500, json={"error": {"code": 500}}), "500 without error code"),
        (httpx.Response(503, json={}), "503 without error code"),
        (httpx.Response(200, json={"error": "invalid_grant"}), None),
        (httpx.Response(502, content=b"<html>Bad gateway</html>"), "Google is unavailable"),
        (httpx.Response(200, json=["id_token"]), "Google is unavailable"),
    ],
    ids=[
        "config_400",
        "config_401",
        "error_not_a_string",
        "no_error",
        "ok_without_token",
        "not_json",
        "not_an_object",
    ],
)
async def test_anything_but_a_rejected_code_is_an_outage_with_the_status_in_the_message(
    provider: GoogleOidcProvider, google: Google, answer: httpx.Response, message: str | None
) -> None:
    google.token = answer

    if message is None:
        assert await provider.exchange_code("4/code", "v") == ProviderRejectionDTO("invalid_token")
        return
    with pytest.raises(IdentityProviderUnavailableError) as caught:
        await provider.exchange_code("4/code", "v")

    assert message in str(caught.value)
    assert CLIENT_SECRET not in str(caught.value)
    assert "4/code" not in str(caught.value)


@pytest.mark.parametrize(
    "failure", [httpx.ConnectError("refused"), httpx.ReadTimeout("slow")], ids=["network", "read"]
)
async def test_network_failure_is_an_outage(
    provider: GoogleOidcProvider, google: Google, failure: Exception
) -> None:
    google.token = failure

    with pytest.raises(IdentityProviderUnavailableError):
        await provider.exchange_code("4/code", "verifier")


async def test_slow_token_endpoint_is_cut_by_the_overall_budget(
    provider: GoogleOidcProvider, google: Google
) -> None:
    google.token = _token_answer(_id_token())
    google.delay = 1.0
    started = time.monotonic()

    with pytest.raises(IdentityProviderUnavailableError):
        await provider.exchange_code("4/code", "verifier")

    assert time.monotonic() - started < 0.8


@pytest.mark.parametrize("id_token", [None, 42, ["a"]], ids=["missing", "number", "list"])
async def test_answer_without_an_id_token_string_is_rejected(
    provider: GoogleOidcProvider, google: Google, id_token: object
) -> None:
    google.token = _token_answer(id_token)

    assert await provider.exchange_code("4/code", "verifier") == ProviderRejectionDTO(
        "invalid_token"
    )


def _hs256_token() -> str:
    return jwt.encode(_claims(), "x" * 32, algorithm="HS256", headers={"kid": "k1"})


def _none_token() -> str:
    header = jwt.utils.base64url_encode(b'{"alg":"none","kid":"k1"}').decode()
    payload = jwt.utils.base64url_encode(json.dumps(_claims()).encode()).decode()
    return f"{header}.{payload}."


def _signed_junk_token() -> str:
    return jwt.api_jws.encode(b"not json", _KEY, algorithm="RS256", headers={"kid": "k1"})


def _tampered_token() -> str:
    header, _, signature = _id_token().split(".")
    payload = jwt.utils.base64url_encode(json.dumps(_claims(sub="666")).encode()).decode()
    return f"{header}.{payload}.{signature}"


@pytest.mark.parametrize(
    ("id_token", "reason"),
    [
        (lambda: _id_token(key=_OTHER_KEY), "bad_signature"),
        (_tampered_token, "bad_signature"),
        (lambda: _id_token(_claims(aud="someone-else")), "wrong_audience"),
        (lambda: _id_token(_claims(iss="https://evil.example")), "wrong_issuer"),
        (lambda: _id_token(_claims(exp=int(time.time()) - 120)), "expired"),
        (lambda: _id_token(_claims(nonce=None)), "missing_claim"),
        (lambda: _id_token(_claims(email=None)), "missing_claim"),
        (lambda: _id_token(_claims(sub=None)), "missing_claim"),
        (lambda: _id_token(_claims(iat=None)), "missing_claim"),
        (lambda: _id_token(_claims(exp=None)), "missing_claim"),
        (lambda: _id_token(kid="k-unknown"), "unknown_key"),
        (lambda: _id_token(kid=None), "unknown_key"),
        (_hs256_token, "invalid_token"),
        (_none_token, "invalid_token"),
        (_signed_junk_token, "invalid_token"),
        (lambda: _id_token(_claims(iat=int(time.time()) + 3600)), "invalid_token"),
        (lambda: _id_token(_claims(nbf=int(time.time()) + 3600)), "invalid_token"),
        (lambda: "not-a-jwt", "invalid_token"),
        (lambda: "a.b.c", "invalid_token"),
    ],
    ids=[
        "foreign_key",
        "tampered_payload",
        "audience",
        "issuer",
        "expired",
        "no_nonce",
        "no_email",
        "no_sub",
        "no_iat",
        "no_exp",
        "unknown_kid",
        "no_kid",
        "hs256",
        "alg_none",
        "payload_not_json",
        "issued_in_future",
        "not_yet_valid",
        "garbage",
        "bad_segments",
    ],
)
async def test_untrustworthy_id_token_is_rejected_with_a_reason(
    provider: GoogleOidcProvider,
    google: Google,
    id_token: Callable[[], str],
    reason: ProviderRejectionReason,
) -> None:
    google.jwks = [_jwks_response("k1")]
    google.token = _token_answer(id_token())

    assert await provider.exchange_code("4/code", "verifier") == ProviderRejectionDTO(reason)


async def test_small_clock_skew_is_tolerated(provider: GoogleOidcProvider, google: Google) -> None:
    google.jwks = [_jwks_response("k1")]
    now = int(time.time())
    google.token = _token_answer(_id_token(_claims(exp=now - 30, iat=now + 30)))

    assert isinstance(await provider.exchange_code("4/code", "verifier"), OidcIdentityDTO)


async def test_key_outage_during_verification_is_an_outage_not_a_rejection(
    provider: GoogleOidcProvider, google: Google
) -> None:
    google.jwks = [httpx.Response(503)]
    google.token = _token_answer(_id_token())

    with pytest.raises(IdentityProviderUnavailableError):
        await provider.exchange_code("4/code", "verifier")

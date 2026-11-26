import asyncio
import re
import time
from collections.abc import Callable
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
import structlog

from app.modules.identity.infrastructure.exceptions import IdentityProviderUnavailableError
from app.modules.identity.service.dto import OidcIdentityDTO, ProviderRejectionDTO

GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")
GOOGLE_TIMEOUT_SECONDS = 5.0
CLOCK_SKEW_SECONDS = 60
JWKS_MIN_REFRESH_INTERVAL = timedelta(minutes=1)
JWKS_STALE_MAX = timedelta(days=1)
JWKS_DEFAULT_MAX_AGE = timedelta(minutes=5)
MAX_AGE_PATTERN = re.compile(r"max-age=(\d+)")

logger = structlog.get_logger(__name__)


class JwksCache:
    def __init__(
        self,
        http: httpx.AsyncClient,
        url: str = GOOGLE_JWKS_URL,
        timeout_seconds: float = GOOGLE_TIMEOUT_SECONDS,
        now: Callable[[], float] = time.monotonic,
    ):
        self._http = http
        self._url = url
        self._timeout_seconds = timeout_seconds
        self._now = now
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fresh_until = 0.0
        self._last_attempt: float | None = None
        self._lock = asyncio.Lock()

    async def get(self, kid: str) -> jwt.PyJWK | None:
        if self._fresh() and kid in self._keys:
            return self._keys[kid]
        async with self._lock:
            if self._fresh() and kid in self._keys:
                return self._keys[kid]
            if self._refresh_allowed():
                try:
                    await self._refresh()
                except IdentityProviderUnavailableError:
                    return self._stale(kid)
                return self._keys.get(kid)
            if self._fresh():
                return None
            return self._stale(kid)

    def _fresh(self) -> bool:
        return self._now() < self._fresh_until

    def _refresh_allowed(self) -> bool:
        if self._last_attempt is None:
            return True
        return self._now() - self._last_attempt >= JWKS_MIN_REFRESH_INTERVAL.total_seconds()

    def _stale(self, kid: str) -> jwt.PyJWK:
        key = self._keys.get(kid)
        if key is None or self._now() - self._fresh_until > JWKS_STALE_MAX.total_seconds():
            raise IdentityProviderUnavailableError("Google keys are unavailable")
        logger.warning("jwks.stale_keys_served", kid=kid)
        return key

    async def _refresh(self) -> None:
        started = self._now()
        self._last_attempt = started
        try:
            async with asyncio.timeout(self._timeout_seconds):
                response = await self._http.get(self._url)
        except (TimeoutError, httpx.HTTPError) as exc:
            raise IdentityProviderUnavailableError("Google keys are unavailable") from exc
        if response.status_code != httpx.codes.OK:
            raise IdentityProviderUnavailableError("Google keys are unavailable")
        keys = _parse_keys(response)
        if not keys:
            raise IdentityProviderUnavailableError("Google keys are unavailable")
        self._keys = keys
        self._fresh_until = started + _lifetime_seconds(response.headers)


def _parse_keys(response: httpx.Response) -> dict[str, jwt.PyJWK]:
    try:
        entries = response.json()["keys"]
    except ValueError, KeyError, TypeError:
        return {}
    if not isinstance(entries, list):
        return {}
    keys: dict[str, jwt.PyJWK] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        try:
            key = jwt.PyJWK.from_dict(entry)
        except jwt.PyJWTError, KeyError:
            continue
        if key.key_id is not None:
            keys[key.key_id] = key
    return keys


def _lifetime_seconds(headers: httpx.Headers) -> float:
    found = MAX_AGE_PATTERN.search(headers.get("cache-control", ""))
    if found is None:
        return JWKS_DEFAULT_MAX_AGE.total_seconds()
    age = headers.get("age", "0")
    already_cached = int(age) if age.isdigit() else 0
    return max(int(found.group(1)) - already_cached, 0)


class GoogleOidcProvider:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        http: httpx.AsyncClient,
        jwks: JwksCache,
        timeout_seconds: float = GOOGLE_TIMEOUT_SECONDS,
    ):
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._http = http
        self._jwks = jwks
        self._timeout_seconds = timeout_seconds

    def authorization_url(self, state: str, nonce: str, code_challenge: str) -> str:
        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
        return f"{GOOGLE_AUTHORIZE_URL}?{urlencode(params)}"

    async def exchange_code(
        self, code: str, code_verifier: str
    ) -> OidcIdentityDTO | ProviderRejectionDTO:
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "redirect_uri": self._redirect_uri,
            "code_verifier": code_verifier,
        }
        try:
            async with asyncio.timeout(self._timeout_seconds):
                response = await self._http.post(GOOGLE_TOKEN_URL, data=form)
        except (TimeoutError, httpx.HTTPError) as exc:
            raise IdentityProviderUnavailableError("Google is unavailable") from exc
        try:
            payload = response.json()
        except ValueError as exc:
            raise IdentityProviderUnavailableError("Google is unavailable") from exc
        if not isinstance(payload, dict):
            raise IdentityProviderUnavailableError("Google is unavailable")
        if (
            response.status_code == httpx.codes.BAD_REQUEST
            and payload.get("error") == "invalid_grant"
        ):
            return ProviderRejectionDTO(reason="invalid_grant")
        if response.status_code != httpx.codes.OK:
            oauth_error = payload.get("error")
            raise IdentityProviderUnavailableError(
                f"Google token endpoint answered {response.status_code}"
                f" {oauth_error if isinstance(oauth_error, str) else 'without error code'}"
            )
        id_token = payload.get("id_token")
        if not isinstance(id_token, str):
            return ProviderRejectionDTO("invalid_token")
        claims = await self._verify(id_token)
        if isinstance(claims, ProviderRejectionDTO):
            return claims
        return OidcIdentityDTO(
            subject=claims["sub"],
            email=claims["email"],
            email_verified=claims.get("email_verified") is True,
            name=claims.get("name") or claims["email"],
            picture=claims.get("picture"),
            nonce=claims["nonce"],
        )

    async def _verify(self, id_token: str) -> dict[str, Any] | ProviderRejectionDTO:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError:
            return ProviderRejectionDTO("invalid_token")
        kid = header.get("kid")
        key = await self._jwks.get(kid) if isinstance(kid, str) else None
        if key is None:
            return ProviderRejectionDTO("unknown_key")
        try:
            return jwt.decode(
                id_token,
                key,
                algorithms=["RS256"],
                audience=self._client_id,
                issuer=GOOGLE_ISSUERS,
                leeway=CLOCK_SKEW_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "email", "nonce"]},
            )
        except jwt.InvalidSignatureError:
            return ProviderRejectionDTO("bad_signature")
        except jwt.InvalidAudienceError:
            return ProviderRejectionDTO("wrong_audience")
        except jwt.InvalidIssuerError:
            return ProviderRejectionDTO("wrong_issuer")
        except jwt.ExpiredSignatureError:
            return ProviderRejectionDTO("expired")
        except jwt.MissingRequiredClaimError:
            return ProviderRejectionDTO("missing_claim")
        except jwt.InvalidAlgorithmError, jwt.DecodeError, jwt.PyJWTError:
            return ProviderRejectionDTO("invalid_token")

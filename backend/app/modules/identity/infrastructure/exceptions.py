from app.core.exceptions import DependencyUnavailableError


class SessionStoreUnavailableError(DependencyUnavailableError):
    pass


class RateLimiterUnavailableError(DependencyUnavailableError):
    pass


class OneTimeTokenStoreUnavailableError(DependencyUnavailableError):
    pass


class IdentityProviderUnavailableError(DependencyUnavailableError):
    pass


class LoginStateStoreUnavailableError(DependencyUnavailableError):
    pass

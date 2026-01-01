"""
HTTP Policy Authorization Profile

Provides the 'policy-http' authorization profile for loading policies over HTTP(S).
This profile is similar to 'policy-localfile' from the runtime package but uses
the HttpAuthorizationPolicySource instead of LocalFileAuthorizationPolicySource.
"""

from naylence.fame.factory import Expressions
from naylence.fame.profile import RegisterProfileOptions, register_profile
from naylence.fame.security.auth.authorization_profile_factory import (
    AUTHORIZER_FACTORY_BASE_TYPE,
)

# Environment variable names for HTTP policy source
ENV_VAR_AUTH_POLICY_URL = "FAME_AUTH_POLICY_URL"
ENV_VAR_AUTH_POLICY_TIMEOUT_MS = "FAME_AUTH_POLICY_TIMEOUT_MS"
ENV_VAR_AUTH_POLICY_CACHE_TTL_MS = "FAME_AUTH_POLICY_CACHE_TTL_MS"
ENV_VAR_AUTH_POLICY_TOKEN_URL = "FAME_AUTH_POLICY_TOKEN_URL"
ENV_VAR_AUTH_POLICY_CLIENT_ID = "FAME_AUTH_POLICY_CLIENT_ID"
ENV_VAR_AUTH_POLICY_CLIENT_SECRET = "FAME_AUTH_POLICY_CLIENT_SECRET"
ENV_VAR_AUTH_POLICY_AUDIENCE = "FAME_AUTH_POLICY_AUDIENCE"

# Legacy environment variable for backwards compatibility
ENV_VAR_AUTH_POLICY_BEARER_TOKEN = "FAME_AUTH_POLICY_BEARER_TOKEN"

# Re-use JWT verifier env vars from runtime
ENV_VAR_JWKS_URL = "FAME_JWKS_URL"
ENV_VAR_JWT_TRUSTED_ISSUER = "FAME_JWT_TRUSTED_ISSUER"

# Profile name constant
PROFILE_NAME_POLICY_HTTP = "policy-http"

# Default token verifier configuration using JWKS
DEFAULT_VERIFIER_CONFIG = {
    "type": "JWKSJWTTokenVerifier",
    "jwks_url": Expressions.env(ENV_VAR_JWKS_URL),
    "issuer": Expressions.env(ENV_VAR_JWT_TRUSTED_ISSUER),
}


def _create_oauth2_token_provider_config():
    """
    Creates OAuth2 token provider configuration for HTTP policy source.

    Uses environment variables for OAuth2 client credentials flow.
    """
    token_url = Expressions.env(ENV_VAR_AUTH_POLICY_TOKEN_URL)
    client_id = Expressions.env(ENV_VAR_AUTH_POLICY_CLIENT_ID)
    client_secret = Expressions.env(ENV_VAR_AUTH_POLICY_CLIENT_SECRET)
    audience = Expressions.env(ENV_VAR_AUTH_POLICY_AUDIENCE)

    return {
        "type": "OAuth2ClientCredentialsTokenProvider",
        "token_url": token_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": ["policy.read"],
        "audience": audience,
    }


# Default HTTP policy source configuration
# Uses environment variables for URL, timeout, and OAuth2 client credentials.
DEFAULT_HTTP_POLICY_SOURCE = {
    "type": "HttpAuthorizationPolicySource",
    "url": Expressions.env(ENV_VAR_AUTH_POLICY_URL),
    "timeout_ms": Expressions.env(ENV_VAR_AUTH_POLICY_TIMEOUT_MS, "30000"),
    "cache_ttl_ms": Expressions.env(ENV_VAR_AUTH_POLICY_CACHE_TTL_MS, "300000"),
    # OAuth2 client credentials token provider
    "token_provider": _create_oauth2_token_provider_config(),
}

# PolicyAuthorizer configuration using HTTP policy source
POLICY_HTTP_PROFILE = {
    "type": "PolicyAuthorizer",
    "verifier": DEFAULT_VERIFIER_CONFIG,
    "policy_source": DEFAULT_HTTP_POLICY_SOURCE,
}

_registered = False


def register_policy_http_profile() -> None:
    """Register the policy-http profile in the profile registry.

    This function is idempotent - it will only register the profile once.
    Call this function to make the policy-http profile available for use.
    """
    global _registered
    if _registered:
        return

    register_profile(
        AUTHORIZER_FACTORY_BASE_TYPE,
        PROFILE_NAME_POLICY_HTTP,
        POLICY_HTTP_PROFILE,
        RegisterProfileOptions(
            source="advanced-security:policy-http-authorization-profile",
            allow_override=True,
        ),
    )
    _registered = True


# Auto-register when module is imported (side-effect import pattern)
register_policy_http_profile()

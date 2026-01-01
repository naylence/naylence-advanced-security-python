"""
Factory for creating HttpAuthorizationPolicySource instances.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import ConfigDict

from naylence.fame.security.auth.policy.authorization_policy_factory import (
    AuthorizationPolicyConfig,
)
from naylence.fame.security.auth.policy.authorization_policy_source import (
    AuthorizationPolicySource,
)
from naylence.fame.security.auth.policy.authorization_policy_source_factory import (
    AUTHORIZATION_POLICY_SOURCE_FACTORY_BASE_TYPE,
    AuthorizationPolicySourceConfig,
    AuthorizationPolicySourceFactory,
)
from naylence.fame.security.auth.token_provider import TokenProvider
from naylence.fame.security.auth.token_provider_factory import (
    TokenProviderConfig,
    TokenProviderFactory,
)


class HttpAuthorizationPolicySourceConfig(AuthorizationPolicySourceConfig):
    """
    Configuration for HttpAuthorizationPolicySource.

    Supports both camelCase and snake_case property names for flexibility.
    """

    model_config = ConfigDict(extra="allow")

    type: str = "HttpAuthorizationPolicySource"

    # The URL to fetch the policy from (required)
    url: str

    # HTTP method to use
    method: Literal["GET", "POST", "PUT"] = "GET"

    # Request timeout in milliseconds
    timeout_ms: Optional[int] = None

    # Additional headers to include in the request
    headers: Optional[dict[str, str]] = None

    # Token provider configuration for bearer authentication
    token_provider: Optional[TokenProviderConfig | dict[str, Any]] = None

    # Prefix for the Authorization header
    bearer_prefix: Optional[str] = None

    # Configuration for the policy factory to use when parsing the loaded data
    policy_factory: Optional[AuthorizationPolicyConfig | dict[str, Any]] = None

    # Polling interval in milliseconds (reserved for future use)
    poll_interval_ms: Optional[int] = None

    # Fallback cache TTL in milliseconds when server provides no caching headers
    cache_ttl_ms: Optional[int] = None


def _normalize_config(
    config: HttpAuthorizationPolicySourceConfig | dict[str, Any] | None,
) -> dict[str, Any]:
    """Normalize and validate configuration."""
    if not config:
        raise ValueError(
            "HttpAuthorizationPolicySourceFactory requires a configuration with a url"
        )

    if isinstance(config, HttpAuthorizationPolicySourceConfig):
        candidate = config.model_dump()
    else:
        candidate = dict(config)

    # URL is required
    url = candidate.get("url")
    if not isinstance(url, str) or not url.strip():
        raise ValueError("HttpAuthorizationPolicySourceConfig requires a non-empty url")

    # Support both camelCase and snake_case
    method = candidate.get("method", "GET")
    if method not in ("GET", "POST", "PUT"):
        raise ValueError(f'Invalid method "{method}". Must be "GET", "POST", or "PUT"')

    timeout_ms = candidate.get("timeout_ms") or candidate.get("timeoutMs") or 30000
    if not isinstance(timeout_ms, int | float) or timeout_ms <= 0:
        raise ValueError("timeout_ms must be a positive number")

    headers = candidate.get("headers")
    if headers is not None and not isinstance(headers, dict):
        raise ValueError("headers must be an object")

    token_provider_config = candidate.get("token_provider") or candidate.get("tokenProvider")

    bearer_prefix = (
        candidate.get("bearer_prefix") or candidate.get("bearerPrefix") or "Bearer "
    )

    policy_factory = candidate.get("policy_factory") or candidate.get("policyFactory")

    cache_ttl_ms = candidate.get("cache_ttl_ms") or candidate.get("cacheTtlMs") or 300000
    if not isinstance(cache_ttl_ms, int | float) or cache_ttl_ms < 0:
        raise ValueError("cache_ttl_ms must be a non-negative number")

    return {
        "url": url.strip(),
        "method": method,
        "timeout_ms": int(timeout_ms),
        "headers": headers,
        "token_provider_config": token_provider_config,
        "bearer_prefix": bearer_prefix,
        "policy_factory": policy_factory,
        "cache_ttl_ms": int(cache_ttl_ms),
    }


# Factory metadata for registration
FACTORY_META = {
    "base": AUTHORIZATION_POLICY_SOURCE_FACTORY_BASE_TYPE,
    "key": "HttpAuthorizationPolicySource",
}


class HttpAuthorizationPolicySourceFactory(
    AuthorizationPolicySourceFactory[HttpAuthorizationPolicySourceConfig]
):
    """
    Factory for creating HttpAuthorizationPolicySource instances.
    """

    type: str = "HttpAuthorizationPolicySource"

    async def create(
        self,
        config: HttpAuthorizationPolicySourceConfig | dict[str, Any] | None = None,
        **factory_args: Any,
    ) -> AuthorizationPolicySource:
        """
        Creates an HttpAuthorizationPolicySource from the given configuration.

        Args:
            config: Configuration specifying the policy URL and options
            **factory_args: Additional factory arguments (unused)

        Returns:
            The created policy source
        """
        normalized = _normalize_config(config)

        # Create token provider if configured
        token_provider: Optional[TokenProvider] = None
        if normalized["token_provider_config"]:
            token_provider = await TokenProviderFactory.create_token_provider(
                normalized["token_provider_config"]
            )

        from naylence.fame.security.auth.policy.http_authorization_policy_source import (
            HttpAuthorizationPolicySource,
            HttpAuthorizationPolicySourceOptions,
        )

        options = HttpAuthorizationPolicySourceOptions(
            url=normalized["url"],
            method=normalized["method"],
            timeout_ms=normalized["timeout_ms"],
            headers=normalized["headers"],
            token_provider=token_provider,
            bearer_prefix=normalized["bearer_prefix"],
            policy_factory=normalized["policy_factory"],
            cache_ttl_ms=normalized["cache_ttl_ms"],
        )

        return HttpAuthorizationPolicySource(options)

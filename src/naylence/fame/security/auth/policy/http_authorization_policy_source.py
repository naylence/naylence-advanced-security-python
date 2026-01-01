"""
HTTP-based authorization policy source.

Loads authorization policies from an HTTP endpoint supporting JSON or YAML.
Supports bearer authentication via TokenProvider and HTTP caching via ETag.

This is a server-side only implementation.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Literal, Optional

import yaml

from naylence.fame.security.auth.policy.authorization_policy import (
    AuthorizationPolicy,
)
from naylence.fame.security.auth.policy.authorization_policy_factory import (
    AuthorizationPolicyConfig,
    AuthorizationPolicyFactory,
)
from naylence.fame.security.auth.policy.authorization_policy_source import (
    AuthorizationPolicySource,
)
from naylence.fame.security.auth.token_provider import TokenProvider

logger = logging.getLogger(
    "naylence.fame.security.auth.policy.http_authorization_policy_source"
)

# HTTP method for the policy request
HttpMethod = Literal["GET", "POST", "PUT"]


@dataclass
class HttpPolicySourceMetadata:
    """
    Metadata about the last fetch operation.

    Useful for verification, debugging, and monitoring.
    """

    # The URL from which the policy was fetched
    url: str

    # HTTP status code of the last successful fetch
    status: int

    # Timestamp when the policy was last fetched (milliseconds since epoch)
    fetched_at: int

    # ETag from the last successful response
    etag: Optional[str] = None

    # Cache-Control max-age value in seconds, if present
    max_age_seconds: Optional[int] = None

    # Computed expiration time based on max-age (milliseconds since epoch)
    expires_at: Optional[int] = None


@dataclass
class HttpAuthorizationPolicySourceOptions:
    """Configuration options for HttpAuthorizationPolicySource."""

    # The URL to fetch the policy from
    url: str

    # HTTP method to use
    method: HttpMethod = "GET"

    # Request timeout in milliseconds
    timeout_ms: int = 30000

    # Additional headers to include in the request
    headers: Optional[dict[str, str]] = None

    # Token provider for bearer authentication
    token_provider: Optional[TokenProvider] = None

    # Prefix for the Authorization header
    bearer_prefix: str = "Bearer "

    # Configuration for the policy factory to use when parsing the loaded data
    policy_factory: Optional[AuthorizationPolicyConfig | dict[str, Any]] = None

    # Fallback cache TTL in milliseconds when server provides no caching headers
    cache_ttl_ms: int = 300000  # 5 minutes default


@dataclass
class _CachedPolicyState:
    """Cached policy state."""

    policy: AuthorizationPolicy
    metadata: HttpPolicySourceMetadata
    raw_definition: dict[str, Any]


def _is_plain_object(value: Any) -> bool:
    """Check if value is a plain dict-like object."""
    return bool(value) and isinstance(value, dict)


def _parse_json(content: str) -> dict[str, Any]:
    """Parse JSON content as a policy object."""
    parsed = json.loads(content)
    if not _is_plain_object(parsed):
        raise ValueError("Parsed JSON policy must be an object")
    return parsed


def _parse_yaml(content: str) -> dict[str, Any]:
    """Parse YAML content as a policy object."""
    parsed = yaml.safe_load(content or "")
    if parsed is None:
        return {}
    if not _is_plain_object(parsed):
        raise ValueError("Parsed YAML policy must be an object")
    return parsed


def _detect_format(content_type: Optional[str], content: str) -> Literal["json", "yaml"]:
    """
    Detect whether content is JSON or YAML based on Content-Type header.
    Falls back to sniffing the content if Content-Type is not definitive.
    """
    if content_type:
        lower = content_type.lower()
        if "application/json" in lower or "text/json" in lower:
            return "json"
        if any(
            x in lower
            for x in [
                "application/yaml",
                "application/x-yaml",
                "text/yaml",
                "text/x-yaml",
            ]
        ):
            return "yaml"

    # Sniff by first non-whitespace character
    trimmed = content.lstrip()
    if trimmed.startswith("{") or trimmed.startswith("["):
        return "json"

    # Default to YAML
    return "yaml"


def _parse_max_age(cache_control: Optional[str]) -> Optional[int]:
    """Parse Cache-Control header to extract max-age value."""
    if not cache_control:
        return None

    match = re.search(r"max-age\s*=\s*(\d+)", cache_control, re.IGNORECASE)
    if match:
        seconds = int(match.group(1))
        if seconds >= 0:
            return seconds

    return None


def _now_ms() -> int:
    """Get current time in milliseconds since epoch."""
    return int(time.time() * 1000)


class HttpAuthorizationPolicySource(AuthorizationPolicySource):
    """
    An authorization policy source that loads policy definitions from an HTTP endpoint.

    Supports JSON and YAML formats, bearer authentication via TokenProvider,
    and HTTP caching via ETag and Cache-Control headers.

    This is a server-side only implementation that uses aiohttp or httpx.
    """

    def __init__(self, options: HttpAuthorizationPolicySourceOptions) -> None:
        if not options.url or not isinstance(options.url, str):
            raise ValueError("HttpAuthorizationPolicySource requires a valid URL")

        self._url = options.url
        self._method = options.method
        self._timeout_ms = options.timeout_ms
        self._headers = dict(options.headers) if options.headers else {}
        self._token_provider = options.token_provider
        self._bearer_prefix = options.bearer_prefix
        self._policy_factory_config = options.policy_factory
        self._cache_ttl_ms = options.cache_ttl_ms

        self._cached_state: Optional[_CachedPolicyState] = None
        self._inflight_fetch: Optional[asyncio.Task[AuthorizationPolicy]] = None
        self._inflight_lock = asyncio.Lock()

    async def load_policy(self) -> AuthorizationPolicy:
        """
        Loads the authorization policy from the configured HTTP endpoint.

        Returns a cached policy if still fresh (based on TTL or cache headers).
        Multiple concurrent calls are de-duplicated (single-flight pattern).

        Returns:
            The loaded authorization policy
        """
        # Return cached policy if still fresh
        if self._cached_state and self._is_cache_fresh():
            logger.debug(
                "returning_cached_policy",
                extra={
                    "url": self._url,
                    "fetched_at": self._cached_state.metadata.fetched_at,
                    "expires_at": self._cached_state.metadata.expires_at,
                },
            )
            return self._cached_state.policy

        # De-duplicate concurrent requests
        async with self._inflight_lock:
            # Check again after acquiring lock
            if self._cached_state and self._is_cache_fresh():
                return self._cached_state.policy

            if self._inflight_fetch is not None:
                # Wait for existing fetch to complete
                return await self._inflight_fetch

            # Start new fetch
            self._inflight_fetch = asyncio.create_task(self._fetch_policy(False))

        try:
            return await self._inflight_fetch
        finally:
            async with self._inflight_lock:
                self._inflight_fetch = None

    async def reload_policy(self) -> AuthorizationPolicy:
        """
        Forces a reload of the policy from the HTTP endpoint.

        Bypasses cache freshness checks and always fetches from the server.
        If the fetch fails, the existing cached policy is preserved and the error is thrown.

        Returns:
            The reloaded authorization policy
        """
        async with self._inflight_lock:
            self._inflight_fetch = None

        return await self._fetch_policy(True)

    def clear_cache(self) -> None:
        """Clears the cached policy, forcing a fresh fetch on the next load_policy() call."""
        self._cached_state = None

    def get_metadata(self) -> Optional[HttpPolicySourceMetadata]:
        """
        Returns metadata about the last successful fetch.

        Useful for verification, monitoring, or debugging.
        """
        return self._cached_state.metadata if self._cached_state else None

    def get_raw_definition(self) -> Optional[dict[str, Any]]:
        """
        Returns the raw policy definition from the last successful fetch.

        Useful for verification or reprocessing.
        """
        return self._cached_state.raw_definition if self._cached_state else None

    def _is_cache_fresh(self) -> bool:
        """Check if cached policy is still fresh."""
        if not self._cached_state:
            return False

        now = _now_ms()
        expires_at = self._cached_state.metadata.expires_at

        if expires_at is not None:
            return now < expires_at

        # No expiration info, check against default TTL
        fetched_at = self._cached_state.metadata.fetched_at
        return now < fetched_at + self._cache_ttl_ms

    async def _fetch_policy(self, force_refresh: bool) -> AuthorizationPolicy:
        """Fetch policy from HTTP endpoint."""
        logger.debug(
            "fetching_policy",
            extra={
                "url": self._url,
                "method": self._method,
                "force_refresh": force_refresh,
            },
        )

        request_headers: dict[str, str] = {
            "Accept": "application/json, application/yaml, text/yaml, */*",
            **self._headers,
        }

        # Add bearer token if token provider is configured
        if self._token_provider:
            try:
                token = await self._token_provider.get_token()
                if token and token.value:
                    request_headers["Authorization"] = f"{self._bearer_prefix}{token.value}"
                    logger.debug("added_bearer_token", extra={"url": self._url})
            except Exception as error:
                logger.warning(
                    "token_provider_failed",
                    extra={
                        "url": self._url,
                        "error": str(error),
                    },
                )
                # Continue without token - let the server decide if auth is required

        # Add If-None-Match header for conditional request if we have a cached ETag
        # and this is not a forced refresh
        if not force_refresh and self._cached_state and self._cached_state.metadata.etag:
            request_headers["If-None-Match"] = self._cached_state.metadata.etag

        timeout_seconds = self._timeout_ms / 1000

        try:
            # Use aiohttp for async HTTP requests
            import aiohttp

            timeout = aiohttp.ClientTimeout(total=timeout_seconds)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.request(
                    self._method,
                    self._url,
                    headers=request_headers,
                ) as response:
                    return await self._handle_response(response, force_refresh)

        except asyncio.TimeoutError:
            timeout_error = TimeoutError(
                f"Request to {self._url} timed out after {self._timeout_ms}ms"
            )
            logger.error(
                "policy_fetch_timeout",
                extra={
                    "url": self._url,
                    "timeout_ms": self._timeout_ms,
                },
            )
            raise timeout_error

        except Exception as error:
            # Re-raise with context
            raise error

    async def _handle_response(
        self,
        response: Any,  # aiohttp.ClientResponse
        force_refresh: bool,
    ) -> AuthorizationPolicy:
        """Handle HTTP response."""
        import aiohttp

        # Handle 304 Not Modified - return cached policy
        if response.status == 304 and self._cached_state:
            logger.debug(
                "policy_not_modified",
                extra={
                    "url": self._url,
                    "etag": self._cached_state.metadata.etag,
                },
            )

            # Update freshness timestamps
            now = _now_ms()
            cache_control = response.headers.get("Cache-Control")
            max_age_seconds = _parse_max_age(cache_control)
            expires_at = (
                now + max_age_seconds * 1000
                if max_age_seconds is not None
                else now + self._cache_ttl_ms
            )

            self._cached_state = _CachedPolicyState(
                policy=self._cached_state.policy,
                raw_definition=self._cached_state.raw_definition,
                metadata=HttpPolicySourceMetadata(
                    url=self._cached_state.metadata.url,
                    status=self._cached_state.metadata.status,
                    etag=self._cached_state.metadata.etag,
                    fetched_at=now,
                    max_age_seconds=max_age_seconds,
                    expires_at=expires_at,
                ),
            )

            return self._cached_state.policy

        if not response.ok:
            error_message = f"HTTP {response.status}: {response.reason}"
            logger.error(
                "policy_fetch_failed",
                extra={
                    "url": self._url,
                    "status": response.status,
                    "reason": response.reason,
                },
            )

            # If we have a cached policy, preserve it and throw
            if self._cached_state:
                raise aiohttp.ClientResponseError(
                    response.request_info,
                    response.history,
                    status=response.status,
                    message=(
                        f"Failed to fetch policy from {self._url}: {error_message}. "
                        "Using last known good policy."
                    ),
                )

            raise aiohttp.ClientResponseError(
                response.request_info,
                response.history,
                status=response.status,
                message=f"Failed to fetch policy from {self._url}: {error_message}",
            )

        # Parse the response
        content_type = response.headers.get("Content-Type")
        content = await response.text()
        detected_format = _detect_format(content_type, content)

        try:
            if detected_format == "json":
                policy_definition = _parse_json(content)
            else:
                policy_definition = _parse_yaml(content)
        except Exception as parse_error:
            message = str(parse_error)
            logger.error(
                "policy_parse_failed",
                extra={
                    "url": self._url,
                    "format": detected_format,
                    "error": message,
                },
            )

            # Preserve cached policy on parse failure
            if self._cached_state:
                raise ValueError(
                    f"Failed to parse policy from {self._url}: {message}. "
                    "Using last known good policy."
                )

            raise ValueError(f"Failed to parse policy from {self._url}: {message}")

        logger.debug(
            "parsed_policy_definition",
            extra={
                "url": self._url,
                "format": detected_format,
                "has_type": "type" in policy_definition,
            },
        )

        # Build the policy using the factory
        policy = await self._build_policy(policy_definition)

        # Update cache
        now = _now_ms()
        etag = response.headers.get("ETag")
        cache_control = response.headers.get("Cache-Control")
        max_age_seconds = _parse_max_age(cache_control)
        expires_at = (
            now + max_age_seconds * 1000
            if max_age_seconds is not None
            else now + self._cache_ttl_ms
        )

        self._cached_state = _CachedPolicyState(
            policy=policy,
            raw_definition=policy_definition,
            metadata=HttpPolicySourceMetadata(
                url=self._url,
                status=response.status,
                etag=etag,
                fetched_at=now,
                max_age_seconds=max_age_seconds,
                expires_at=expires_at,
            ),
        )

        logger.info(
            "loaded_policy_from_http",
            extra={
                "url": self._url,
                "status": response.status,
                "format": detected_format,
                "etag": etag,
                "max_age_seconds": max_age_seconds,
            },
        )

        return policy

    async def _build_policy(
        self,
        policy_definition: dict[str, Any],
    ) -> AuthorizationPolicy:
        """Build an AuthorizationPolicy from the parsed definition."""
        # Determine the factory configuration to use
        factory_config: dict[str, Any] = (
            dict(self._policy_factory_config)
            if isinstance(self._policy_factory_config, dict)
            else (
                self._policy_factory_config.model_dump()
                if self._policy_factory_config is not None
                else dict(policy_definition)
            )
        )

        # Ensure we have a type field for the factory
        if "type" not in factory_config or not isinstance(factory_config.get("type"), str):
            logger.warning(
                "policy_type_missing_defaulting_to_basic",
                extra={"url": self._url},
            )
            factory_config["type"] = "BasicAuthorizationPolicy"

        # Build the factory config with the policy definition
        # The response content IS the policy definition, so we extract the type
        # and wrap the remaining content as the policyDefinition
        definition_type = policy_definition.get("type")
        rest_of_definition = {k: v for k, v in policy_definition.items() if k != "type"}

        resolved_type = (
            definition_type
            if isinstance(definition_type, str) and definition_type.strip()
            else factory_config.get("type")
        )

        if self._policy_factory_config is not None:
            merged_config = {
                **factory_config,
                "policyDefinition": policy_definition,
            }
        else:
            merged_config = {
                "type": resolved_type,
                "policyDefinition": rest_of_definition,
            }

        policy = await AuthorizationPolicyFactory.create_authorization_policy(merged_config)

        if not policy:
            raise ValueError(f"Failed to create authorization policy from {self._url}")

        return policy

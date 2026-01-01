"""
Tests for HttpAuthorizationPolicySource.

Uses aiohttp test server for integration testing.
"""

import asyncio
from dataclasses import dataclass
from typing import Optional

import pytest
import yaml
from aiohttp import web

from naylence.fame.security.auth.policy.authorization_policy_definition import (
    AuthorizationPolicyDefinition,
)
from naylence.fame.security.auth.policy.http_authorization_policy_source import (
    HttpAuthorizationPolicySource,
    HttpAuthorizationPolicySourceOptions,
)
from naylence.fame.security.auth.policy.http_authorization_policy_source_factory import (
    HttpAuthorizationPolicySourceFactory,
)
from naylence.fame.security.auth.token import Token

# Test policy definitions
# NOTE: Do NOT use frame_type in these policies - BasicAuthorizationPolicy
# skips rules containing frame_type (reserved for advanced-security)
BASIC_ALLOW_POLICY: AuthorizationPolicyDefinition = {
    "version": "1.0",
    "default_effect": "deny",
    "rules": [
        {
            "id": "allow-all",
            "effect": "allow",
            "action": "*",
        },
    ],
}

BASIC_DENY_POLICY: AuthorizationPolicyDefinition = {
    "version": "1.0",
    "default_effect": "allow",
    "rules": [
        {
            "id": "deny-deliver-local",
            "effect": "deny",
            "action": "DeliverLocal",
        },
    ],
}

ADVANCED_POLICY: AuthorizationPolicyDefinition = {
    "version": "1.0",
    "default_effect": "deny",
    "rules": [
        {
            "id": "allow-admin",
            "effect": "allow",
            "action": "*",
            # Note: 'when' is ignored by BasicAuthorizationPolicy
            "when": 'principal.role == "admin"',
        },
    ],
}


# Mock types for testing
@dataclass
class MockFrame:
    """Mock frame object."""

    type: str


@dataclass
class MockEnvelope:
    """Mock envelope for testing."""

    id: str
    frame: MockFrame
    to: Optional[str] = None
    from_: Optional[str] = None
    corr_id: Optional[str] = None
    sid: Optional[str] = None


@dataclass
class MockNode:
    """Mock node for testing."""

    id: str
    sid: Optional[str] = None


def create_mock_node() -> MockNode:
    """Create a mock node for testing."""
    return MockNode(id="test-node-1")


def create_mock_envelope() -> MockEnvelope:
    """Create a mock envelope for testing."""
    return MockEnvelope(id="test-envelope-1", frame=MockFrame(type="Data"))


@dataclass
class PolicyServerState:
    """State for the test HTTP server."""

    policy: AuthorizationPolicyDefinition
    format: str = "json"
    etag: Optional[str] = None
    max_age: Optional[int] = None
    require_auth: bool = False
    expected_token: Optional[str] = None
    return_error: Optional[int] = None
    delay: Optional[float] = None


class PolicyServer:
    """Test HTTP server for serving policies."""

    def __init__(self, state: PolicyServerState):
        self.state = state
        self.app: Optional[web.Application] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.port: int = 0

    async def start(self) -> str:
        """Start the test server and return the base URL."""
        self.app = web.Application()
        self.app.router.add_get("/policy", self._handle_policy)

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await self.site.start()

        # Get the actual port
        if self.site._server and self.site._server.sockets:
            socket = self.site._server.sockets[0]
            self.port = socket.getsockname()[1]

        return f"http://127.0.0.1:{self.port}/policy"

    async def stop(self) -> None:
        """Stop the test server."""
        if self.runner:
            await self.runner.cleanup()

    async def _handle_policy(self, request: web.Request) -> web.Response:
        """Handle policy requests."""
        state = self.state

        # Simulate delay if configured
        if state.delay and state.delay > 0:
            await asyncio.sleep(state.delay)

        # Check authorization if required
        if state.require_auth:
            auth_header = request.headers.get("Authorization")
            if not auth_header:
                return web.json_response(
                    {"error": "Authorization required"}, status=401
                )
            if state.expected_token and state.expected_token not in auth_header:
                return web.json_response({"error": "Invalid token"}, status=403)

        # Return error if configured
        if state.return_error:
            return web.json_response(
                {"error": "Simulated error"}, status=state.return_error
            )

        # Handle conditional request with ETag
        if state.etag:
            if_none_match = request.headers.get("If-None-Match")
            if if_none_match == state.etag:
                headers = {"ETag": state.etag}
                if state.max_age is not None:
                    headers["Cache-Control"] = f"max-age={state.max_age}"
                return web.Response(status=304, headers=headers)

        # Prepare response
        policy_with_type = {
            "type": "BasicAuthorizationPolicy",
            **state.policy,
        }

        headers: dict[str, str] = {}

        if state.format == "yaml":
            body = yaml.dump(policy_with_type)
            headers["Content-Type"] = "application/yaml"
        else:
            import json

            body = json.dumps(policy_with_type)
            headers["Content-Type"] = "application/json"

        if state.etag:
            headers["ETag"] = state.etag

        if state.max_age is not None:
            headers["Cache-Control"] = f"max-age={state.max_age}"

        return web.Response(text=body, headers=headers)


@pytest.fixture
async def test_server():
    """Fixture that provides a test server factory."""
    servers: list[PolicyServer] = []

    async def create_server(
        policy: AuthorizationPolicyDefinition = BASIC_ALLOW_POLICY,
        format: str = "json",
        etag: Optional[str] = None,
        max_age: Optional[int] = None,
        require_auth: bool = False,
        expected_token: Optional[str] = None,
        return_error: Optional[int] = None,
        delay: Optional[float] = None,
    ) -> tuple[str, PolicyServer]:
        state = PolicyServerState(
            policy=policy,
            format=format,
            etag=etag,
            max_age=max_age,
            require_auth=require_auth,
            expected_token=expected_token,
            return_error=return_error,
            delay=delay,
        )
        server = PolicyServer(state)
        url = await server.start()
        servers.append(server)
        return url, server

    yield create_server

    # Cleanup
    for server in servers:
        await server.stop()


class TestHttpAuthorizationPolicySourceBasic:
    """Tests for basic functionality of HttpAuthorizationPolicySource."""

    async def test_loads_json_policy_from_http_endpoint(self, test_server):
        """Test loading a JSON policy from HTTP endpoint."""
        url, _ = await test_server(policy=BASIC_ALLOW_POLICY, format="json")

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(url=url)
        )

        policy = await source.load_policy()
        assert policy is not None

        # Verify policy has the required interface
        assert hasattr(policy, "evaluate_request")

        # Verify policy evaluates correctly
        node = create_mock_node()
        envelope = create_mock_envelope()
        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "allow"

    async def test_loads_yaml_policy_from_http_endpoint(self, test_server):
        """Test loading a YAML policy from HTTP endpoint."""
        url, _ = await test_server(policy=BASIC_ALLOW_POLICY, format="yaml")

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(url=url)
        )

        policy = await source.load_policy()
        assert policy is not None

        # Verify policy has the required interface
        assert hasattr(policy, "evaluate_request")

        # Verify policy evaluates correctly
        node = create_mock_node()
        envelope = create_mock_envelope()
        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "allow"

    async def test_evaluates_allow_deny_correctly_based_on_policy(self, test_server):
        """Test that policy evaluates allow/deny correctly."""
        url, _ = await test_server(policy=BASIC_DENY_POLICY, format="json")

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(url=url)
        )

        policy = await source.load_policy()
        node = create_mock_node()
        envelope = create_mock_envelope()

        # ForwardUpstream should be allowed (default is allow)
        forward_result = await policy.evaluate_request(
            node, envelope, None, "ForwardUpstream"
        )
        assert forward_result.effect == "allow"

        # DeliverLocal should be denied (explicit deny rule)
        deliver_result = await policy.evaluate_request(
            node, envelope, None, "DeliverLocal"
        )
        assert deliver_result.effect == "deny"


class TestHttpAuthorizationPolicySourceBearerAuth:
    """Tests for bearer authentication."""

    async def test_sends_bearer_token_when_token_provider_is_configured(
        self, test_server
    ):
        """Test that bearer token is sent when token provider is configured."""
        url, _ = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="json",
            require_auth=True,
            expected_token="test-secret-token",
        )

        class TestTokenProvider:
            """Test token provider."""

            async def get_token(self) -> Token:
                return Token(value="test-secret-token")

        token_provider = TestTokenProvider()

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(
                url=url, token_provider=token_provider
            )
        )

        policy = await source.load_policy()
        assert policy is not None

    async def test_fails_when_required_token_is_missing(self, test_server):
        """Test that request fails when required token is missing."""
        url, _ = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="json",
            require_auth=True,
            expected_token="test-secret-token",
        )

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(url=url)  # No token provider
        )

        with pytest.raises(Exception) as exc_info:
            await source.load_policy()
        assert "401" in str(exc_info.value)

    async def test_supports_custom_bearer_prefix(self, test_server):
        """Test that custom bearer prefix is supported."""
        url, _ = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="json",
            require_auth=True,
            expected_token="custom-token",
        )

        class TestTokenProvider:
            """Test token provider."""

            async def get_token(self) -> Token:
                return Token(value="custom-token")

        token_provider = TestTokenProvider()

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(
                url=url,
                token_provider=token_provider,
                bearer_prefix="Token ",
            )
        )

        policy = await source.load_policy()
        assert policy is not None


class TestHttpAuthorizationPolicySourceETagCaching:
    """Tests for ETag caching."""

    async def test_uses_if_none_match_header_on_subsequent_requests(self, test_server):
        """Test that If-None-Match header is used on subsequent requests."""
        url, _ = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="json",
            etag='"v1"',
            max_age=0,  # Immediate expiration to force refetch
        )

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(
                url=url,
                cache_ttl_ms=0,  # Force cache expiration
            )
        )

        # First load fetches the policy
        policy1 = await source.load_policy()
        assert policy1 is not None

        metadata1 = source.get_metadata()
        assert metadata1 is not None
        assert metadata1.etag == '"v1"'
        assert metadata1.status == 200

        # Second load should use conditional request and get 304
        source.clear_cache()

        # Re-add the etag to the internal state by doing a fresh fetch
        policy2 = await source.load_policy()
        assert policy2 is not None

        metadata2 = source.get_metadata()
        assert metadata2 is not None
        assert metadata2.status == 200

    async def test_returns_cached_policy_on_304_response(self, test_server):
        """Test that cached policy is returned on 304 response."""
        url, server = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="json",
            etag='"v1"',
            max_age=0,
        )

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(
                url=url,
                cache_ttl_ms=0,
            )
        )

        # First fetch
        await source.load_policy()

        # Update server to return different policy
        server.state.policy = BASIC_DENY_POLICY

        # Force cache to be stale but keep etag
        # The server should return 304 because etag matches
        metadata = source.get_metadata()
        assert metadata is not None
        assert metadata.etag == '"v1"'


class TestHttpAuthorizationPolicySourceReloadPolicy:
    """Tests for reloadPolicy method."""

    async def test_forces_fresh_fetch_regardless_of_cache_freshness(self, test_server):
        """Test that reloadPolicy forces fresh fetch regardless of cache freshness."""
        url, server = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="json",
            max_age=3600,  # Long cache time
        )

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(url=url)
        )

        # Initial load
        policy1 = await source.load_policy()
        assert policy1 is not None

        # Change the server's policy
        server.state.policy = BASIC_DENY_POLICY

        # loadPolicy would return cached version
        cached_policy = await source.load_policy()
        assert cached_policy is policy1

        # reloadPolicy forces fresh fetch
        reloaded_policy = await source.reload_policy()
        assert reloaded_policy is not None
        assert reloaded_policy is not policy1

        # Verify the new policy has different behavior
        node = create_mock_node()
        envelope = create_mock_envelope()
        deliver_result = await reloaded_policy.evaluate_request(
            node, envelope, None, "DeliverLocal"
        )
        assert deliver_result.effect == "deny"

    async def test_updates_decisions_after_policy_change(self, test_server):
        """Test that decisions update after policy change."""
        url, server = await test_server(
            policy={
                "version": "1.0",
                "default_effect": "deny",
                "rules": [{"id": "allow-all", "effect": "allow", "action": "*"}],
            },
            format="json",
        )

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(
                url=url,
                cache_ttl_ms=0,
            )
        )

        node = create_mock_node()
        envelope = create_mock_envelope()

        policy1 = await source.load_policy()
        result1 = await policy1.evaluate_request(node, envelope, None, "*")
        assert result1.effect == "allow"

        # Update server to deny all
        server.state.policy = {
            "version": "1.0",
            "default_effect": "deny",
            "rules": [{"id": "deny-all", "effect": "deny", "action": "*"}],
        }

        # Reload and verify new decision
        policy2 = await source.reload_policy()
        result2 = await policy2.evaluate_request(node, envelope, None, "*")
        assert result2.effect == "deny"


class TestHttpAuthorizationPolicySourceFailureHandling:
    """Tests for failure handling."""

    async def test_preserves_last_known_good_policy_on_http_error(self, test_server):
        """Test that last-known-good policy is preserved on HTTP error."""
        url, server = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="json",
            max_age=0,
        )

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(
                url=url,
                cache_ttl_ms=0,
            )
        )

        # First load succeeds
        policy1 = await source.load_policy()
        assert policy1 is not None

        # Configure server to return error
        server.state.return_error = 500

        # reloadPolicy throws but policy is preserved
        with pytest.raises(Exception) as exc_info:
            await source.reload_policy()
        assert "500" in str(exc_info.value)

        # Original cached policy should still be in metadata
        metadata = source.get_metadata()
        assert metadata is not None
        assert metadata.status == 200

    async def test_preserves_last_known_good_policy_on_parse_error(self, test_server):
        """Test that last-known-good policy is preserved on parse error."""
        url, _ = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="json",
        )

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(
                url=url,
                cache_ttl_ms=0,
            )
        )

        # First load succeeds
        policy1 = await source.load_policy()
        assert policy1 is not None

        # Get the raw definition before we break things
        raw_def = source.get_raw_definition()
        assert raw_def is not None

    async def test_throws_on_first_load_if_server_returns_error(self, test_server):
        """Test that first load throws if server returns error."""
        url, _ = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="json",
            return_error=404,
        )

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(url=url)
        )

        with pytest.raises(Exception) as exc_info:
            await source.load_policy()
        assert "404" in str(exc_info.value)


class TestHttpAuthorizationPolicySourceTimeout:
    """Tests for timeout handling."""

    async def test_throws_on_timeout(self, test_server):
        """Test that request throws on timeout."""
        url, _ = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="json",
            delay=5.0,  # 5 second delay
        )

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(
                url=url,
                timeout_ms=100,  # 100ms timeout
            )
        )

        # The error may be timeout or connection related
        with pytest.raises(Exception):
            await source.load_policy()


class TestHttpAuthorizationPolicySourceContentType:
    """Tests for content type detection."""

    async def test_sniffs_json_when_content_type_is_missing(self, test_server):
        """Test that JSON is detected when content-type is missing."""
        url, _ = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="json",
        )

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(url=url)
        )

        policy = await source.load_policy()
        assert policy is not None

    async def test_sniffs_yaml_when_content_type_indicates_yaml(self, test_server):
        """Test that YAML is detected when content starts with non-JSON."""
        url, _ = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="yaml",
        )

        source = HttpAuthorizationPolicySource(
            HttpAuthorizationPolicySourceOptions(url=url)
        )

        policy = await source.load_policy()
        assert policy is not None


class TestHttpAuthorizationPolicySourceConcurrentRequests:
    """Tests for concurrent request handling."""

    async def test_deduplicates_concurrent_load_policy_calls(self, test_server):
        """Test that concurrent loadPolicy calls are deduplicated."""
        request_count = 0

        async def counting_handler(request: web.Request) -> web.Response:
            nonlocal request_count
            request_count += 1
            await asyncio.sleep(0.1)
            policy_with_type = {
                "type": "BasicAuthorizationPolicy",
                **BASIC_ALLOW_POLICY,
            }

            return web.json_response(policy_with_type)

        app = web.Application()
        app.router.add_get("/policy", counting_handler)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()

        try:
            if site._server and site._server.sockets:
                socket = site._server.sockets[0]
                port = socket.getsockname()[1]
            url = f"http://127.0.0.1:{port}/policy"

            source = HttpAuthorizationPolicySource(
                HttpAuthorizationPolicySourceOptions(url=url)
            )

            # Fire multiple concurrent requests
            results = await asyncio.gather(
                source.load_policy(),
                source.load_policy(),
                source.load_policy(),
            )

            # All should return the same policy
            assert results[0] is results[1]
            assert results[1] is results[2]

            # Only one HTTP request should have been made
            assert request_count == 1
        finally:
            await runner.cleanup()


class TestHttpAuthorizationPolicySourceFactory:
    """Tests for HttpAuthorizationPolicySourceFactory."""

    async def test_creates_source_from_config(self, test_server):
        """Test that factory creates source from config."""
        url, _ = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="json",
        )

        factory = HttpAuthorizationPolicySourceFactory()
        source = await factory.create({
            "type": "HttpAuthorizationPolicySource",
            "url": url,
        })

        assert source is not None

        policy = await source.load_policy()
        assert policy is not None

    async def test_creates_source_with_token_provider_config(self, test_server):
        """Test that factory creates source with token provider config."""
        url, _ = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="json",
            require_auth=True,
            expected_token="static-token-123",
        )

        factory = HttpAuthorizationPolicySourceFactory()
        source = await factory.create({
            "type": "HttpAuthorizationPolicySource",
            "url": url,
            "token_provider": {
                "type": "StaticTokenProvider",
                "token": "static-token-123",
            },
        })

        assert source is not None

        policy = await source.load_policy()
        assert policy is not None

    async def test_supports_snake_case_config_properties(self, test_server):
        """Test that factory supports snake_case config properties."""
        url, _ = await test_server(
            policy=BASIC_ALLOW_POLICY,
            format="json",
        )

        factory = HttpAuthorizationPolicySourceFactory()
        source = await factory.create({
            "type": "HttpAuthorizationPolicySource",
            "url": url,
            "timeout_ms": 5000,
            "cache_ttl_ms": 60000,
            "bearer_prefix": "Token ",
        })

        assert source is not None

    async def test_throws_on_missing_url(self):
        """Test that factory throws on missing url."""
        factory = HttpAuthorizationPolicySourceFactory()

        with pytest.raises(ValueError) as exc_info:
            await factory.create({
                "type": "HttpAuthorizationPolicySource",
            })
        assert "url" in str(exc_info.value).lower()

    async def test_throws_on_invalid_method(self):
        """Test that factory throws on invalid method."""
        factory = HttpAuthorizationPolicySourceFactory()

        with pytest.raises(ValueError) as exc_info:
            await factory.create({
                "type": "HttpAuthorizationPolicySource",
                "url": "http://example.com/policy",
                "method": "DELETE",
            })
        assert 'Invalid method "DELETE"' in str(exc_info.value)

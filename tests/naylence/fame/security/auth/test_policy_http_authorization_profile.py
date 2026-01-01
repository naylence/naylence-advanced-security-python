"""
Tests for policy-http authorization profile.
"""


from naylence.fame.profile import get_profile
from naylence.fame.security.auth.authorization_profile_factory import (
    AUTHORIZER_FACTORY_BASE_TYPE,
)
from naylence.fame.security.auth.policy_http_authorization_profile import (
    ENV_VAR_AUTH_POLICY_AUDIENCE,
    ENV_VAR_AUTH_POLICY_BEARER_TOKEN,
    ENV_VAR_AUTH_POLICY_CACHE_TTL_MS,
    ENV_VAR_AUTH_POLICY_CLIENT_ID,
    ENV_VAR_AUTH_POLICY_CLIENT_SECRET,
    ENV_VAR_AUTH_POLICY_TIMEOUT_MS,
    ENV_VAR_AUTH_POLICY_TOKEN_URL,
    ENV_VAR_AUTH_POLICY_URL,
    PROFILE_NAME_POLICY_HTTP,
    register_policy_http_profile,
)


class TestPolicyHttpAuthorizationProfile:
    """Tests for policy-http authorization profile."""

    def test_exports_profile_name_policy_http_constant(self):
        """Test that PROFILE_NAME_POLICY_HTTP constant is exported."""
        assert PROFILE_NAME_POLICY_HTTP == "policy-http"

    def test_exports_environment_variable_constants(self):
        """Test that environment variable constants are exported."""
        assert ENV_VAR_AUTH_POLICY_URL == "FAME_AUTH_POLICY_URL"
        assert ENV_VAR_AUTH_POLICY_TIMEOUT_MS == "FAME_AUTH_POLICY_TIMEOUT_MS"
        assert ENV_VAR_AUTH_POLICY_CACHE_TTL_MS == "FAME_AUTH_POLICY_CACHE_TTL_MS"
        assert ENV_VAR_AUTH_POLICY_TOKEN_URL == "FAME_AUTH_POLICY_TOKEN_URL"
        assert ENV_VAR_AUTH_POLICY_CLIENT_ID == "FAME_AUTH_POLICY_CLIENT_ID"
        assert ENV_VAR_AUTH_POLICY_CLIENT_SECRET == "FAME_AUTH_POLICY_CLIENT_SECRET"
        assert ENV_VAR_AUTH_POLICY_AUDIENCE == "FAME_AUTH_POLICY_AUDIENCE"
        assert ENV_VAR_AUTH_POLICY_BEARER_TOKEN == "FAME_AUTH_POLICY_BEARER_TOKEN"

    def test_registers_policy_http_profile_in_profile_registry(self):
        """Test that policy-http profile is registered in profile registry."""
        # Ensure profile is registered
        register_policy_http_profile()

        profile = get_profile(AUTHORIZER_FACTORY_BASE_TYPE, PROFILE_NAME_POLICY_HTTP)
        assert profile is not None

    def test_profile_has_correct_structure_with_policy_authorizer_type(self):
        """Test that profile has correct structure with PolicyAuthorizer type."""
        register_policy_http_profile()

        profile = get_profile(AUTHORIZER_FACTORY_BASE_TYPE, PROFILE_NAME_POLICY_HTTP)
        assert profile is not None
        assert profile.get("type") == "PolicyAuthorizer"

    def test_profile_includes_jwks_token_verifier(self):
        """Test that profile includes JWKS token verifier."""
        register_policy_http_profile()

        profile = get_profile(AUTHORIZER_FACTORY_BASE_TYPE, PROFILE_NAME_POLICY_HTTP)
        assert profile is not None

        verifier = profile.get("verifier")
        assert verifier is not None
        assert verifier.get("type") == "JWKSJWTTokenVerifier"

    def test_profile_includes_http_authorization_policy_source(self):
        """Test that profile includes HttpAuthorizationPolicySource."""
        register_policy_http_profile()

        profile = get_profile(AUTHORIZER_FACTORY_BASE_TYPE, PROFILE_NAME_POLICY_HTTP)
        assert profile is not None

        policy_source = profile.get("policy_source")
        assert policy_source is not None
        assert policy_source.get("type") == "HttpAuthorizationPolicySource"

    def test_profile_policy_source_has_url_configured_via_expression(self):
        """Test that profile policy_source has url configured via expression."""
        register_policy_http_profile()

        profile = get_profile(AUTHORIZER_FACTORY_BASE_TYPE, PROFILE_NAME_POLICY_HTTP)
        assert profile is not None

        policy_source = profile.get("policy_source")
        assert policy_source is not None

        url_config = policy_source.get("url")
        assert url_config is not None
        # The url should be an expression reference to ENV_VAR_AUTH_POLICY_URL
        assert "FAME_AUTH_POLICY_URL" in str(url_config)
        assert str(url_config).startswith("${env:")

    def test_profile_policy_source_includes_token_provider_with_oauth2_client_credentials(self):
        """Test that profile policy_source includes OAuth2 client credentials token_provider."""
        register_policy_http_profile()

        profile = get_profile(AUTHORIZER_FACTORY_BASE_TYPE, PROFILE_NAME_POLICY_HTTP)
        assert profile is not None

        policy_source = profile.get("policy_source")
        assert policy_source is not None

        token_provider = policy_source.get("token_provider")
        assert token_provider is not None
        assert token_provider.get("type") == "OAuth2ClientCredentialsTokenProvider"

    def test_register_is_idempotent(self):
        """Test that register_policy_http_profile is idempotent."""
        # Call multiple times - should not raise
        register_policy_http_profile()
        register_policy_http_profile()
        register_policy_http_profile()

        # Profile should still be registered correctly
        profile = get_profile(AUTHORIZER_FACTORY_BASE_TYPE, PROFILE_NAME_POLICY_HTTP)
        assert profile is not None
        assert profile.get("type") == "PolicyAuthorizer"

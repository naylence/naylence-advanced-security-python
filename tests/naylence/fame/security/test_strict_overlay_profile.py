"""
Tests for strict-overlay security profile registration.

These tests verify that the strict-overlay profile is correctly registered
and can be used through the SecurityProfileFactory.
"""

import os
from typing import Generator

import pytest

from naylence.fame.profile import get_profile, list_profiles
from naylence.fame.security.security_manager_factory import (
    SECURITY_MANAGER_FACTORY_BASE_TYPE,
)

# Import the strict-overlay module to trigger registration
from naylence.fame.security.strict_overlay_security_profile import (
    ENV_VAR_AUTHORIZATION_PROFILE,
    ENV_VAR_DEFAULT_ENCRYPTION_LEVEL,
    PROFILE_NAME_STRICT_OVERLAY,
    STRICT_OVERLAY_PROFILE,
    register_strict_overlay_profile,
)


@pytest.fixture(autouse=True)
def clean_env() -> Generator[None, None, None]:
    """Clean up environment variables before and after each test."""
    original_values = {}
    for key in list(os.environ.keys()):
        if key.startswith("FAME_"):
            original_values[key] = os.environ.pop(key)
    yield
    for key in list(os.environ.keys()):
        if key.startswith("FAME_"):
            del os.environ[key]
    os.environ.update(original_values)


class TestStrictOverlayProfileRegistration:
    """Tests for strict-overlay profile registration."""

    def test_profile_name_is_strict_overlay(self):
        """Profile name should be 'strict-overlay'."""
        assert PROFILE_NAME_STRICT_OVERLAY == "strict-overlay"

    def test_profile_is_registered(self):
        """Strict-overlay profile should be registered in the registry."""
        # Ensure registration has happened
        register_strict_overlay_profile()

        profiles = list_profiles(SECURITY_MANAGER_FACTORY_BASE_TYPE)
        assert PROFILE_NAME_STRICT_OVERLAY in profiles

    def test_profile_can_be_retrieved(self):
        """Should be able to retrieve the strict-overlay profile configuration."""
        register_strict_overlay_profile()

        profile = get_profile(
            SECURITY_MANAGER_FACTORY_BASE_TYPE,
            PROFILE_NAME_STRICT_OVERLAY,
        )
        assert profile is not None
        assert profile["type"] == "DefaultSecurityManager"

    def test_registration_is_idempotent(self):
        """Calling register_strict_overlay_profile multiple times should not raise."""
        register_strict_overlay_profile()
        register_strict_overlay_profile()
        register_strict_overlay_profile()

        profiles = list_profiles(SECURITY_MANAGER_FACTORY_BASE_TYPE)
        # Should only be registered once
        assert profiles.count(PROFILE_NAME_STRICT_OVERLAY) == 1


class TestStrictOverlayProfileConfiguration:
    """Tests for strict-overlay profile configuration values."""

    def test_uses_x509_chain_signing_material(self):
        """Strict-overlay should use x509-chain signing material."""
        signing = STRICT_OVERLAY_PROFILE["security_policy"]["signing"]
        assert signing["signing_material"] == "x509-chain"

    def test_requires_cert_sid_match(self):
        """Strict-overlay should require certificate subject ID match."""
        signing = STRICT_OVERLAY_PROFILE["security_policy"]["signing"]
        assert signing["require_cert_sid_match"] is True

    def test_requires_inbound_signatures(self):
        """Strict-overlay should require inbound signatures."""
        inbound = STRICT_OVERLAY_PROFILE["security_policy"]["signing"]["inbound"]
        assert inbound["signature_policy"] == "required"
        assert inbound["unsigned_violation_action"] == "nack"
        assert inbound["invalid_signature_action"] == "nack"

    def test_allows_channel_and_sealed_encryption(self):
        """Strict-overlay should allow channel and sealed encryption."""
        encryption_inbound = STRICT_OVERLAY_PROFILE["security_policy"]["encryption"][
            "inbound"
        ]
        assert encryption_inbound["allow_plaintext"] is True
        assert encryption_inbound["allow_channel"] is True
        assert encryption_inbound["allow_sealed"] is True

    def test_outbound_defaults_to_channel_encryption(self):
        """Strict-overlay outbound encryption should default to channel."""
        outbound = STRICT_OVERLAY_PROFILE["security_policy"]["encryption"]["outbound"]
        default_level = outbound["default_level"]
        # Should be an expression with 'channel' as default
        assert "${env:" in default_level
        assert ENV_VAR_DEFAULT_ENCRYPTION_LEVEL in default_level
        assert ":channel}" in default_level

    def test_authorizer_uses_jwt_profile_by_default(self):
        """Strict-overlay should use JWT authorization profile by default."""
        authorizer = STRICT_OVERLAY_PROFILE["authorizer"]
        assert authorizer["type"] == "AuthorizationProfile"
        profile_value = authorizer["profile"]
        assert "${env:" in profile_value
        assert ENV_VAR_AUTHORIZATION_PROFILE in profile_value
        assert ":jwt}" in profile_value

"""
Test stickiness key provider injection functionality.
"""

from unittest.mock import Mock

from naylence.fame.security.keys.key_provider import KeyProvider, get_key_provider
from naylence.fame.stickiness.aft_load_balancer_stickiness_manager import (
    AFTLoadBalancerStickinessManager,
    AFTLoadBalancerStickinessManagerConfig,
)
from naylence.fame.stickiness.aft_verifier import (
    SidOnlyAFTVerifier,
    SignedOptionalAFTVerifier,
    StrictAFTVerifier,
    create_aft_verifier,
)
from naylence.fame.stickiness.stickiness_mode import StickinessMode


def create_stickiness_manager(config: AFTLoadBalancerStickinessManagerConfig, key_provider, verifier=None):
    """Create and return an AFTLoadBalancerStickinessManager for testing.

    Args:
        config: AFTLoadBalancerStickinessManagerConfig instance
        key_provider: Key provider instance
        verifier: Optional verifier instance

    Returns:
        AFTLoadBalancerStickinessManager instance
    """
    if not verifier:
        verifier = create_aft_verifier(config.security_level, key_provider, config.default_ttl_sec)

    return AFTLoadBalancerStickinessManager(config, verifier)


class TestStickinessKeyProviderInjection:
    """Test key provider injection in stickiness components."""

    def test_create_aft_verifier_auto_key_provider(self):
        """Test that create_aft_verifier requires explicit key provider."""

        # STRICT mode requires explicit key provider
        verifier_strict = create_aft_verifier(StickinessMode.STRICT, get_key_provider())
        assert isinstance(verifier_strict, StrictAFTVerifier)
        assert verifier_strict.key_provider is not None

        # SIGNED_OPTIONAL mode requires explicit key provider
        verifier_optional = create_aft_verifier(StickinessMode.SIGNED_OPTIONAL, get_key_provider())
        assert isinstance(verifier_optional, SignedOptionalAFTVerifier)
        assert verifier_optional.key_provider is not None

        # SID_ONLY mode doesn't need key provider
        verifier_sid = create_aft_verifier(StickinessMode.SID_ONLY, get_key_provider())
        assert isinstance(verifier_sid, SidOnlyAFTVerifier)

    def test_create_aft_verifier_explicit_key_provider(self):
        """Test that create_aft_verifier accepts explicit key provider."""

        mock_key_provider = Mock(spec=KeyProvider)

        # STRICT mode with explicit key provider
        verifier_strict = create_aft_verifier(StickinessMode.STRICT, mock_key_provider)
        assert isinstance(verifier_strict, StrictAFTVerifier)
        assert verifier_strict.key_provider is mock_key_provider

        # SIGNED_OPTIONAL mode with explicit key provider
        verifier_optional = create_aft_verifier(StickinessMode.SIGNED_OPTIONAL, mock_key_provider)
        assert isinstance(verifier_optional, SignedOptionalAFTVerifier)
        assert verifier_optional.key_provider is mock_key_provider

    def test_create_stickiness_manager_auto_key_provider(self):
        """Test that create_stickiness_manager requires explicit key provider."""

        # STRICT mode config
        config_strict = AFTLoadBalancerStickinessManagerConfig()
        config_strict.security_level = StickinessMode.STRICT

        manager_strict = create_stickiness_manager(config_strict, get_key_provider())
        assert manager_strict.verifier is not None
        assert isinstance(manager_strict.verifier, StrictAFTVerifier)
        assert manager_strict.verifier.key_provider is not None

        # SIGNED_OPTIONAL mode config
        config_optional = AFTLoadBalancerStickinessManagerConfig()
        config_optional.security_level = StickinessMode.SIGNED_OPTIONAL

        manager_optional = create_stickiness_manager(config_optional, get_key_provider())
        assert manager_optional.verifier is not None
        assert isinstance(manager_optional.verifier, SignedOptionalAFTVerifier)
        assert manager_optional.verifier.key_provider is not None

        # SID_ONLY mode config
        config_sid = AFTLoadBalancerStickinessManagerConfig()
        config_sid.security_level = StickinessMode.SID_ONLY

        manager_sid = create_stickiness_manager(config_sid, get_key_provider())
        assert manager_sid.verifier is not None
        assert isinstance(manager_sid.verifier, SidOnlyAFTVerifier)

    def test_create_stickiness_manager_explicit_key_provider(self):
        """Test that create_stickiness_manager accepts explicit key provider."""

        mock_key_provider = Mock(spec=KeyProvider)

        config = AFTLoadBalancerStickinessManagerConfig()
        config.security_level = StickinessMode.STRICT

        manager = create_stickiness_manager(config, key_provider=mock_key_provider)
        assert manager.verifier is not None
        assert isinstance(manager.verifier, StrictAFTVerifier)
        assert manager.verifier.key_provider is mock_key_provider

    def test_create_stickiness_manager_explicit_verifier(self):
        """Test that create_stickiness_manager accepts explicit verifier."""

        mock_verifier = Mock()
        config = AFTLoadBalancerStickinessManagerConfig()

        manager = create_stickiness_manager(config, key_provider=get_key_provider(), verifier=mock_verifier)
        assert manager.verifier is mock_verifier

    def test_key_provider_consistency(self):
        """Test that global key provider is used consistently."""

        global_key_provider = get_key_provider()

        # Create verifier with explicit key provider
        verifier = create_aft_verifier(StickinessMode.STRICT, global_key_provider)
        assert verifier.key_provider is global_key_provider

        # Create manager with explicit key provider
        config = AFTLoadBalancerStickinessManagerConfig()
        config.security_level = StickinessMode.STRICT
        manager = create_stickiness_manager(config, global_key_provider)
        assert manager.verifier.key_provider is global_key_provider

    def test_factory_parameter_combinations(self):
        """Test various parameter combinations for factory functions."""

        mock_key_provider = Mock(spec=KeyProvider)
        mock_verifier = Mock()

        config = AFTLoadBalancerStickinessManagerConfig()
        config.security_level = StickinessMode.STRICT

        # Both verifier and key_provider provided (verifier should take precedence)
        manager = create_stickiness_manager(config, verifier=mock_verifier, key_provider=mock_key_provider)
        assert manager.verifier is mock_verifier

        # Only key_provider provided
        manager = create_stickiness_manager(config, key_provider=mock_key_provider)
        assert isinstance(manager.verifier, StrictAFTVerifier)
        assert manager.verifier.key_provider is mock_key_provider

        # Only verifier provided (still requires key_provider but verifier takes precedence)
        manager = create_stickiness_manager(config, key_provider=get_key_provider(), verifier=mock_verifier)
        assert manager.verifier is mock_verifier

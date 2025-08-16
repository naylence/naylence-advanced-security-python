"""
Test flexible crypto policy functionality.
"""

from typing import Optional
from unittest.mock import Mock

import pytest

from naylence.fame.core import FameAddress, FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.policy.no_security_policy import NoSecurityPolicy
from naylence.fame.security.policy.security_policy import (
    CryptoLevel,
    EncryptionConfig,
    InboundCryptoRules,
    OutboundCryptoRules,
    ResponseCryptoRules,
    SecurityAction,
)


def create_test_envelope(envelope_id: str = "test-1", to_address: Optional[str] = None) -> FameEnvelope:
    """Helper to create test envelopes with proper frame."""
    frame = DataFrame(payload=b"test data")
    envelope = FameEnvelope(id=envelope_id, frame=frame)
    if to_address:
        envelope.to = FameAddress(to_address)
    return envelope


class TestFlexibleCryptoPolicy:
    """Test flexible crypto policy functionality."""

    def test_crypto_level_enum_values(self):
        """Test that CryptoLevel enum has expected values."""
        assert CryptoLevel.PLAINTEXT is not None
        assert CryptoLevel.CHANNEL is not None
        assert CryptoLevel.SEALED is not None

    def test_security_action_enum_values(self):
        """Test that SecurityAction enum has expected values."""
        assert SecurityAction.ALLOW is not None
        assert SecurityAction.REJECT is not None
        assert SecurityAction.NACK is not None

    def test_encryption_defaults(self):
        """Test EncryptionConfig has sensible defaults."""
        config = EncryptionConfig()

        # Check inbound rules defaults
        assert config.inbound.allow_plaintext is True
        assert config.inbound.allow_channel is True
        assert config.inbound.allow_sealed is True
        assert config.inbound.plaintext_violation_action == SecurityAction.NACK

        # Check response rules defaults
        assert config.response.mirror_request_level is True
        assert config.response.minimum_response_level == CryptoLevel.CHANNEL
        assert config.response.escalate_sealed_responses is False

        # Check outbound rules defaults
        assert config.outbound.default_level == CryptoLevel.CHANNEL
        assert config.outbound.escalate_if_peer_supports is True
        assert config.outbound.prefer_sealed_for_sensitive is True

    def test_default_policy_crypto_level_classification(self):
        """Test crypto level classification in default policy."""
        policy = DefaultSecurityPolicy()

        # Create test envelope
        envelope = create_test_envelope()

        # Test plaintext classification
        crypto_level = policy.classify_message_crypto_level(envelope)
        assert crypto_level == CryptoLevel.PLAINTEXT

        # Test sealed classification (envelope with encryption)
        envelope.sec = Mock()
        envelope.sec.enc = Mock()
        crypto_level = policy.classify_message_crypto_level(envelope)
        assert crypto_level == CryptoLevel.SEALED

    def test_default_policy_inbound_crypto_rules(self):
        """Test inbound crypto level checking in default policy."""
        # Test the crypto rules with default policy
        policy = DefaultSecurityPolicy()
        envelope = create_test_envelope()

        # Test default rules - Default policy is minimal and only allows PLAINTEXT
        assert policy.is_inbound_crypto_level_allowed(CryptoLevel.PLAINTEXT, envelope) is True
        assert policy.is_inbound_crypto_level_allowed(CryptoLevel.CHANNEL, envelope) is False  # Not allowed by default
        assert policy.is_inbound_crypto_level_allowed(CryptoLevel.SEALED, envelope) is False   # Not allowed by default

        # Test violation actions - ALLOW for allowed level, NACK for violations
        assert policy.get_inbound_violation_action(CryptoLevel.PLAINTEXT, envelope) == SecurityAction.ALLOW  # Allowed
        assert policy.get_inbound_violation_action(CryptoLevel.CHANNEL, envelope) == SecurityAction.NACK   # Violation
        assert policy.get_inbound_violation_action(CryptoLevel.SEALED, envelope) == SecurityAction.NACK    # Violation

    @pytest.mark.asyncio
    async def test_default_policy_response_crypto_rules(self):
        """Test response crypto level decisions in default policy."""
        policy = DefaultSecurityPolicy()
        envelope = create_test_envelope()

        # Test response level - Default policy uses PLAINTEXT minimum, doesn't mirror request level
        response_level = await policy.decide_response_crypto_level(CryptoLevel.SEALED, envelope)
        assert response_level == CryptoLevel.PLAINTEXT  # Default policy defaults to plaintext

        # Test minimum level - Already at minimum (PLAINTEXT)
        response_level = await policy.decide_response_crypto_level(CryptoLevel.PLAINTEXT, envelope)
        assert response_level == CryptoLevel.PLAINTEXT  # Should stay at minimum

    @pytest.mark.asyncio
    async def test_default_policy_outbound_crypto_rules(self):
        """Test outbound crypto level decisions in default policy."""
        policy = DefaultSecurityPolicy()
        envelope = create_test_envelope(to_address="test@example.com/path")

        # Test default level - Default policy uses PLAINTEXT as default level
        crypto_level = await policy.decide_outbound_crypto_level(envelope)
        assert crypto_level == CryptoLevel.PLAINTEXT  # Default policy default level

    @pytest.mark.asyncio
    async def test_custom_encryption(self):
        """Test default policy with custom flexible crypto config."""
        # Create custom config that allows plaintext
        custom_config = EncryptionConfig(
            inbound=InboundCryptoRules(allow_plaintext=True, allow_channel=True, allow_sealed=True),
            response=ResponseCryptoRules(
                mirror_request_level=False, minimum_response_level=CryptoLevel.PLAINTEXT
            ),
            outbound=OutboundCryptoRules(default_level=CryptoLevel.PLAINTEXT),
        )

        policy = DefaultSecurityPolicy(encryption=custom_config)
        envelope = create_test_envelope()

        # Test that plaintext is now allowed
        assert policy.is_inbound_crypto_level_allowed(CryptoLevel.PLAINTEXT, envelope) is True

        # Test that response level can be plaintext
        response_level = await policy.decide_response_crypto_level(CryptoLevel.SEALED, envelope)
        assert response_level == CryptoLevel.PLAINTEXT  # Should be minimum level

        # Test that outbound default is plaintext
        envelope.to = FameAddress("test@example.com/path")
        crypto_level = await policy.decide_outbound_crypto_level(envelope)
        assert crypto_level == CryptoLevel.PLAINTEXT

    @pytest.mark.asyncio
    async def test_no_security_policy_flexible_methods(self):
        """Test that NoSecurityPolicy implements flexible methods correctly."""
        policy = NoSecurityPolicy()
        envelope = create_test_envelope()

        # Test crypto level classification
        crypto_level = policy.classify_message_crypto_level(envelope)
        assert crypto_level == CryptoLevel.PLAINTEXT

        # Test all crypto levels are allowed
        assert policy.is_inbound_crypto_level_allowed(CryptoLevel.PLAINTEXT, envelope) is True
        assert policy.is_inbound_crypto_level_allowed(CryptoLevel.CHANNEL, envelope) is True
        assert policy.is_inbound_crypto_level_allowed(CryptoLevel.SEALED, envelope) is True

        # Test violation action is always ALLOW
        assert policy.get_inbound_violation_action(CryptoLevel.PLAINTEXT, envelope) == SecurityAction.ALLOW

        # Test response and outbound are always plaintext
        assert (
            await policy.decide_response_crypto_level(CryptoLevel.SEALED, envelope) == CryptoLevel.PLAINTEXT
        )
        assert await policy.decide_outbound_crypto_level(envelope) == CryptoLevel.PLAINTEXT

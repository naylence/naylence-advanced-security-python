"""
Test that policy-driven security correctly handles signature mirroring scenarios.
"""

from unittest.mock import Mock

import pytest

from naylence.fame.core import DataFrame, DeliveryOriginType, FameDeliveryContext, FameEnvelope
from naylence.fame.security.policy import DefaultSecurityPolicy
from naylence.fame.security.policy.security_policy import (
    CryptoLevel,
    EncryptionConfig,
    InboundCryptoRules,
    InboundSigningRules,
    OutboundCryptoRules,
    OutboundSigningRules,
    ResponseCryptoRules,
    ResponseSigningRules,
    SecurityAction,
    SignaturePolicy,
    SigningConfig,
)
from naylence.fame.security.security_manager_factory import SecurityManagerFactory


class TestSignatureMirroringPolicyRequirements:
    """Test that policy requirements correctly identify when signers are needed for mirroring."""

    @pytest.mark.asyncio
    async def test_mirror_request_signing_requires_signer(self):
        """Test that mirror_request_signing=True requires a signer even with default_signing=False."""

        # Policy with signature mirroring but no default signing
        policy = DefaultSecurityPolicy(
            signing=SigningConfig(
                response=ResponseSigningRules(
                    mirror_request_signing=True,  # Should require signer
                ),
                outbound=OutboundSigningRules(
                    default_signing=False,  # No default signing
                    sign_sensitive_operations=False,
                    sign_if_recipient_expects=False,
                ),
            )
        )

        requirements = policy.requirements()
        assert requirements.signing_required is True, (
            "mirror_request_signing should require signing capability"
        )

        # Auto-selection should create a signer
        node_security = await SecurityManagerFactory.create_security_manager(policy)
        assert node_security.envelope_signer is not None, "Should auto-select signer for mirroring"

    @pytest.mark.asyncio
    async def test_always_sign_responses_requires_signer(self):
        """Test that always_sign_responses=True requires a signer."""

        policy = DefaultSecurityPolicy(
            signing=SigningConfig(
                response=ResponseSigningRules(
                    always_sign_responses=True,  # Should require signer
                ),
                outbound=OutboundSigningRules(
                    default_signing=False, sign_sensitive_operations=False, sign_if_recipient_expects=False
                ),
            )
        )

        requirements = policy.requirements()
        assert requirements.signing_required is True, (
            "always_sign_responses should require signing capability"
        )

        node_security = await SecurityManagerFactory.create_security_manager(policy)
        assert node_security.envelope_signer is not None, "Should auto-select signer for response signing"

    @pytest.mark.asyncio
    async def test_sign_error_responses_requires_signer(self):
        """Test that sign_error_responses=True requires a signer."""

        policy = DefaultSecurityPolicy(
            signing=SigningConfig(
                response=ResponseSigningRules(
                    sign_error_responses=True,  # Should require signer
                ),
                outbound=OutboundSigningRules(
                    default_signing=False, sign_sensitive_operations=False, sign_if_recipient_expects=False
                ),
            )
        )

        requirements = policy.requirements()
        assert requirements.signing_required is True, (
            "sign_error_responses should require signing capability"
        )

        node_security = await SecurityManagerFactory.create_security_manager(policy)
        assert node_security.envelope_signer is not None, (
            "Should auto-select signer for error response signing"
        )

    @pytest.mark.asyncio
    async def test_no_response_signing_no_signer_needed(self):
        """Test that with all response signing disabled, no signer is needed."""

        policy = DefaultSecurityPolicy(
            signing=SigningConfig(
                response=ResponseSigningRules(
                    mirror_request_signing=False,  # No mirroring
                    always_sign_responses=False,  # No response signing
                    sign_error_responses=False,  # No error signing
                ),
                outbound=OutboundSigningRules(
                    default_signing=False, sign_sensitive_operations=False, sign_if_recipient_expects=False
                ),
                inbound=InboundSigningRules(
                    signature_policy=SignaturePolicy.DISABLED  # No verification either
                ),
            )
        )

        requirements = policy.requirements()
        assert requirements.signing_required is False, "No signing should be required"
        assert requirements.verification_required is False, "No verification should be required"

        node_security = await SecurityManagerFactory.create_security_manager(policy)
        assert node_security.envelope_signer is None, "Should not auto-select signer when not needed"
        assert node_security.envelope_verifier is None, "Should not auto-select verifier when not needed"


class TestSignatureMirroringBehavior:
    """Test the actual signature mirroring behavior in response scenarios."""

    @pytest.mark.asyncio
    async def test_agent_config_signature_mirroring(self):
        """Test the agent configuration scenario from the user's issue."""

        # Agent policy - matches user's agent config
        agent_policy = DefaultSecurityPolicy(
            encryption=EncryptionConfig(
                inbound=InboundCryptoRules(
                    allow_plaintext=True,
                    allow_channel=True,
                    allow_sealed=True,
                    plaintext_violation_action=SecurityAction.NACK,
                    channel_violation_action=SecurityAction.NACK,
                    sealed_violation_action=SecurityAction.NACK,
                ),
                outbound=OutboundCryptoRules(
                    default_level=CryptoLevel.PLAINTEXT,  # Key: no default encryption
                    escalate_if_peer_supports=False,
                    prefer_sealed_for_sensitive=False,
                ),
                response=ResponseCryptoRules(
                    mirror_request_level=True,
                    minimum_response_level=CryptoLevel.PLAINTEXT,  # Key: allow plaintext responses
                    escalate_sealed_responses=False,
                ),
            ),
            signing=SigningConfig(
                inbound=InboundSigningRules(signature_policy=SignaturePolicy.OPTIONAL),
                response=ResponseSigningRules(
                    mirror_request_signing=True,  # Key: should mirror signatures
                    always_sign_responses=False,
                    sign_error_responses=True,
                ),
                outbound=OutboundSigningRules(
                    default_signing=False,  # Key: no default outbound signing
                    sign_sensitive_operations=False,
                    sign_if_recipient_expects=False,
                ),
            ),
        )

        # Should auto-select signer for mirroring
        node_security = await SecurityManagerFactory.create_security_manager(agent_policy)
        assert node_security.envelope_signer is not None, "Agent should have signer for mirroring"
        assert node_security.envelope_verifier is not None, (
            "Agent should have verifier for optional signatures"
        )

        # Test outbound request behavior (should NOT sign)
        outbound_envelope = Mock(spec=FameEnvelope)
        outbound_envelope.id = "outbound-123"
        outbound_envelope.sec = None
        outbound_envelope.frame = Mock(spec=DataFrame)
        outbound_envelope.frame.type = "Data"
        outbound_envelope.to = None

        outbound_context = Mock(spec=FameDeliveryContext)
        outbound_context.origin_type = DeliveryOriginType.LOCAL
        outbound_context.meta = {"message-type": "request"}

        should_sign_outbound = await agent_policy.should_sign_envelope(outbound_envelope, outbound_context)
        assert should_sign_outbound is False, "Agent should not sign outbound requests"

        # Test response to signed request behavior (should sign due to mirroring)
        response_envelope = Mock(spec=FameEnvelope)
        response_envelope.id = "response-456"
        response_envelope.sec = None
        response_envelope.frame = Mock(spec=DataFrame)
        response_envelope.frame.type = "Data"
        response_envelope.to = None

        response_context = Mock(spec=FameDeliveryContext)
        response_context.origin_type = DeliveryOriginType.LOCAL
        response_context.meta = {"message-type": "response"}
        response_context.security = Mock()
        response_context.security.inbound_was_signed = True  # Original request was signed
        response_context.security.inbound_crypto_level = CryptoLevel.PLAINTEXT

        should_sign_response = await agent_policy.should_sign_envelope(response_envelope, response_context)
        assert should_sign_response is True, "Agent should sign response to signed request"


if __name__ == "__main__":
    pytest.main([__file__])

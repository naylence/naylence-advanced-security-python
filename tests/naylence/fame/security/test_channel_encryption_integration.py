"""
Integration test for end-to-end channel encryption context tracking.

This test verifies that when a message is encrypted over a virtual secure channel,
the encryption context is properly tracked and preserved throughout the entire
delivery pipeline, including responses.
"""

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    generate_id,
)
from naylence.fame.core.protocol.delivery_context import SecurityContext
from naylence.fame.core.protocol.security_header import EncryptionHeader, SecurityHeader
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.policy.security_policy import CryptoLevel


@pytest.mark.asyncio
async def test_end_to_end_channel_encryption_context_tracking():
    """
    Test that channel encryption context is properly tracked throughout the entire flow:
    1. Message arrives with channel encryption (algorithm indicates channel encryption)
    2. Node classifies it based on the encryption algorithm
    3. Context is forwarded to local handlers
    4. Response inherits channel encryption context
    5. Crypto level classification works correctly at each step
    """

    # Step 1: Simulate a channel-encrypted message arriving at the node
    # Channel encryption is detected by the algorithm in the security header

    # Envelope with channel encryption algorithm
    envelope = FameEnvelope(
        id=generate_id(),
        frame=DataFrame(payload={"message": "hello", "method": "test_method"}),
        to=FameAddress("test-service@local"),
        sec=SecurityHeader(enc=EncryptionHeader(alg="chacha20-poly1305-channel", val="encrypted-data")),
    )

    # Step 2: Context that indicates channel transport
    # This simulates what the node does when it detects and decrypts a channel-encrypted message
    delivery_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL,
        security=SecurityContext(
            crypto_channel_id="secure-channel-789",
            # The inbound_crypto_level would be set by the security policy
            inbound_crypto_level=CryptoLevel.CHANNEL,
        ),
    )

    # Step 3: Verify that the security policy correctly classifies this as CHANNEL encryption
    policy = DefaultSecurityPolicy()
    crypto_level = policy.classify_message_crypto_level(envelope, delivery_context)
    assert crypto_level == CryptoLevel.CHANNEL

    # Step 4: Simulate handler processing and response creation
    # This is what would happen in EnvelopeListenerManager.listen

    # Handler returns a response without explicit context
    response_envelope = FameEnvelope(
        id=generate_id(), frame=DataFrame(payload={"result": "success"}), to=FameAddress("client@remote")
    )

    # Step 5: Smart response context creation (as implemented in EnvelopeListenerManager)
    # When handler doesn't provide context, we create one with inherited properties
    response_context = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL,
        from_system_id="test-node",
        security=SecurityContext(
            # Use inbound_crypto_level to represent the original request's crypto level
            inbound_crypto_level=delivery_context.security.inbound_crypto_level
            if delivery_context.security
            else None,
            # Inherit channel encryption information
            crypto_channel_id=delivery_context.security.crypto_channel_id
            if delivery_context.security
            else None,
        ),
    )

    # Step 6: Verify that channel encryption context is properly preserved in response
    assert response_context.security is not None
    assert response_context.security.crypto_channel_id == "secure-channel-789"
    assert response_context.security.inbound_crypto_level == CryptoLevel.CHANNEL

    # Step 7: Verify that the security policy makes correct decisions for the response
    # Response crypto level should match or exceed the original request level
    response_crypto_level = await policy.decide_response_crypto_level(
        request_crypto_level=CryptoLevel.CHANNEL, envelope=response_envelope, context=response_context
    )

    # The response should use at least CHANNEL level (or higher based on policy)
    assert response_crypto_level.value >= CryptoLevel.CHANNEL.value


@pytest.mark.asyncio
async def test_channel_vs_sealed_precedence_in_real_scenario():
    """
    Test a realistic scenario where a message has both channel encryption and envelope encryption.
    This could happen if a message is sent over a secure channel AND has end-to-end encryption.
    """

    # Message with both channel encryption (was encrypted over virtual channel)
    # AND envelope encryption (end-to-end encryption)

    envelope = FameEnvelope(
        id=generate_id(),
        frame=DataFrame(payload={"sensitive": "data"}),
        to=FameAddress("secure-service@local"),
        # Has envelope-level encryption
        sec=SecurityHeader(enc=EncryptionHeader(kid="e2e-key-123", val="encrypted-envelope-content")),
    )

    # Context indicating it was also delivered over a secure channel
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL,
        security=SecurityContext(
            crypto_channel_id="secure-channel-999",
            inbound_crypto_level=CryptoLevel.SEALED,  # Would be set to SEALED due to envelope encryption
        ),
    )

    # Security policy should classify this as SEALED (envelope encryption takes precedence)
    policy = DefaultSecurityPolicy()
    crypto_level = policy.classify_message_crypto_level(envelope, context)
    assert crypto_level == CryptoLevel.SEALED

    # Create a response envelope
    response_envelope = FameEnvelope(
        id=generate_id(), frame=DataFrame(payload={"status": "processed"}), to=FameAddress("client@remote")
    )

    # Create a policy that supports encryption responses
    from naylence.fame.security.policy.security_policy import (
        EncryptionConfig,
        InboundCryptoRules,
        ResponseCryptoRules,
    )

    encryption_policy = DefaultSecurityPolicy(
        encryption=EncryptionConfig(
            inbound=InboundCryptoRules(allow_sealed=True, allow_channel=True, allow_plaintext=True),
            response=ResponseCryptoRules(
                mirror_request_level=True,  # Mirror the request level
                minimum_response_level=CryptoLevel.PLAINTEXT,
            ),
        )
    )

    response_crypto_level = await encryption_policy.decide_response_crypto_level(
        request_crypto_level=CryptoLevel.SEALED, envelope=response_envelope, context=context
    )

    # Response should mirror the SEALED level when policy supports it
    assert response_crypto_level == CryptoLevel.SEALED


@pytest.mark.asyncio
async def test_channel_context_lost_fallback():
    """
    Test that the system gracefully handles cases where channel context might be lost.
    This ensures backward compatibility and robustness.
    """

    # Message that was channel-encrypted but context information was lost
    envelope = FameEnvelope(
        id=generate_id(), frame=DataFrame(payload={"message": "data"}), to=FameAddress("service@local")
    )

    # Context without channel information (simulating lost context)
    context = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL,
        # No channel_id
    )

    # Should fall back to PLAINTEXT classification
    policy = DefaultSecurityPolicy()
    crypto_level = policy.classify_message_crypto_level(envelope, context)
    assert crypto_level == CryptoLevel.PLAINTEXT

    # System should still function normally
    response_crypto_level = await policy.decide_response_crypto_level(
        request_crypto_level=CryptoLevel.PLAINTEXT, envelope=envelope, context=context
    )

    # Should get a valid response level (at least PLAINTEXT)
    assert response_crypto_level is not None
    assert isinstance(response_crypto_level, CryptoLevel)


@pytest.mark.asyncio
async def test_channel_encryption_detection_edge_cases():
    """Test edge cases in channel encryption detection based on envelope security headers."""

    policy = DefaultSecurityPolicy()

    # Case 1: No security header in envelope (plaintext)
    envelope_plaintext = FameEnvelope(
        id=generate_id(), frame=DataFrame(payload={"data": "test"}), to=FameAddress("service@local")
    )

    context_with_channel = FameDeliveryContext(
        origin_type=DeliveryOriginType.LOCAL,
        security=SecurityContext(crypto_channel_id="some-channel"),
    )

    crypto_level = policy.classify_message_crypto_level(envelope_plaintext, context_with_channel)
    assert crypto_level == CryptoLevel.PLAINTEXT

    # Case 2: Envelope with channel encryption algorithm
    envelope_channel = FameEnvelope(
        id=generate_id(),
        frame=DataFrame(payload={"data": "test"}),
        to=FameAddress("service@local"),
        sec=SecurityHeader(
            enc=EncryptionHeader(alg="chacha20-poly1305-channel", val="dummy-encrypted-value")
        ),
    )

    crypto_level = policy.classify_message_crypto_level(envelope_channel, context_with_channel)
    assert crypto_level == CryptoLevel.CHANNEL

    # Case 3: Envelope with non-channel encryption algorithm
    envelope_sealed = FameEnvelope(
        id=generate_id(),
        frame=DataFrame(payload={"data": "test"}),
        to=FameAddress("service@local"),
        sec=SecurityHeader(enc=EncryptionHeader(alg="aes-256-gcm", val="dummy-encrypted-value")),
    )

    crypto_level = policy.classify_message_crypto_level(envelope_sealed, context_with_channel)
    assert crypto_level == CryptoLevel.SEALED

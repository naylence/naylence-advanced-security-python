#!/usr/bin/env python3
"""
Test script to validate the encryption key flow implementation in EnvelopeSecurityHandler.
"""

from unittest.mock import AsyncMock, Mock

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    generate_id,
)
from naylence.fame.node.envelope_security_handler import EnvelopeSecurityHandler
from naylence.fame.security.encryption.encryption_manager import EncryptionResult, EncryptionStatus
from naylence.fame.security.keys.key_management_handler import KeyManagementHandler
from naylence.fame.security.policy import DefaultSecurityPolicy


@pytest.mark.asyncio
async def test_encryption_key_flow():
    """Test that encryption key flow works similar to signing key flow."""
    print("🧪 Testing encryption key flow...")

    # Create mocks for required components
    node_like = Mock()
    node_like.sid = "test-node"
    node_like.physical_path = "/test/node"

    encryption_manager = Mock()
    # Set up the encryption manager to return proper EncryptionResult objects
    encryption_manager.encrypt_envelope = AsyncMock()

    security_policy = Mock(spec=DefaultSecurityPolicy)

    # Create a mock key management handler
    key_management_handler = Mock(spec=KeyManagementHandler)
    key_management_handler._pending_encryption_envelopes = {}
    key_management_handler._maybe_request_encryption_key = AsyncMock()
    key_management_handler.has_key = AsyncMock()

    # Create the handler under test
    handler = EnvelopeSecurityHandler(
        node_like=node_like,
        encryption_manager=encryption_manager,
        security_policy=security_policy,
        key_management_handler=key_management_handler,
    )

    # Test envelope
    envelope = FameEnvelope(
        id=generate_id(),
        frame=DataFrame(payload="test message"),
        to=FameAddress("test-service@/test/recipient"),
    )

    context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, from_system_id="test-node")

    # Test Case 1: Security policy returns encryption options with key ID
    test_kid = "test-recipient-enc-key"
    encryption_opts = {"recip_pub": b"mock_public_key_bytes", "recip_kid": test_kid}

    security_policy.get_encryption_options.return_value = encryption_opts

    print("📋 Test Case 1: Key not available - should queue envelope")
    # Mock encryption manager to return QUEUED status (simulating missing key)
    encryption_manager.encrypt_envelope.return_value = EncryptionResult(EncryptionStatus.QUEUED, None)

    # Call the method under test
    result = await handler._handle_to_be_encrypted_envelope(envelope, context)

    # Verify envelope was queued (method should return False when queued)
    assert result is False, "Should return False when envelope is queued"

    print("✅ Test Case 1 passed - envelope queued when encryption returned QUEUED status")

    # Test Case 2: Key available immediately - should encrypt and continue
    print("📋 Test Case 2: Key available immediately - should encrypt")

    envelope2 = FameEnvelope(
        id=generate_id(),
        frame=DataFrame(payload="immediate encryption test"),
        to=FameAddress("test-service2@/test/recipient2"),
    )

    # Create a mock encrypted envelope for the result
    encrypted_envelope = FameEnvelope(
        id=envelope2.id, frame=DataFrame(payload="encrypted content"), to=envelope2.to
    )

    # Mock encryption manager to return OK status with encrypted envelope
    encryption_manager.encrypt_envelope.return_value = EncryptionResult(
        EncryptionStatus.OK, encrypted_envelope
    )

    result = await handler._handle_to_be_encrypted_envelope(envelope2, context)

    # Verify encryption was called and method returned True
    assert result is True, "Should return True when encryption succeeds"
    encryption_manager.encrypt_envelope.assert_called_with(envelope2, opts=encryption_opts)

    print("✅ Test Case 2 passed - envelope encrypted immediately")

    # Test Case 3: No encryption options - should continue without encryption
    print("📋 Test Case 3: No encryption options - should skip encryption")

    security_policy.get_encryption_options.return_value = None

    envelope3 = FameEnvelope(
        id=generate_id(),
        frame=DataFrame(payload="no encryption test"),
        to=FameAddress("test-service3@/test/recipient3"),
    )

    result = await handler._handle_to_be_encrypted_envelope(envelope3, context)

    # Verify no encryption was attempted and method returned True
    assert result is True, "Should return True when no encryption is needed"
    # Since no encryption options were provided, encrypt_envelope should not be called
    # Reset call count to verify this specific case
    encryption_manager.encrypt_envelope.reset_mock()

    # Call again to verify encrypt_envelope is not called with None options
    result = await handler._handle_to_be_encrypted_envelope(envelope3, context)
    encryption_manager.encrypt_envelope.assert_not_called()

    print("✅ Test Case 3 passed - skipped encryption when no options provided")

    # Test Case 4: Encryption skipped - should continue without encryption
    print("📋 Test Case 4: Encryption skipped - should continue")

    security_policy.get_encryption_options.return_value = encryption_opts  # Valid options
    # Mock encryption manager to return SKIPPED status
    encryption_manager.encrypt_envelope.return_value = EncryptionResult(EncryptionStatus.SKIPPED, None)

    envelope4 = FameEnvelope(
        id=generate_id(),
        frame=DataFrame(payload="skipped encryption test"),
        to=FameAddress("test-service4@/test/recipient4"),
    )

    result = await handler._handle_to_be_encrypted_envelope(envelope4, context)

    # Verify method returned True when encryption is skipped
    assert result is True, "Should return True when encryption is skipped"
    encryption_manager.encrypt_envelope.assert_called_with(envelope4, opts=encryption_opts)

    print("✅ Test Case 4 passed - continued when encryption was skipped")

    # Test Case 5: Non-DataFrame should skip encryption
    print("📋 Test Case 5: Non-DataFrame - should skip encryption")

    from naylence.fame.core import KeyAnnounceFrame

    envelope5 = FameEnvelope(
        id=generate_id(),
        frame=KeyAnnounceFrame(physical_path="/test", keys=[]),  # Non-DataFrame
        to=FameAddress("test-service5@/test/recipient5"),
    )

    # Reset security policy to return encryption options (should be ignored for non-DataFrame)
    security_policy.get_encryption_options.return_value = encryption_opts
    encryption_manager.encrypt_envelope.reset_mock()

    result = await handler._handle_to_be_encrypted_envelope(envelope5, context)

    # Verify no encryption was attempted and method returned True
    assert result is True, "Should return True for non-DataFrame"
    encryption_manager.encrypt_envelope.assert_not_called()

    print("✅ Test Case 5 passed - skipped encryption for non-DataFrame")

    print("\n🎉 All encryption key flow tests passed!")
    print("💡 Key features validated:")
    print("   ✅ Envelope queuing when encryption returns QUEUED status")
    print("   ✅ Successful encryption when encryption returns OK status")
    print("   ✅ Graceful handling when encryption is not needed (no options)")
    print("   ✅ Graceful handling when encryption is skipped")
    print("   ✅ DataFrame-only encryption (other frame types skipped)")

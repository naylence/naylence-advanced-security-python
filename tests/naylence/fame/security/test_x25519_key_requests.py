"""Test X25519EncryptionManager key request functionality."""

from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from naylence.fame.core import FameAddress, FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame, KeyRequestFrame
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
from naylence.fame.security.encryption.encryption_manager import EncryptionStatus
from naylence.fame.security.encryption.sealed.x25519_encryption_manager import X25519EncryptionManager
from naylence.fame.security.keys.key_provider import get_key_provider


@pytest.mark.asyncio
async def test_x25519_key_request_and_replay():
    """Test that X25519EncryptionManager can request keys and replay envelopes."""

    print("🔐 Testing X25519EncryptionManager key request and replay...")

    # Create mock node_like
    node_like = AsyncMock()
    node_like.sid = "test-node-id"  # Mock the system ID
    delivered_envelopes = []

    async def mock_deliver(envelope, context=None):
        delivered_envelopes.append(envelope)

    node_like.deliver = mock_deliver

    # Create encryption manager with node_like
    crypto = get_crypto_provider()
    manager = X25519EncryptionManager(crypto=crypto, node_like=node_like, key_provider=get_key_provider())

    # Create test envelope
    frame = DataFrame(payload="Test message", codec="json")
    envelope = FameEnvelope(frame=frame)

    # Create test address
    test_address = FameAddress("test-node@/test-path")

    # Try to encrypt with missing key (should trigger key request)
    result = await manager.encrypt_envelope(envelope, opts={"request_address": test_address})

    print(f"✅ Encryption result status: {result.status}")
    assert result.status == EncryptionStatus.QUEUED

    # Verify key request was sent
    assert len(delivered_envelopes) == 1
    key_request_envelope = delivered_envelopes[0]
    assert isinstance(key_request_envelope.frame, KeyRequestFrame)
    assert key_request_envelope.frame.address == test_address
    assert key_request_envelope.to == test_address

    print("✅ Key request was sent correctly")

    # Clear delivered envelopes
    delivered_envelopes.clear()

    # Generate test key pair
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    # Add the key to key provider (simulating key arrival)
    key_provider = get_key_provider()
    test_kid = f"request-{str(test_address)}"

    # Add key to the provider
    test_key_data = {
        "kid": test_kid,
        "kty": "OKP",
        "crv": "X25519",
        "use": "enc",
        "encryption_public_pem": public_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode(),
    }

    # Mock the key provider to return our test key
    original_get_key = key_provider.get_key

    async def mock_get_key(kid):
        if kid == test_kid:
            return test_key_data
        return await original_get_key(kid)

    key_provider.get_key = mock_get_key

    # Notify that key is available
    await manager.notify_key_available(test_kid)

    # Verify that the original envelope was replayed
    assert len(delivered_envelopes) == 1
    replayed_envelope = delivered_envelopes[0]
    assert replayed_envelope.id == envelope.id
    assert isinstance(replayed_envelope.frame, DataFrame)

    print("✅ Envelope was replayed after key became available")

    # Test that the envelope can now be encrypted successfully
    delivered_envelopes.clear()

    # Create a new envelope to test encryption with available key
    new_frame = DataFrame(payload="New test message", codec="json")
    new_envelope = FameEnvelope(frame=new_frame)

    # Try to encrypt with the now-available key
    result = await manager.encrypt_envelope(new_envelope, opts={"recip_kid": test_kid})

    print(f"✅ Second encryption result status: {result.status}")
    assert result.status == EncryptionStatus.OK
    assert result.envelope is not None
    envelope = result.envelope
    assert envelope.sec is not None
    sec_header = envelope.sec
    assert sec_header.enc is not None
    assert sec_header.enc.kid == test_kid

    print("✅ Encryption succeeded with available key")

    # Verify no additional envelopes were delivered (no queueing needed)
    assert len(delivered_envelopes) == 0

    print("✅ All tests passed!")


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_x25519_without_node_like():
    """Test that X25519EncryptionManager works without node_like (no key requests)."""

    print("🔐 Testing X25519EncryptionManager without node_like...")

    # Create encryption manager without node_like
    crypto = get_crypto_provider()
    manager = X25519EncryptionManager(crypto=crypto, key_provider=get_key_provider())

    # Create test envelope
    frame = DataFrame(payload="Test message", codec="json")
    envelope = FameEnvelope(frame=frame)

    # Create test address
    test_address = FameAddress("test-node@/test-path")

    # Try to encrypt with missing key
    result = await manager.encrypt_envelope(envelope, opts={"request_address": test_address})

    print(f"✅ Encryption result status: {result.status}")
    assert result.status == EncryptionStatus.QUEUED

    # Verify envelope was queued but no key request was sent
    test_kid = f"request-{str(test_address)}"
    assert test_kid in manager._pending_envelopes
    assert len(manager._pending_envelopes[test_kid]) == 1

    print("✅ Envelope was queued without sending key request (no node_like)")

    # Notify that key is available
    await manager.notify_key_available(test_kid)

    # Verify envelope was cleared from queue but not replayed (no node_like)
    assert test_kid not in manager._pending_envelopes

    print("✅ Queue was cleared on key notification without replay")
    print("✅ All tests passed!")

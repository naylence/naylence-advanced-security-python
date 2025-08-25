"""Test that nodes can use the updated encryption managers with key requests."""

import pytest

from naylence.fame.core import FameAddress, FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.security.encryption.encryption_manager import EncryptionStatus
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore


@pytest.mark.asyncio
async def test_node_with_key_requests():
    """Test that a node can use the encryption manager with key requests."""

    print("🏗️ Testing node with key request functionality...")

    # Create a mock channel manager for testing
    class MockSecureChannelManager:
        def __init__(self):
            self._channels = {}

    mock_secure_channel_manager = MockSecureChannelManager()

    # Create encryption manager first
    from naylence.fame.security.encryption.composite_encryption_manager import CompositeEncryptionManager
    from naylence.fame.security.keys.key_provider import get_key_provider
    from naylence.fame.security.security_manager_factory import SecurityManagerFactory

    encryption_manager = CompositeEncryptionManager(
        secure_channel_manager=mock_secure_channel_manager,  # type: ignore
        key_provider=get_key_provider(),
    )

    # Create a test node
    node_security = await SecurityManagerFactory.create_security_manager(
        encryption_manager=encryption_manager
    )
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
    from naylence.fame.tracking.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory

    storage_provider = InMemoryStorageProvider()

    # Create envelope tracker
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

    node = FameNode(
        system_id="test-node",
        security_manager=node_security,
        storage_provider=storage_provider,
        node_meta_store=InMemoryKVStore[NodeMeta](NodeMeta),
        delivery_tracker=delivery_tracker,
    )

    # Use async context manager to ensure proper cleanup
    async with node:
        print(f"✅ Created and started node: {node._id}")
        print(f"📍 Node physical path: {node.physical_path}")
        print(f"🔧 Encryption manager type: {type(node._security_manager.encryption)}")  # type: ignore

        # Verify that the encryption manager has node_like set
        if hasattr(node._security_manager.encryption, "_sealed"):  # type: ignore
            assert hasattr(node._security_manager.encryption, "_channel_with_handshake")  # type: ignore
            assert node._security_manager.encryption._sealed._node_like is node  # type: ignore
            if node._security_manager.encryption._channel_with_handshake is not None:  # type: ignore
                assert node._security_manager.encryption._channel_with_handshake._node_like is node  # type: ignore
            print("✅ Node references properly set on encryption managers")
        else:
            print("⚠️ Using different encryption manager type, continuing with basic test...")

        # Create test envelope
        frame = DataFrame(payload={"test": "message"}, codec="json")
        envelope = FameEnvelope(frame=frame)
        test_address = FameAddress("recipient@/remote-node")

        # Test X25519 encryption with key request
        print(f"🔐 Testing X25519 encryption with key request to {test_address}...")

        # Try encryption (should trigger key request)
        result = await node._security_manager.encryption.encrypt_envelope(  # type: ignore
            envelope, opts={"request_address": test_address}
        )

        print(f"✅ Encryption result: {result.status}")
        assert result.status == EncryptionStatus.QUEUED

        # Test key notification
        test_kid = f"request-{str(test_address)}"

        # Mock key provider to simulate key arrival
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        from naylence.fame.security.keys.key_provider import get_key_provider

        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()

        test_key_data = {
            "kid": test_kid,
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "encryption_public_pem": public_key.public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
        }

        key_provider = get_key_provider()
        original_get_key = key_provider.get_key

        async def mock_get_key(kid):
            if kid == test_kid:
                return test_key_data
            return await original_get_key(kid)

        key_provider.get_key = mock_get_key

        # Notify key available
        print(f"🔔 Notifying key available: {test_kid}")
        await node._security_manager.encryption.notify_key_available(test_kid)  # type: ignore

        print("✅ Key notification completed")

        # Test that new encryption now works immediately
        new_frame = DataFrame(payload={"test": "immediate"}, codec="json")
        new_envelope = FameEnvelope(frame=new_frame)

        result = await node._security_manager.encryption.encrypt_envelope(  # type: ignore
            new_envelope, opts={"recip_kid": test_kid}
        )  # type: ignore

        print(f"✅ New encryption result: {result.status}")
        assert result.status == EncryptionStatus.OK

        print("🎉 Node with key request functionality test completed successfully!")

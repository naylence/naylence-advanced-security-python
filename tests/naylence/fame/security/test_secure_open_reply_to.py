from unittest.mock import Mock

import pytest

from naylence.fame.core import FameAddress, generate_id
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.security.encryption.channel.channel_encryption_manager import ChannelEncryptionManager
from naylence.fame.security.encryption.default_secure_channel_manager import DefaultSecureChannelManager


@pytest.mark.asyncio
async def test_secure_open_reply_to():
    """Test that SecureOpen envelope has reply_to field populated."""
    print("🔐 Testing SecureOpen reply_to Population")
    print("=" * 50)

    # Create channel manager and mock node
    secure_channel_manager = DefaultSecureChannelManager()
    # No need to manually manipulate _channels since we use the public interface

    node = Mock()
    node.secure_channel_manager = secure_channel_manager

    # Mock the physical_path and envelope_factory
    node.physical_path = "/test-node"

    # Mock the envelope factory to capture the reply_to
    created_envelopes = []

    def mock_create_envelope(**kwargs):
        """Mock envelope factory that captures arguments."""
        envelope = Mock()
        envelope.to = kwargs.get("to")
        envelope.reply_to = kwargs.get("reply_to")
        envelope.frame = kwargs.get("frame")
        created_envelopes.append(envelope)
        return envelope

    mock_envelope_factory = Mock()
    mock_envelope_factory.create_envelope = mock_create_envelope
    node._envelope_factory = mock_envelope_factory

    # Mock spawn method to properly handle coroutines
    def mock_spawn(coro, *, name=None):
        """Mock spawn that closes the coroutine to prevent warnings."""
        if hasattr(coro, "close"):
            coro.close()
        return Mock()

    node.spawn = mock_spawn

    # Create encryption manager
    encryptor = ChannelEncryptionManager(secure_channel_manager=secure_channel_manager, node_like=node)

    # Create test envelope
    destination = FameAddress("test-service@/remote-server")
    test_envelope = Mock()
    test_envelope.to = destination
    test_envelope.frame = DataFrame(fid=generate_id(), payload={"test": "data"}, codec="json")

    print(f"📡 Testing encryption to destination: {destination}")
    print(f"🏠 Node physical path: {node.physical_path}")

    # Encrypt the envelope (this should trigger SecureOpen frame creation)
    await encryptor.encrypt_envelope(test_envelope)

    # Verify a SecureOpen envelope was created
    if created_envelopes:
        secure_open_envelope = created_envelopes[0]
        print("✅ SecureOpen envelope created")
        print(f"   📤 To: {secure_open_envelope.to}")
        print(f"   📬 Reply-to: {secure_open_envelope.reply_to}")
        print(f"   🔧 Frame type: {secure_open_envelope.frame.type}")

        # Check that reply_to is properly set
        if secure_open_envelope.reply_to:
            expected_reply_to = "__sys__@/test-node"
            if str(secure_open_envelope.reply_to) == expected_reply_to:
                print(f"   ✅ Reply-to correctly set: {secure_open_envelope.reply_to}")
            else:
                print(
                    f"   ❌ Reply-to incorrect: got {secure_open_envelope.reply_to}, "
                    f"expected {expected_reply_to}"
                )
        else:
            print("   ❌ Reply-to not set!")
    else:
        print("   ❌ No SecureOpen envelope was created")

    print("\n🔐 SecureOpen reply_to test complete!")

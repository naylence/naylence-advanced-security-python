import asyncio

import pytest

from naylence.fame.security.default_security_manager_factory import DefaultSecurityManagerFactory
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy


class MockNode:
    """Mock node for testing."""

    def __init__(self):
        self.node_id = "test_node"
        self.id = "test_node"
        self.sid = "test_sid"
        self.physical_path = "/test/path"
        self.accepted_logicals = ["test.service"]
        self.envelope_factory = None
        self.default_binding_path = "/test"

    async def deliver_upstream(self, envelope, context=None):
        """Mock deliver_upstream method."""
        pass

    async def deliver_local(self, address, envelope, context=None):
        """Mock deliver_local method."""
        pass


class MinimalSecurityPolicy(DefaultSecurityPolicy):
    """Security policy that only requires channel encryption (no key exchange)."""

    def requirements(self):
        from naylence.fame.security.policy.security_policy import SecurityRequirements

        return SecurityRequirements(
            encryption_required=True,
            decryption_required=True,
            require_encryption_key_exchange=False,  # Only channel encryption, no sealed encryption
            signing_required=False,
            verification_required=False,
            require_key_exchange=False,
            require_signing_key_exchange=False,  # Add this to be explicit
            require_node_authorization=False,
            require_certificates=False,
        )


@pytest.mark.asyncio
async def test_channel_encryption_manager_gets_node_like():
    """Test that ChannelEncryptionManager receives node_like parameter properly."""

    # Create a mock node
    mock_node = MockNode()

    # Create ChannelEncryptionManager directly with node_like parameter
    from naylence.fame.security.encryption.channel.channel_encryption_manager import (
        ChannelEncryptionManager,
    )

    # Test that we can create it with node_like (using type ignore to bypass protocol checking)
    channel_manager = ChannelEncryptionManager(node_like=mock_node)  # type: ignore

    # Verify that the ChannelEncryptionManager has the node_like reference
    assert channel_manager._node_like is mock_node

    print("✅ ChannelEncryptionManager successfully received node_like parameter")

    # Test with None (should also work)
    channel_manager_none = ChannelEncryptionManager(node_like=None)
    assert channel_manager_none._node_like is None

    print("✅ ChannelEncryptionManager accepts None for node_like parameter")


if __name__ == "__main__":
    asyncio.run(test_channel_encryption_manager_gets_node_like())

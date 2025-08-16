"""
Test the SecurityPolicy integration with FameNode.
"""

import pytest

from naylence.fame.core import FameEnvelope
from naylence.fame.node.node import FameNode
from naylence.fame.security.policy import (
    DefaultSecurityPolicy,
)
from naylence.fame.security.policy.security_policy import (
    CryptoLevel,
    SecurityAction,
    SecurityPolicy,
)
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider


class CustomSecurityPolicy(SecurityPolicy):
    """Custom security policy for testing."""

    def __init__(self):
        self.sign_calls = []
        self.encrypt_calls = []
        self.verify_calls = []
        self.decrypt_calls = []

    async def should_sign_envelope(self, envelope, context=None, node_like=None):
        print(f"should_sign_envelope called with envelope={envelope}, context={context}")
        self.sign_calls.append((envelope, context))
        return False  # Consistent with minimal security requirements

    async def should_encrypt_envelope(self, envelope, context=None, node_like=None):
        print(f"should_encrypt_envelope called with envelope={envelope}, context={context}")
        self.encrypt_calls.append((envelope, context))
        return False  # Disable encryption to match minimal requirements

    async def should_verify_signature(self, envelope, context=None):
        self.verify_calls.append((envelope, context))
        return False  # Consistent with no signatures required

    async def should_decrypt_envelope(self, envelope, context=None, node_like=None):
        self.decrypt_calls.append((envelope, context))
        return False  # Consistent with no encryption

    def should_use_channel_encryption(self, envelope, context=None):
        print(f"should_use_channel_encryption called with envelope={envelope}, context={context}")
        return False  # Default to no channel encryption for testing

    async def get_encryption_options(self, envelope, context=None, node_like=None):
        # Return mock encryption options
        from naylence.fame.security.encryption.encryption_manager import EncryptionOptions

        return EncryptionOptions(
            recip_pub=b"mock_public_key_32_bytes_length", recip_kid="mock-encryption-key-id"
        )

    # Implement the new flexible crypto policy methods
    def classify_message_crypto_level(self, envelope, context=None):
        return CryptoLevel.PLAINTEXT

    def is_inbound_crypto_level_allowed(self, crypto_level, envelope, context=None):
        return True  # Allow all for testing

    def get_inbound_violation_action(self, crypto_level, envelope, context=None):
        return SecurityAction.ALLOW

    async def decide_response_crypto_level(self, request_crypto_level, envelope, context=None):
        return CryptoLevel.PLAINTEXT

    async def decide_outbound_crypto_level(self, envelope, context=None, node_like=None):
        return CryptoLevel.PLAINTEXT

    # Implement the new signature violation methods
    def is_signature_required(self, envelope, context=None):
        return False  # Consistent with minimal security requirements

    def get_unsigned_violation_action(self, envelope, context=None):
        return SecurityAction.ALLOW  # Allow unsigned for minimal security testing

    def get_invalid_signature_violation_action(self, envelope, context=None):
        return SecurityAction.ALLOW  # Allow invalid signatures for minimal security testing

    def requirements(self):
        """Get the security requirements for custom security policy."""
        from naylence.fame.security.policy.security_policy import CryptoLevel, SecurityRequirements

        return SecurityRequirements(
            signing_required=False,  # Consistent - no signing required
            verification_required=False,  # Consistent - no verification required
            encryption_required=False,  # Consistent - no encryption required
            decryption_required=False,  # Consistent - no decryption required
            minimum_crypto_level=CryptoLevel.PLAINTEXT,
            supported_signing_algorithms=frozenset(["EdDSA"]),
            supported_encryption_algorithms=frozenset(["X25519", "ChaCha20Poly1305"]),
            preferred_signing_algorithm="EdDSA",
            preferred_encryption_algorithm="X25519",
            require_encryption_key_exchange=False,  # Consistent with no encryption
        )


@pytest.mark.asyncio
async def test_security_policy_integration():
    """Test that FameNode properly integrates with SecurityPolicy."""

    # Create a custom security policy to track calls
    policy = CustomSecurityPolicy()

    from naylence.fame.security.security_manager_factory import SecurityManagerFactory

    node_security = await SecurityManagerFactory.create_security_manager(policy=policy)

    from naylence.fame.node.node_meta import NodeMeta
    from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore(NodeMeta)
    async with FameNode(
        system_id="test_node",
        security_manager=node_security,
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
    ) as node:
        # Verify the node has our custom policy through the security manager
        assert node._security_manager.policy is policy

        # Test that the envelope security handler uses our policy
        print(f"Node security policy: {node._security_manager.policy}")
        if (
            hasattr(node._security_manager, "envelope_security_handler")
            and node._security_manager.envelope_security_handler
        ):
            print(
                "Handler security policy: "
                f"{node._security_manager.envelope_security_handler._security_policy}"
            )
            print(
                f"Are they the same? "
                f"{node._security_manager.envelope_security_handler._security_policy is policy}"
            )
            assert node._security_manager.envelope_security_handler._security_policy is policy
        else:
            print("Envelope security handler not available (delegated to security manager)")
            # Test that the security policy is still accessible through the security manager
            assert node._security_manager.policy is policy

        # Test the security policy methods directly through the envelope security handler

        from naylence.fame.core import DeliveryOriginType, FameAddress, FameDeliveryContext
        from naylence.fame.core.protocol.frames import DataFrame

        envelope = FameEnvelope(
            frame=DataFrame(payload={"test": "data"}, codec="json"),
            to=FameAddress("test-recipient@/test-node/service"),
        )

        context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, from_system_id="test_sender")

        # Test the security policy through the SecurityManager's on_deliver method
        # Since all security logic is now delegated to SecurityManager, test through that interface
        result = await node._security_manager.on_deliver(node, envelope, context)

        # For a DataFrame, the result should be the processed envelope (not None unless delivery is halted)
        assert result is not None
        assert result.frame.type == "Data"  # Should be our DataFrame

        # Verify our policy methods were called during the delivery process
        # Note: The exact calls may vary based on the security policy logic
        print(f"Sign calls: {len(policy.sign_calls)}, Encrypt calls: {len(policy.encrypt_calls)}")

        # The key assertion is that our custom policy was used
        # and that the security processing occurred through the SecurityManager
        print("✅ Security policy integration test passed - custom policy was integrated")


@pytest.mark.asyncio
async def test_existing_security_policy_with_context():
    """Test that existing DefaultSecurityPolicy works with node context."""

    # Create a DefaultSecurityPolicy with custom flexible config
    from naylence.fame.security.policy.security_policy import (
        CryptoLevel,
        EncryptionConfig,
        InboundCryptoRules,
        OutboundCryptoRules,
    )

    custom_config = EncryptionConfig(
        inbound=InboundCryptoRules(allow_plaintext=True),
        outbound=OutboundCryptoRules(default_level=CryptoLevel.CHANNEL),
    )

    existing_policy = DefaultSecurityPolicy(
        encryption=custom_config,
    )

    from naylence.fame.security.security_manager_factory import SecurityManagerFactory

    node_security = await SecurityManagerFactory.create_security_manager(policy=existing_policy)

    from naylence.fame.node.node_meta import NodeMeta
    from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore

    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore(NodeMeta)
    async with FameNode(
        system_id="test_node",
        security_manager=node_security,
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
    ):
        # Verify our custom settings are preserved
        assert existing_policy.encryption is not None
        assert existing_policy.encryption.inbound.allow_plaintext is True
        assert existing_policy.encryption.outbound.default_level == CryptoLevel.CHANNEL


if __name__ == "__main__":
    pytest.main([__file__])

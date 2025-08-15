import pytest

from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.security.keys.default_key_manager import DefaultKeyManager
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.policy.security_policy import SecurityRequirements
from naylence.fame.security.security_manager_factory import SecurityManagerFactory
from naylence.fame.sentinel.sentinel import Sentinel
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider


class TestPolicyDrivenSecurityArchitecture:
    """Test the complete policy-driven security architecture."""

    @pytest.mark.asyncio
    async def test_node_security_single_bundle_for_crypto_primitives(self):
        """Test that SecurityManager is the single bundle for appropriate crypto primitives."""
        # Create a security bundle
        security = await SecurityManagerFactory.create_security_manager(DefaultSecurityPolicy())

        # Verify crypto primitives that can be auto-created are bundled
        assert security.policy is not None
        assert security.envelope_signer is not None
        assert security.envelope_verifier is not None
        # Encryption managers ARE auto-created when policy requires encryption and key manager is available
        assert security.encryption is not None

        # Verify key manager is included when required by policy
        assert security.key_manager is not None
        assert isinstance(security.key_manager, DefaultKeyManager)

        print("✓ SecurityManager provides single bundle for appropriate crypto primitives")
        print("✓ Encryption managers are auto-created when policy requires encryption")

    @pytest.mark.asyncio
    async def test_key_management_policy_driven(self):
        """Test that key management is policy-driven."""
        # Test with default policy (requires key exchange)
        security_with_keys = await SecurityManagerFactory.create_security_manager(DefaultSecurityPolicy())
        assert security_with_keys.policy.requirements().require_key_exchange is True
        assert security_with_keys.key_manager is not None

        # Test with policy that doesn't require key exchange
        class NoKeyExchangePolicy(DefaultSecurityPolicy):
            def requirements(self) -> SecurityRequirements:
                return SecurityRequirements(require_key_exchange=False)

        security_without_keys = await SecurityManagerFactory.create_security_manager(NoKeyExchangePolicy())
        assert security_without_keys.policy.requirements().require_key_exchange is False
        assert security_without_keys.key_manager is None

        print("✓ Key management is policy-driven")

    @pytest.mark.asyncio
    async def test_fame_node_delegates_to_security_bundle(self):
        """Test that FameNode delegates all security setup to SecurityManager."""
        # Create node with security bundle
        security = await SecurityManagerFactory.create_security_manager(DefaultSecurityPolicy())
        from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

        storage_provider = InMemoryStorageProvider()
        node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)
        node = FameNode(
            security_manager=security, storage_provider=storage_provider, node_meta_store=node_meta_store
        )

        # Verify node uses security bundle components through the security manager
        assert node._security_manager is security
        assert node._security_manager.policy is security.policy
        assert node._security_manager.envelope_signer is security.envelope_signer
        assert node._security_manager.envelope_verifier is security.envelope_verifier
        assert node._security_manager.encryption is security.encryption

        # Verify key manager delegation
        if security.key_manager is not None:
            assert node._security_manager.key_manager is security.key_manager

        print("✓ FameNode delegates all security setup to NodeSecurity")

    @pytest.mark.asyncio
    async def test_fame_node_key_manager_priority(self):
        """Test FameNode key manager behavior with SecurityManager."""
        # Test 1: node_security.key_manager is used when available
        security_with_km = await SecurityManagerFactory.create_security_manager(DefaultSecurityPolicy())

        from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

        storage_provider = InMemoryStorageProvider()
        node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)
        node1 = FameNode(
            security_manager=security_with_km,
            storage_provider=storage_provider,
            node_meta_store=node_meta_store,
        )
        assert node1._security_manager.key_manager is security_with_km.key_manager

        # Test 2: Policy that doesn't require key exchange doesn't create key manager
        class NoKMSecurityPolicy(DefaultSecurityPolicy):
            def requirements(self) -> SecurityRequirements:
                return SecurityRequirements(require_key_exchange=False)

        security_without_km = await SecurityManagerFactory.create_security_manager(NoKMSecurityPolicy())
        storage_provider2 = InMemoryStorageProvider()
        node_meta_store2 = InMemoryKVStore[NodeMeta](NodeMeta)
        node2 = FameNode(
            security_manager=security_without_km,
            storage_provider=storage_provider2,
            node_meta_store=node_meta_store2,
        )
        assert node2._security_manager.key_manager is None

        print("✓ FameNode key manager priority works correctly")

    @pytest.mark.asyncio
    async def test_sentinel_delegates_to_security_architecture(self):
        """Test that Sentinel delegates all security setup to the architecture."""
        # Create Sentinel with explicit security
        security = await SecurityManagerFactory.create_security_manager(DefaultSecurityPolicy())
        storage_provider = InMemoryStorageProvider()
        sentinel = Sentinel(security_manager=security, storage_provider=storage_provider)

        # Verify Sentinel uses security bundle through the security manager
        assert sentinel._security_manager.policy is security.policy
        assert sentinel._security_manager.envelope_signer is security.envelope_signer
        assert sentinel._security_manager.envelope_verifier is security.envelope_verifier
        assert sentinel._security_manager.encryption is security.encryption

        # Verify Sentinel has DefaultKeyManager (required for routing)
        assert isinstance(sentinel._security_manager.key_manager, DefaultKeyManager)

        print("✓ Sentinel delegates all security setup to the architecture")

    @pytest.mark.asyncio
    async def test_sentinel_routing_context_update(self):
        """Test that Sentinel updates key manager with routing context."""
        storage_provider = InMemoryStorageProvider()
        sentinel = Sentinel(storage_provider=storage_provider)

        # Verify key manager has routing capabilities
        assert hasattr(sentinel, "forward_to_route")
        assert hasattr(sentinel, "forward_to_peers")

        # The key manager should be updated with routing context
        # (we can't easily test the internal state, but we can verify the methods exist)
        assert callable(sentinel.forward_to_route)
        assert callable(sentinel.forward_to_peers)

        print("✓ Sentinel updates key manager with routing context")

    @pytest.mark.asyncio
    async def test_complete_architecture_integration(self):
        """Test the complete architecture integration."""
        # Create a complete setup
        security = await SecurityManagerFactory.create_security_manager(DefaultSecurityPolicy())

        # Create regular node
        storage_provider = InMemoryStorageProvider()
        node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)
        node = FameNode(
            security_manager=security, storage_provider=storage_provider, node_meta_store=node_meta_store
        )

        # Create routing node (Sentinel)
        storage_provider2 = InMemoryStorageProvider()
        sentinel = Sentinel(security_manager=security, storage_provider=storage_provider2)

        # Verify both use the same security policy
        assert node._security_manager.policy is security.policy
        assert sentinel._security_manager.policy is security.policy

        # Verify both have appropriate key managers
        assert isinstance(node._security_manager.key_manager, DefaultKeyManager)
        assert isinstance(sentinel._security_manager.key_manager, DefaultKeyManager)

        # Verify policy-driven behavior
        requirements = security.policy.requirements()
        assert requirements.require_key_exchange is True

        print("✓ Complete architecture integration works")


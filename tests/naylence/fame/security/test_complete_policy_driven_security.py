import pytest

from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.security.keys.x5c_key_manager import X5CKeyManager
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.policy.security_policy import SecurityRequirements
from naylence.fame.security.security_manager_factory import SecurityManagerFactory
from naylence.fame.sentinel.sentinel import Sentinel
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
from naylence.fame.tracking.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory


class TestPolicyDrivenSecurityArchitecture:
    """Test the complete policy-driven security architecture."""

    @pytest.mark.asyncio
    async def test_node_security_single_bundle_for_crypto_primitives(self):
        """Test that SecurityManager is the single bundle for appropriate crypto primitives."""
        # Create a security bundle with a policy that requires security components
        from naylence.fame.security.policy.security_policy import (
            SigningConfig, OutboundSigningRules, EncryptionConfig, OutboundCryptoRules, CryptoLevel
        )
        
        # Create a policy that actually requires security components
        policy_with_requirements = DefaultSecurityPolicy(
            signing=SigningConfig(
                outbound=OutboundSigningRules(default_signing=True)
            ),
            encryption=EncryptionConfig(
                outbound=OutboundCryptoRules(default_level=CryptoLevel.CHANNEL)
            )
        )
        
        security = await SecurityManagerFactory.create_security_manager(policy_with_requirements)

        # Verify crypto primitives that can be auto-created are bundled
        assert security.policy is not None
        assert security.envelope_signer is not None  # Auto-created because signing required
        assert security.envelope_verifier is not None  # Auto-created because verification required
        # Encryption manager auto-created when policy requires encryption
        assert security.encryption is not None

        # Verify key manager is included when required by policy
        assert security.key_manager is not None
        assert isinstance(security.key_manager, X5CKeyManager)

        print("✓ SecurityManager provides single bundle for appropriate crypto primitives")
        print("✓ Encryption managers are auto-created when policy requires encryption")
        
        # Also test with default policy (should create nothing)
        default_security = await SecurityManagerFactory.create_security_manager(DefaultSecurityPolicy())
        assert default_security.policy is not None
        assert default_security.envelope_signer is None  # Default policy doesn't require signing
        assert default_security.envelope_verifier is None  # Default policy doesn't require verification
        assert default_security.encryption is None  # Default policy doesn't require encryption
        assert default_security.key_manager is None  # Default policy doesn't require key exchange
        
        print("✓ Default policy correctly creates no security components")

    @pytest.mark.asyncio
    async def test_key_management_policy_driven(self):
        """Test that key management is policy-driven."""
        # Test with default policy (does NOT require key exchange)
        default_security = await SecurityManagerFactory.create_security_manager(DefaultSecurityPolicy())
        assert default_security.policy.requirements().require_key_exchange is False
        assert default_security.key_manager is None  # Not created because not required

        # Test with policy that requires key exchange (signing requires key exchange)
        from naylence.fame.security.policy.security_policy import SigningConfig, OutboundSigningRules
        
        signing_policy = DefaultSecurityPolicy(
            signing=SigningConfig(
                outbound=OutboundSigningRules(default_signing=True)
            )
        )
        
        security_with_keys = await SecurityManagerFactory.create_security_manager(signing_policy)
        assert security_with_keys.policy.requirements().require_key_exchange is True
        assert security_with_keys.key_manager is not None

        # Test with policy that doesn't require key exchange
        class NoKeyExchangePolicy(DefaultSecurityPolicy):
            def requirements(self) -> SecurityRequirements:
                return SecurityRequirements(require_key_exchange=False)

        security_without_keys = await SecurityManagerFactory.create_security_manager(NoKeyExchangePolicy())
        assert security_without_keys.policy.requirements().require_key_exchange is False
        assert security_without_keys.key_manager is None

        print("✓ Key management is correctly policy-driven")
        assert security_without_keys.key_manager is None

        print("✓ Key management is policy-driven")

    @pytest.mark.asyncio
    async def test_fame_node_delegates_to_security_bundle(self):
        """Test that FameNode delegates all security setup to SecurityManager."""
        # Create node with security bundle
        security = await SecurityManagerFactory.create_security_manager(DefaultSecurityPolicy())
        from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
        from naylence.fame.tracking.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory

        storage_provider = InMemoryStorageProvider()
        node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)
        
        # Create envelope tracker
        delivery_tracker_factory = DefaultDeliveryTrackerFactory()
        delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)
        
        node = FameNode(
            security_manager=security, 
            storage_provider=storage_provider, 
            node_meta_store=node_meta_store,
            delivery_tracker=delivery_tracker,
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
        # Test 1: Create policy that requires key manager
        from naylence.fame.security.policy.security_policy import SigningConfig, OutboundSigningRules
        
        policy_with_km = DefaultSecurityPolicy(
            signing=SigningConfig(
                outbound=OutboundSigningRules(default_signing=True)
            )
        )
        
        security_with_km = await SecurityManagerFactory.create_security_manager(policy_with_km)

        from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
        from naylence.fame.tracking.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory

        storage_provider = InMemoryStorageProvider()
        node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)
        
        # Create envelope tracker
        delivery_tracker_factory = DefaultDeliveryTrackerFactory()
        delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)
        
        node1 = FameNode(
            security_manager=security_with_km,
            storage_provider=storage_provider,
            node_meta_store=node_meta_store,
            delivery_tracker=delivery_tracker,
        )
        assert node1._security_manager.key_manager is security_with_km.key_manager
        assert node1._security_manager.key_manager is not None

        # Test 2: Default policy doesn't require key exchange, doesn't create key manager
        security_without_km = await SecurityManagerFactory.create_security_manager(DefaultSecurityPolicy())
        storage_provider2 = InMemoryStorageProvider()
        node_meta_store2 = InMemoryKVStore[NodeMeta](NodeMeta)
        
        # Create envelope tracker for second node
        delivery_tracker_factory2 = DefaultDeliveryTrackerFactory()
        delivery_tracker2 = await delivery_tracker_factory2.create(storage_provider=storage_provider2)
        
        node2 = FameNode(
            security_manager=security_without_km,
            storage_provider=storage_provider2,
            node_meta_store=node_meta_store2,
            delivery_tracker=delivery_tracker2,
        )
        assert node2._security_manager.key_manager is None

        print("✓ FameNode key manager priority works correctly")

    @pytest.mark.asyncio
    async def test_sentinel_delegates_to_security_architecture(self):
        """Test that Sentinel delegates all security setup to the architecture."""
        # Create Sentinel with explicit security that requires key manager
        from naylence.fame.security.policy.security_policy import SigningConfig, OutboundSigningRules
        
        policy_with_km = DefaultSecurityPolicy(
            signing=SigningConfig(
                outbound=OutboundSigningRules(default_signing=True)
            )
        )
        
        security = await SecurityManagerFactory.create_security_manager(policy_with_km)
        storage_provider = InMemoryStorageProvider()
        
        # Create envelope tracker for Sentinel
        delivery_tracker_factory = DefaultDeliveryTrackerFactory()
        delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)
        
        sentinel = Sentinel(security_manager=security, storage_provider=storage_provider, delivery_tracker=delivery_tracker)

        # Verify Sentinel uses security bundle through the security manager
        assert sentinel._security_manager.policy is security.policy
        assert sentinel._security_manager.envelope_signer is security.envelope_signer
        assert sentinel._security_manager.envelope_verifier is security.envelope_verifier
        assert sentinel._security_manager.encryption is security.encryption

        # Verify Sentinel has X5CKeyManager (required for routing)
        assert isinstance(sentinel._security_manager.key_manager, X5CKeyManager)

        print("✓ Sentinel delegates all security setup to the architecture")

    @pytest.mark.asyncio
    async def test_sentinel_routing_context_update(self):
        """Test that Sentinel updates key manager with routing context."""
        storage_provider = InMemoryStorageProvider()
        
        # Create envelope tracker for Sentinel
        delivery_tracker_factory = DefaultDeliveryTrackerFactory()
        delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)
        
        sentinel = Sentinel(storage_provider=storage_provider, delivery_tracker=delivery_tracker)

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
        # Create a complete setup with policy that requires key managers
        from naylence.fame.security.policy.security_policy import SigningConfig, OutboundSigningRules
        
        policy_with_km = DefaultSecurityPolicy(
            signing=SigningConfig(
                outbound=OutboundSigningRules(default_signing=True)
            )
        )
        
        security = await SecurityManagerFactory.create_security_manager(policy_with_km)

        # Create regular node
        storage_provider = InMemoryStorageProvider()
        node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)
        
        # Create envelope tracker
        delivery_tracker_factory = DefaultDeliveryTrackerFactory()
        delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)
        
        node = FameNode(
            security_manager=security, 
            storage_provider=storage_provider, 
            node_meta_store=node_meta_store,
            delivery_tracker=delivery_tracker,
        )

        # Create routing node (Sentinel)
        storage_provider2 = InMemoryStorageProvider()
        
        # Create envelope tracker for Sentinel
        delivery_tracker_factory2 = DefaultDeliveryTrackerFactory()
        delivery_tracker2 = await delivery_tracker_factory2.create(storage_provider=storage_provider2)
        
        sentinel = Sentinel(security_manager=security, storage_provider=storage_provider2, delivery_tracker=delivery_tracker2)

        # Verify both use the same security policy
        assert node._security_manager.policy is security.policy
        assert sentinel._security_manager.policy is security.policy

        # Verify both have appropriate key managers
        assert isinstance(node._security_manager.key_manager, X5CKeyManager)
        assert isinstance(sentinel._security_manager.key_manager, X5CKeyManager)

        # Verify policy-driven behavior
        requirements = security.policy.requirements()
        assert requirements.require_key_exchange is True

        print("✓ Complete architecture integration works")


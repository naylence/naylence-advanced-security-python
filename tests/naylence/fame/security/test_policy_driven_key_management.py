import pytest

from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.security_manager_factory import SecurityManagerFactory
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore


@pytest.mark.asyncio
async def test_policy_driven_key_management():
    """Test that key management is policy-driven and only instantiated when required."""

    # Test 1: Default policy does NOT require key exchange
    default_policy = DefaultSecurityPolicy()
    default_requirements = default_policy.requirements()
    assert default_requirements.require_key_exchange is False

    default_security = await SecurityManagerFactory.create_security_manager(policy=default_policy)
    assert default_security.key_manager is None  # Not created because not required
    assert default_security.policy is default_policy

    # Test 2: Policy that requires key exchange (signing requires key exchange)
    from naylence.fame.security.policy.security_policy import (
        OutboundSigningRules,
        SigningConfig,
    )

    policy_with_signing = DefaultSecurityPolicy(
        signing=SigningConfig(outbound=OutboundSigningRules(default_signing=True))
    )

    signing_requirements = policy_with_signing.requirements()
    assert signing_requirements.require_key_exchange is True

    signing_security = await SecurityManagerFactory.create_security_manager(policy=policy_with_signing)
    assert signing_security.key_manager is not None
    assert signing_security.policy is policy_with_signing

    # Test 3: FameNode uses key_manager from SecurityManager when it exists
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
    from naylence.fame.tracking.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory

    storage_provider = InMemoryStorageProvider()

    # Create delivery tracker
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

    node_with_key_manager = FameNode(
        system_id="test_node_with_key_manager",
        security_manager=signing_security,  # This one has a key manager
        storage_provider=storage_provider,
        node_meta_store=InMemoryKVStore[NodeMeta](NodeMeta),
        delivery_tracker=delivery_tracker,
    )
    assert node_with_key_manager._security_manager.key_manager is not None

    # Test 4: FameNode doesn't have key_manager when policy doesn't require it
    storage_provider2 = InMemoryStorageProvider()

    # Create delivery tracker for second node
    delivery_tracker_factory2 = DefaultDeliveryTrackerFactory()
    delivery_tracker2 = await delivery_tracker_factory2.create(storage_provider=storage_provider2)

    node_without_key_manager = FameNode(
        system_id="test_node_without_key_manager",
        security_manager=default_security,  # This one doesn't have a key manager
        storage_provider=storage_provider2,
        node_meta_store=InMemoryKVStore[NodeMeta](NodeMeta),
        delivery_tracker=delivery_tracker2,
    )
    assert node_without_key_manager._security_manager.key_manager is None

    print("✓ Key management is correctly policy-driven")
    # FameNode should not create a key_manager when the policy doesn't require key exchange
    assert node_without_key_manager._security_manager.key_manager is None

    print("Policy-driven key management test passed!")


@pytest.mark.asyncio
async def test_node_security_key_manager_priority():
    """Test that SecurityManager handles all key manager creation based on policy."""

    # Test 1: Policy that requires key exchange creates key manager
    from naylence.fame.security.policy.security_policy import OutboundSigningRules, SigningConfig

    policy_with_km = DefaultSecurityPolicy(
        signing=SigningConfig(outbound=OutboundSigningRules(default_signing=True))
    )

    security_with_key_manager = await SecurityManagerFactory.create_security_manager(policy_with_km)
    assert security_with_key_manager.key_manager is not None

    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
    from naylence.fame.tracking.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory

    storage_provider = InMemoryStorageProvider()

    # Create delivery tracker
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

    node_with_key_manager = FameNode(
        system_id="test_node_with_key_manager",
        security_manager=security_with_key_manager,
        storage_provider=storage_provider,
        node_meta_store=InMemoryKVStore[NodeMeta](NodeMeta),
        delivery_tracker=delivery_tracker,
    )

    # Should use the key_manager from SecurityManager
    assert node_with_key_manager._security_manager.key_manager is security_with_key_manager.key_manager

    # Test 2: Default policy doesn't require key exchange, doesn't create key manager
    default_security = await SecurityManagerFactory.create_security_manager(DefaultSecurityPolicy())
    assert default_security.key_manager is None

    storage_provider2 = InMemoryStorageProvider()

    # Create delivery tracker for second node
    delivery_tracker_factory2 = DefaultDeliveryTrackerFactory()
    delivery_tracker2 = await delivery_tracker_factory2.create(storage_provider=storage_provider2)

    node_without_key_manager = FameNode(
        system_id="test_node_without_key_manager",
        security_manager=default_security,
        storage_provider=storage_provider2,
        node_meta_store=InMemoryKVStore[NodeMeta](NodeMeta),
        delivery_tracker=delivery_tracker2,
    )

    # Should have no key manager
    assert node_without_key_manager._security_manager.key_manager is None

    print("SecurityManager key_manager priority test passed!")


if __name__ == "__main__":
    import asyncio

    asyncio.run(test_policy_driven_key_management())
    asyncio.run(test_node_security_key_manager_priority())
    print("All tests passed!")

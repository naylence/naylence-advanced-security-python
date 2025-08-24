from collections.abc import Iterable
from unittest.mock import Mock

import pytest

from naylence.fame.security.keys.x5c_key_manager import X5CKeyManager
from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore
from naylence.fame.security.keys.key_manager import KeyManager
from naylence.fame.sentinel.key_frame_handler import KeyFrameHandler
from naylence.fame.sentinel.sentinel import Sentinel
from naylence.fame.tracking.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory


@pytest.mark.asyncio
async def test_default_key_manager_implements_interface():
    """Test that X5CKeyManager properly implements KeyManager interface."""
    print("Testing X5CKeyManager implements interface...")

    key_store = InMemoryKeyStore()
    key_manager = X5CKeyManager(key_store=key_store)

    # Verify it implements the interface
    assert isinstance(key_manager, KeyManager)

    # Test the new get_keys_for_path method
    keys = await key_manager.get_keys_for_path("/test/path")
    assert isinstance(keys, Iterable)

    print("✓ X5CKeyManager implements KeyManager interface correctly")


@pytest.mark.asyncio
async def test_sentinel_works_with_key_manager_interface():
    """Test that Sentinel can work with KeyManager interface without requiring X5CKeyManager."""
    print("Testing Sentinel works with KeyManager interface...")

    # Create a real X5CKeyManager that implements KeyManager
    key_store = InMemoryKeyStore()
    X5CKeyManager(key_store=key_store)

    # Verify Sentinel can be created with any KeyManager implementation
    # (Previously it required specifically X5CKeyManager)
    from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
    from naylence.fame.security.policy.security_policy import SigningConfig, OutboundSigningRules
    from naylence.fame.security.security_manager_factory import SecurityManagerFactory
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    # Create a policy that requires key management (signing requires key management)
    policy_with_key_mgmt = DefaultSecurityPolicy(
        signing=SigningConfig(
            outbound=OutboundSigningRules(default_signing=True)
        )
    )

    # Create SecurityManager with the key manager
    node_security = await SecurityManagerFactory.create_security_manager(policy_with_key_mgmt)

    # Create required storage provider
    storage_provider = InMemoryStorageProvider()

    # Create envelope tracker for Sentinel
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

    # Sentinel should work with any KeyManager implementation
    # No specific type checking for X5CKeyManager anymore
    sentinel = Sentinel(security_manager=node_security, storage_provider=storage_provider, delivery_tracker=delivery_tracker)

    # Verify the key manager is accessible and is a KeyManager
    assert isinstance(sentinel._security_manager.key_manager, KeyManager)
    assert hasattr(sentinel._security_manager.key_manager, "get_keys_for_path")

    print("✓ Sentinel works with KeyManager interface without requiring X5CKeyManager")


@pytest.mark.asyncio
async def test_key_frame_handler_uses_interface():
    """Test that KeyFrameHandler uses KeyManager interface methods."""
    print("Testing KeyFrameHandler uses KeyManager interface...")

    # Create mocks
    routing_node = Mock()
    key_manager = Mock(spec=KeyManager)  # Mock the interface, not X5CKeyManager
    key_manager.get_keys_for_path.return_value = []
    route_manager = Mock()
    binding_manager = Mock()
    accept_key_announce_parent = Mock()

    # Create KeyFrameHandler - should work with KeyManager interface
    handler = KeyFrameHandler(
        routing_node=routing_node,
        key_manager=key_manager,
        route_manager=route_manager,
        binding_manager=binding_manager,
        accept_key_announce_parent=accept_key_announce_parent,
    )

    # Verify it stores the key manager as KeyManager interface
    assert hasattr(handler._key_manager, "get_keys_for_path")

    print("✓ KeyFrameHandler uses KeyManager interface correctly")


@pytest.mark.asyncio
async def test_no_default_key_manager_specific_dependencies():
    """Test that no critical code depends on X5CKeyManager specifically."""
    print("Testing no X5CKeyManager-specific dependencies...")

    # Check the actual source file content
    import os

    # Find the project root by going up from the test file
    project_root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    )
    key_frame_handler_file = os.path.join(project_root, "../naylence-fame-runtime/src/naylence/fame/sentinel/key_frame_handler.py")

    with open(key_frame_handler_file) as f:
        source_content = f.read()

    # Should import KeyManager interface
    assert "from naylence.fame.security.keys.key_manager import KeyManager" in source_content
    # Should not import X5CKeyManager anymore
    assert (
        "from naylence.fame.security.keys.default_key_manager import X5CKeyManager"
        not in source_content
    )

    print("✓ Critical classes only depend on KeyManager interface")


if __name__ == "__main__":
    import asyncio

    async def run_tests():
        await test_key_manager_interface_completeness()
        await test_default_key_manager_implements_interface()
        await test_sentinel_works_with_key_manager_interface()
        await test_key_frame_handler_uses_interface()
        await test_no_default_key_manager_specific_dependencies()
        print("\n🎉 All interface tests passed! KeyManager interface is complete and properly used.")

    asyncio.run(run_tests())

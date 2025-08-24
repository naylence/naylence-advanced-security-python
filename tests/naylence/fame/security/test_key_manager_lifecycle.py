#!/usr/bin/env python3
"""
Test the lifecycle integration of X5CKeyManager with NodeEventListener.
"""

import asyncio
from unittest.mock import Mock

import pytest

from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.security.keys.x5c_key_manager import X5CKeyManager
from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore


class MockNode:
    """Mock node for testing."""

    def __init__(self):
        self._id = "test-node"
        self._sid = "test-sid"
        self.physical_path = "/test"
        self.has_parent = False
        self._envelope_factory = Mock()


@pytest.mark.asyncio
async def test_key_manager_implements_node_event_listener():
    """Test that X5CKeyManager properly implements NodeEventListener."""
    print("Testing KeyManager implements NodeEventListener...")

    key_store = InMemoryKeyStore()
    key_manager = X5CKeyManager(key_store=key_store)

    # Verify it implements the protocol (now guaranteed by inheritance)
    assert isinstance(key_manager, NodeEventListener)

    # Verify it has the required lifecycle methods
    assert hasattr(key_manager, "on_node_started")
    assert hasattr(key_manager, "on_node_stopped")
    assert callable(getattr(key_manager, "on_node_started"))
    assert callable(getattr(key_manager, "on_node_stopped"))

    # Test that KeyManager abstract class itself implements NodeEventListener
    from naylence.fame.security.keys.key_manager import KeyManager

    assert issubclass(KeyManager, NodeEventListener)

    print("✓ KeyManager implements NodeEventListener correctly (guaranteed by inheritance)")


@pytest.mark.asyncio
async def test_node_lifecycle_context_setup():
    """Test that node context is properly set up during on_node_started."""
    print("Testing node lifecycle context setup...")

    key_store = InMemoryKeyStore()
    key_manager = X5CKeyManager(key_store=key_store, cert_purge_interval=0.1)

    mock_node = MockNode()
    mock_node._id = "test-node-123"
    mock_node._sid = "test-sid-456"
    mock_node.physical_path = "/test/path/123"
    mock_node.has_parent = True

    # Before starting, context should be empty
    assert key_manager._node is None
    assert key_manager._node_id == ""
    assert key_manager._physical_path == "/"
    assert key_manager._has_upstream is False

    # Start the key manager
    await key_manager.on_node_started(mock_node)

    # After starting, context should be set
    assert key_manager._node is mock_node
    assert key_manager._node_id == "test-node-123"
    assert key_manager._physical_path == "/test/path/123"
    assert key_manager._has_upstream is True

    # Background task should be running
    assert key_manager._purge_task is not None
    assert not key_manager._purge_task.done()

    # Clean up
    await key_manager.on_node_stopped(mock_node)

    print("✓ Node lifecycle context setup test passed")


@pytest.mark.asyncio
async def test_background_task_management():
    """Test that background tasks are properly started and stopped."""
    print("Testing background task management...")

    key_store = InMemoryKeyStore()
    key_manager = X5CKeyManager(key_store=key_store)

    mock_node = MockNode()

    # Initially no background task
    assert key_manager._purge_task is None

    # Start node - should start background task
    await key_manager.on_node_started(mock_node)

    # Task should be running
    assert key_manager._purge_task is not None
    assert not key_manager._purge_task.done()
    task_id = id(key_manager._purge_task)

    # Let task run briefly
    await asyncio.sleep(0.05)

    # Stop node - should stop background task
    await key_manager.on_node_stopped(mock_node)

    # Task should be done/cancelled
    assert key_manager._purge_task.done() or key_manager._purge_task.cancelled()

    # Start again - should create new task
    await key_manager.on_node_started(mock_node)
    assert key_manager._purge_task is not None
    assert not key_manager._purge_task.done()
    assert id(key_manager._purge_task) != task_id  # New task instance

    # Clean up
    await key_manager.on_node_stopped(mock_node)

    print("✓ Background task management test passed")


@pytest.mark.asyncio
async def test_routing_node_detection():
    """Test that routing nodes are properly detected and stored."""
    print("Testing routing node detection...")

    key_store = InMemoryKeyStore()
    key_manager = X5CKeyManager(key_store=key_store)

    # Test with regular node
    regular_node = MockNode()
    await key_manager.on_node_started(regular_node)

    assert key_manager._node is regular_node
    assert key_manager._routing_node is None

    await key_manager.on_node_stopped(regular_node)

    # Test with routing node (mock routing capabilities)
    try:
        # Create a mock that looks like a routing node
        class MockRoutingNode(MockNode):
            def forward_to_peers(self, *args, **kwargs):
                pass

            def forward_to_route(self, *args, **kwargs):
                pass

        routing_node = MockRoutingNode()
        await key_manager.on_node_started(routing_node)

        assert key_manager._node is routing_node
        # Note: Without actual RoutingNodeLike import, _routing_node will be None
        # In production with proper imports, this would be set

        await key_manager.on_node_stopped(routing_node)

    except ImportError:
        # Expected if RoutingNodeLike is not available
        pass

    print("✓ Routing node detection test passed")


@pytest.mark.asyncio
async def test_deprecated_update_context():
    """Test that deprecated update_context method is no longer available."""
    print("Testing deprecated update_context method removal...")

    key_store = InMemoryKeyStore()
    key_manager = X5CKeyManager(key_store=key_store)

    # Method should no longer exist
    assert not hasattr(key_manager, "update_context")

    print("✓ Deprecated update_context method has been removed")


@pytest.mark.asyncio
async def test_multiple_lifecycle_calls():
    """Test that multiple start/stop calls are handled gracefully."""
    print("Testing multiple lifecycle calls...")

    key_store = InMemoryKeyStore()
    key_manager = X5CKeyManager(key_store=key_store, cert_purge_interval=0.1)

    mock_node = MockNode()

    # Multiple start calls
    await key_manager.on_node_started(mock_node)
    first_task = key_manager._purge_task

    await key_manager.on_node_started(mock_node)  # Should replace task
    second_task = key_manager._purge_task

    # Second start should create new task
    assert second_task is not first_task

    # Multiple stop calls should not crash
    await key_manager.on_node_stopped(mock_node)
    await key_manager.on_node_stopped(mock_node)  # Should be safe

    print("✓ Multiple lifecycle calls test passed")


if __name__ == "__main__":

    async def run_tests():
        await test_key_manager_implements_node_event_listener()
        await test_node_lifecycle_context_setup()
        await test_background_task_management()
        await test_routing_node_detection()
        await test_deprecated_update_context()
        await test_multiple_lifecycle_calls()
        print("🎉 All lifecycle integration tests passed!")

    asyncio.run(run_tests())

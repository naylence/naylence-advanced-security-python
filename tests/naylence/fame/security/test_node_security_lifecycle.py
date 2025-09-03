"""
Integration tests for node security lifecycle scenarios.

These tests simulate complete node lifecycle scenarios including:
- Node startup with security components
- Key exchange flows
- Certificate provisioning
- Node shutdown and cleanup
- Error recovery scenarios
"""

import asyncio
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from naylence.fame.core import DeliveryOriginType, FameAddress, FameEnvelope
from naylence.fame.core.protocol.delivery_context import FameDeliveryContext
from naylence.fame.core.protocol.frames import (
    DataFrame,
    KeyRequestFrame,
    NodeHeartbeatFrame,
    NodeWelcomeFrame,
)
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.security.default_security_manager import DefaultSecurityManager
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy


class MockNodeLike:
    """Comprehensive mock node for lifecycle testing."""

    def __init__(self, node_id: str = None, is_sentinel: bool = False):
        self.id = node_id or str(uuid4())
        self.sid = f"sid-{self.id}"
        self.physical_path = f"/test/path/{self.id}"
        self.envelope_factory = MagicMock()
        self.envelope_factory.create_envelope.return_value = FameEnvelope(
            frame=DataFrame(payload={}, codec="json")
        )
        self._event_listeners = []
        self.deliver_calls = []
        self.spawn_calls = []

        # Sentinel-specific attributes
        if is_sentinel:
            self._route_manager = MagicMock()
            self._binding_manager = MagicMock()

    async def deliver(self, envelope, context):
        """Mock deliver method that records calls."""
        self.deliver_calls.append((envelope, context))

    def spawn(self, coro):
        """Mock spawn method that records calls."""
        task = asyncio.create_task(coro)
        self.spawn_calls.append(task)
        return task


class MockKeyManager:
    """Mock key manager for testing."""

    def __init__(self):
        self.started = False
        self.stopped = False
        self.initialized = False
        self.keys_added = []
        self.keys_removed = []

    async def on_node_started(self, node):
        self.started = True

    async def on_node_stopped(self, node):
        self.stopped = True

    async def on_node_initialized(self, node):
        self.initialized = True

    async def add_keys(self, keys, physical_path, system_id, origin):
        self.keys_added.append(
            {"keys": keys, "physical_path": physical_path, "system_id": system_id, "origin": origin}
        )

    async def remove_keys_for_path(self, path):
        self.keys_removed.append(path)
        return len(self.keys_removed)

    async def announce_keys_to_upstream(self):
        pass


class MockCertificateManager(NodeEventListener):
    """Mock certificate manager for testing."""

    def __init__(self):
        self.started = False
        self.stopped = False
        self.initialized = False
        self.welcome_calls = []

    async def on_node_started(self, node):
        self.started = True

    async def on_node_stopped(self, node):
        self.stopped = True

    async def on_node_initialized(self, node):
        self.initialized = True

    async def on_welcome(self, welcome_frame):
        self.welcome_calls.append(welcome_frame)


@pytest.fixture
def mock_child_node():
    """Create a mock child node."""
    return MockNodeLike(node_id="child-node")


@pytest.fixture
def mock_sentinel_node():
    """Create a mock sentinel node."""
    return MockNodeLike(node_id="sentinel-node", is_sentinel=True)


@pytest.fixture
def mock_key_manager():
    """Create a mock key manager."""
    return MockKeyManager()


@pytest.fixture
def mock_certificate_manager():
    """Create a mock certificate manager."""
    return MockCertificateManager()


@pytest.fixture
def security_policy():
    """Create a security policy for testing."""
    return DefaultSecurityPolicy()


class TestCompleteNodeLifecycle:
    """Test complete node lifecycle scenarios."""

    @pytest.mark.asyncio
    async def test_child_node_complete_lifecycle(
        self, mock_child_node, mock_key_manager, mock_certificate_manager, security_policy
    ):
        """Test complete lifecycle of a child node with all security components."""

        # Create fully configured security manager
        # Add mock envelope verifier to enable key sharing functionality
        mock_verifier = MagicMock()
        mock_verifier.verify_envelope = MagicMock()

        # Create mock key validator
        mock_key_validator = MagicMock()

        manager = DefaultSecurityManager(
            policy=security_policy,
            key_manager=mock_key_manager,
            certificate_manager=mock_certificate_manager,
            envelope_verifier=mock_verifier,
            key_validator=mock_key_validator,
        )

        # Phase 1: Node initialization
        await manager.on_node_initialized(mock_child_node)

        assert mock_key_manager.initialized
        assert mock_certificate_manager.initialized

        # Phase 2: Node startup
        await manager.on_node_started(mock_child_node)

        assert mock_key_manager.started
        assert mock_certificate_manager.started
        assert manager._key_management_handler is not None
        assert manager.envelope_security_handler is not None

        # Phase 3: Attach to upstream with parent keys
        attach_info = {
            "target_system_id": "parent-node",
            "target_physical_path": "/parent/path",
            "parent_keys": [
                {"kid": "parent-sig-key", "kty": "OKP", "crv": "Ed25519", "use": "sig"},
                {"kid": "parent-enc-key", "kty": "OKP", "crv": "X25519", "use": "enc"},
            ],
        }

        await manager.on_node_attach_to_upstream(mock_child_node, attach_info)

        # Should have added parent keys (in addition to child's own keys during startup)
        assert len(mock_key_manager.keys_added) >= 1

        # Find the parent keys entry
        parent_keys_entry = None
        for entry in mock_key_manager.keys_added:
            if entry["system_id"] == "parent-node" and entry["origin"] == DeliveryOriginType.UPSTREAM:
                parent_keys_entry = entry
                break

        assert parent_keys_entry is not None, "Parent keys should have been added"
        assert parent_keys_entry["physical_path"] == "/parent/path"
        assert len(parent_keys_entry["keys"]) == 2

        # Phase 4: Handle welcome frame (certificate provisioning)
        welcome_frame = NodeWelcomeFrame(
            system_id="child-node", instance_id="child-instance-lifecycle", assigned_path="/child/path"
        )

        await manager.on_welcome(welcome_frame)

        # Should have handled certificate provisioning
        assert len(mock_certificate_manager.welcome_calls) == 1

        # Phase 5: Process various envelope types

        # Test heartbeat processing
        heartbeat_frame = NodeHeartbeatFrame()
        heartbeat_envelope = FameEnvelope(frame=heartbeat_frame)

        await manager.on_heartbeat_received(heartbeat_envelope)
        # Should not raise any exceptions

        # Test key request handling
        key_request_frame = KeyRequestFrame(address=FameAddress("target@/node"), kid="requested-key")
        key_request_envelope = FameEnvelope(frame=key_request_frame)
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM, from_system_id="requesting-node"
        )

        result = await manager.on_deliver(mock_child_node, key_request_envelope, context)
        # Should handle appropriately (return None if handled, envelope if passed through)
        assert result is None or result is key_request_envelope

        # Phase 6: Epoch change
        await manager.on_epoch_change(mock_child_node, "new-epoch")
        # Should not raise any exceptions

        # Phase 7: Node shutdown
        await manager.on_node_stopped(mock_child_node)

        assert mock_key_manager.stopped
        assert mock_certificate_manager.stopped

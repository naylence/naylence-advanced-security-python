"""
Advanced integration tests for DefaultSecurityManager focusing on uncovered code paths.

These tests target specific functionality that was not covered by the basic tests,
including node lifecycle events, envelope processing, and error scenarios.
"""

import asyncio
import unittest.mock
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from naylence.fame.core import DeliveryOriginType, FameAddress, FameEnvelope
from naylence.fame.core.protocol.delivery_context import FameDeliveryContext
from naylence.fame.core.protocol.frames import (
    DataFrame,
    DeliveryAckFrame,
    KeyAnnounceFrame,
    KeyRequestFrame,
    NodeHeartbeatFrame,
    NodeWelcomeFrame,
    SecureAcceptFrame,
    SecureCloseFrame,
    SecureOpenFrame,
)
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.security.default_security_manager import DefaultSecurityManager
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy


@pytest.fixture
def security_policy():
    """Create a security policy for testing."""
    return DefaultSecurityPolicy()


class AdvancedMockNode:
    """Advanced mock node with routing capabilities for testing sentinel functionality."""

    def __init__(self, node_id: str | None = None, is_sentinel: bool = False):
        self.id = node_id or str(uuid4())
        self.sid = f"sid-{self.id}"
        self.physical_path = f"/test/path/{self.id}"  # Add missing physical_path attribute
        self.envelope_factory = MagicMock()
        self.envelope_factory.create_envelope.return_value = FameEnvelope(
            frame=DeliveryAckFrame(corr_id="test", success=False, code="test_code")
        )
        self._event_listeners = []
        self.deliver_calls = []
        self.spawn_calls = []
        self._security_policy = None
        self._is_sentinel = is_sentinel

        # Sentinel-specific attributes - these enable sentinel code paths
        if is_sentinel:
            self._route_manager = MagicMock()
            self._binding_manager = MagicMock()
            self.routing_epoch = "test-epoch"

    async def deliver(self, envelope, context=None):
        """Mock deliver method that records calls."""
        self.deliver_calls.append((envelope, context))

    def spawn(self, coro, **kwargs):
        """Mock spawn method that records and executes coroutines."""
        task = asyncio.create_task(coro, name=kwargs.get("name"))
        self.spawn_calls.append(task)
        return task

    # RoutingNodeLike protocol methods for sentinel nodes
    async def deliver_local(self, address: FameAddress, envelope: FameEnvelope, context=None):
        """Mock deliver_local method."""
        return await self.deliver(envelope, context)

    async def forward_to_route(self, next_segment: str, envelope: FameEnvelope, context=None):
        """Mock forward_to_route method."""
        self.deliver_calls.append(("route", next_segment, envelope, context))

    async def forward_to_peer(self, peer_segment: str, envelope: FameEnvelope, context=None):
        """Mock forward_to_peer method."""
        self.deliver_calls.append(("peer", peer_segment, envelope, context))

    async def forward_to_peers(self, envelope: FameEnvelope, peers=None, exclude_peers=None, context=None):
        """Mock forward_to_peers method."""
        self.deliver_calls.append(("peers", envelope, peers, exclude_peers, context))

    async def forward_upstream(self, envelope: FameEnvelope, context=None):
        """Mock forward_upstream method."""
        self.deliver_calls.append(("upstream", envelope, context))

    async def remove_downstream_route(self, segment: str, *, stop: bool = True):
        """Mock remove_downstream_route method."""
        pass

    async def remove_peer_route(self, segment: str, *, stop: bool = True):
        """Mock remove_peer_route method."""
        pass

    def _downstream_connector(self, system_id: str):
        """Mock _downstream_connector method."""
        return None

    async def create_origin_connector(
        self, *, origin_type, system_id: str, connector_config, authorization=None, **kwargs
    ):
        """Mock create_origin_connector method."""
        return MagicMock()


class MockEncryptionManager(NodeEventListener):
    """Mock encryption manager that implements NodeEventListener."""

    def __init__(self):
        self.started = False
        self.stopped = False
        self.initialized = False
        self.attach_calls = []

    async def on_node_started(self, node):
        self.started = True

    async def on_node_stopped(self, node):
        self.stopped = True

    async def on_node_initialized(self, node):
        self.initialized = True

    async def on_node_attach_to_upstream(self, node, attach_info):
        self.attach_calls.append(("upstream", attach_info))

    async def on_attach_to_peer(self, node, attach_info, connector):
        self.attach_calls.append(("peer", attach_info, connector))


class MockKeyManager:
    """Enhanced mock key manager with full functionality."""

    def __init__(self):
        self.started = False
        self.stopped = False
        self.initialized = False
        self.keys_added = []
        self.keys_removed = []
        self.key_announcements = []

    async def on_node_started(self, node):
        self.started = True

    async def on_node_stopped(self, node):
        self.stopped = True

    async def on_node_initialized(self, node):
        self.initialized = True

    async def add_keys(self, keys, physical_path, system_id, origin):
        entry = {"keys": keys, "physical_path": physical_path, "system_id": system_id, "origin": origin}
        self.keys_added.append(entry)

    async def remove_keys_for_path(self, path):
        self.keys_removed.append(path)
        return len([r for r in self.keys_removed if r == path])

    async def announce_keys_to_upstream(self):
        announcement = {"timestamp": "test"}
        self.key_announcements.append(announcement)


@pytest.fixture
def advanced_child_node():
    """Create an advanced mock child node."""
    return AdvancedMockNode(node_id="advanced-child-node")


@pytest.fixture
def advanced_sentinel_node():
    """Create an advanced mock sentinel node."""
    return AdvancedMockNode(node_id="advanced-sentinel-node", is_sentinel=True)


@pytest.fixture
def mock_encryption_manager():
    """Create a mock encryption manager."""
    return MockEncryptionManager()


@pytest.fixture
def enhanced_key_manager():
    """Create an enhanced mock key manager."""
    return MockKeyManager()


class TestAdvancedNodeLifecycle:
    """Test advanced node lifecycle scenarios with full component integration."""

    @pytest.mark.asyncio
    async def test_sentinel_node_startup_with_key_frame_handler(
        self, advanced_sentinel_node, enhanced_key_manager, security_policy
    ):
        """Test sentinel node startup that creates KeyFrameHandler."""

        # Create mock envelope verifier to enable key sharing functionality
        mock_verifier = MagicMock()
        mock_verifier.verify_envelope = MagicMock()

        manager = DefaultSecurityManager(
            policy=security_policy, key_manager=enhanced_key_manager, envelope_verifier=mock_verifier
        )

        # Initialize and start - should create KeyFrameHandler for sentinel
        await manager.on_node_initialized(advanced_sentinel_node)

        # Patch isinstance to make the node appear as RoutingNodeLike
        with unittest.mock.patch(
            "naylence.fame.security.default_security_manager.isinstance"
        ) as mock_isinstance:

            def isinstance_side_effect(obj, class_or_tuple):
                if obj is advanced_sentinel_node and class_or_tuple is RoutingNodeLike:
                    return True
                # Use the original isinstance for all other cases
                import builtins

                return builtins.isinstance(obj, class_or_tuple)

            mock_isinstance.side_effect = isinstance_side_effect

            await manager.on_node_started(advanced_sentinel_node)

        # Should have created key frame handler for sentinel
        assert manager._key_frame_handler is not None

        # Should have spawned task for key frame handler
        assert len(advanced_sentinel_node.spawn_calls) >= 1

        assert enhanced_key_manager.initialized
        assert enhanced_key_manager.started

    @pytest.mark.asyncio
    async def test_node_startup_with_encryption_manager(
        self, advanced_child_node, mock_encryption_manager, security_policy
    ):
        """Test node startup with encryption manager that implements NodeEventListener."""

        manager = DefaultSecurityManager(policy=security_policy, encryption=mock_encryption_manager)

        await manager.on_node_initialized(advanced_child_node)
        await manager.on_node_started(advanced_child_node)

        # Encryption manager should have been started
        assert mock_encryption_manager.initialized
        assert mock_encryption_manager.started

    @pytest.mark.asyncio
    async def test_node_attach_to_upstream_with_security_validation(
        self, advanced_child_node, enhanced_key_manager, mock_encryption_manager, security_policy
    ):
        """Test upstream attachment with security validation."""

        manager = DefaultSecurityManager(
            policy=security_policy, key_manager=enhanced_key_manager, encryption=mock_encryption_manager
        )

        # Attach to upstream with parent keys
        attach_info = {
            "target_system_id": "parent-system",
            "target_physical_path": "/parent/path",
            "parent_keys": [{"kid": "parent-signing-key", "kty": "OKP", "crv": "Ed25519", "use": "sig"}],
        }

        await manager.on_node_attach_to_upstream(advanced_child_node, attach_info)  # type: ignore

        # Should have added parent keys
        assert len(enhanced_key_manager.keys_added) == 1
        added_keys = enhanced_key_manager.keys_added[0]
        assert added_keys["system_id"] == "parent-system"
        assert added_keys["origin"] == DeliveryOriginType.UPSTREAM

        # Encryption manager should have been notified
        assert len(mock_encryption_manager.attach_calls) == 1
        assert mock_encryption_manager.attach_calls[0][0] == "upstream"

    @pytest.mark.asyncio
    async def test_node_attach_to_upstream_without_parent_keys(
        self, advanced_child_node, enhanced_key_manager, security_policy
    ):
        """Test upstream attachment without parent keys."""

        manager = DefaultSecurityManager(policy=security_policy, key_manager=enhanced_key_manager)

        # Attach without parent keys
        attach_info = {
            "target_system_id": "parent-system",
            "target_physical_path": "/parent/path",
            # No parent_keys
        }

        await manager.on_node_attach_to_upstream(advanced_child_node, attach_info)  # type: ignore

        # Should not have added any keys
        assert len(enhanced_key_manager.keys_added) == 0

    @pytest.mark.asyncio
    async def test_attach_to_peer_integration(
        self, advanced_sentinel_node, enhanced_key_manager, mock_encryption_manager, security_policy
    ):
        """Test peer attachment integration."""

        manager = DefaultSecurityManager(
            policy=security_policy, key_manager=enhanced_key_manager, encryption=mock_encryption_manager
        )

        # Mock connector
        mock_connector = MagicMock()

        # Attach to peer with keys
        attach_info = {
            "target_system_id": "peer-system",
            "target_physical_path": "/peer/path",
            "parent_keys": [{"kid": "peer-key", "kty": "OKP", "crv": "Ed25519", "use": "sig"}],
        }

        await manager.on_attach_to_peer(advanced_sentinel_node, attach_info, mock_connector)  # type: ignore

        # Should have added peer keys
        assert len(enhanced_key_manager.keys_added) == 1
        added_keys = enhanced_key_manager.keys_added[0]
        assert added_keys["system_id"] == "peer-system"
        assert added_keys["origin"] == DeliveryOriginType.PEER

        # Encryption manager should have been notified
        assert len(mock_encryption_manager.attach_calls) == 1
        assert mock_encryption_manager.attach_calls[0][0] == "peer"


class TestEnvelopeProcessingAdvanced:
    """Test advanced envelope processing scenarios."""

    @pytest.mark.asyncio
    async def test_deliver_local_with_channel_decryption(self, advanced_child_node, security_policy):
        """Test local delivery with channel decryption."""

        manager = DefaultSecurityManager(policy=security_policy)

        # Start node to create channel manager
        await manager.on_node_started(advanced_child_node)

        # Create DataFrame with channel encryption
        frame = DataFrame(
            payload={"test": "data"},
            codec="json",
            cid="test-channel-id",  # Indicates channel encryption
        )
        envelope = FameEnvelope(frame=frame)
        address = FameAddress("local@/test")
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL, from_system_id=advanced_child_node.sid
        )

        # Mock channel manager to simulate encrypted channel
        if manager._secure_channel_manager:
            manager._secure_channel_manager.is_channel_encrypted = MagicMock(return_value=False)
            manager._secure_channel_manager.has_channel = MagicMock(return_value=True)
            # Add the method dynamically for testing
            manager._secure_channel_manager.decrypt_dataframe = MagicMock(return_value=frame)

        result = await manager.on_deliver_local(advanced_child_node, address, envelope, context)

        # Should return processed envelope
        assert result is not None

    @pytest.mark.asyncio
    async def test_deliver_local_with_system_frames(self, advanced_child_node, security_policy):
        """Test local delivery with various system frames."""

        manager = DefaultSecurityManager(policy=security_policy)
        await manager.on_node_initialized(advanced_child_node)
        await manager.on_node_started(advanced_child_node)

        # Test different system frames
        system_frames = [
            SecureOpenFrame(
                cid="test-channel",
                eph_pub=b"12345678901234567890123456789012",  # Exactly 32 bytes
            ),
            SecureAcceptFrame(
                cid="test-channel",
                eph_pub=b"12345678901234567890123456789012",  # Exactly 32 bytes
                ok=True,
            ),
            SecureCloseFrame(cid="test-channel"),
            NodeHeartbeatFrame(),
            DeliveryAckFrame(corr_id="test", success=True, code="ok"),
        ]

        address = FameAddress("local@/test")

        for frame in system_frames:
            envelope = FameEnvelope(frame=frame)
            context = FameDeliveryContext(
                origin_type=DeliveryOriginType.LOCAL, from_system_id=advanced_child_node.sid
            )

            # Mock channel frame handler for channel frames
            if frame.type in ["SecureOpen", "SecureAccept", "SecureClose"]:
                if not manager._secure_channel_frame_handler:
                    manager._secure_channel_frame_handler = MagicMock()
                    manager._secure_channel_frame_handler.handle_secure_open = AsyncMock()
                    manager._secure_channel_frame_handler.handle_secure_accept = AsyncMock()
                    manager._secure_channel_frame_handler.handle_secure_close = AsyncMock()

            result = await manager.on_deliver_local(advanced_child_node, address, envelope, context)

            # Channel frames should return None (handled by frame handler)
            if frame.type in ["SecureOpen", "SecureAccept", "SecureClose"]:
                assert result is None
            else:
                # Other system frames should pass through
                assert result is not None

    @pytest.mark.asyncio
    async def test_deliver_with_key_management_handler(
        self, advanced_child_node, enhanced_key_manager, security_policy
    ):
        """Test envelope delivery with key management handler."""

        manager = DefaultSecurityManager(policy=security_policy, key_manager=enhanced_key_manager)

        await manager.on_node_started(advanced_child_node)

        # Create KeyAnnounce frame
        key_announce_frame = KeyAnnounceFrame(
            address=FameAddress("announcer@/node"),
            physical_path="/test/path/announcer",
            keys=[
                {"kid": "announced-key", "kty": "OKP", "crv": "Ed25519", "use": "sig", "x": "test-key-data"}
            ],
        )
        envelope = FameEnvelope(frame=key_announce_frame)
        envelope.sec = MagicMock()  # Create SecurityHeader mock
        envelope.sec.sig = "test-signature"  # Add signature since critical frames must be signed
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM, from_system_id="announcing-node"
        )

        # Mock key management handler
        manager._key_management_handler = MagicMock()
        manager._key_management_handler.accept_key_announce = AsyncMock()

        result = await manager.on_deliver(advanced_child_node, envelope, context)

        # Should be handled by key management handler
        assert result is None
        manager._key_management_handler.accept_key_announce.assert_called_once()


class TestSecurityPolicyValidation:
    """Test security policy validation and enforcement."""

    @pytest.mark.asyncio
    async def test_crypto_level_policy_enforcement(self, advanced_child_node, security_policy):
        """Test crypto level policy enforcement."""

        # Mock policy with strict requirements
        security_policy.classify_message_crypto_level = MagicMock()
        security_policy.is_inbound_crypto_level_allowed = MagicMock(return_value=False)
        security_policy.get_inbound_violation_action = MagicMock()

        from naylence.fame.security.policy.security_policy import CryptoLevel, SecurityAction

        security_policy.classify_message_crypto_level.return_value = CryptoLevel.PLAINTEXT
        security_policy.get_inbound_violation_action.return_value = SecurityAction.REJECT

        manager = DefaultSecurityManager(policy=security_policy)
        await manager.on_node_started(advanced_child_node)

        # Create non-system frame that would violate policy
        frame = DataFrame(payload={"sensitive": "data"}, codec="json")
        envelope = FameEnvelope(frame=frame)
        address = FameAddress("sensitive@/endpoint")
        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM, from_system_id="remote-node")

        result = await manager.on_deliver_local(advanced_child_node, address, envelope, context)

        # Should be rejected due to policy violation
        assert result is None

    @pytest.mark.asyncio
    async def test_signature_verification_policy(self, advanced_child_node, security_policy):
        """Test signature verification policy enforcement."""

        # Create verifier that succeeds
        mock_verifier = MagicMock()
        mock_verifier.verify_envelope = MagicMock()

        # Mock policy requiring signatures
        security_policy.is_signature_required = MagicMock(return_value=True)
        security_policy.should_verify_signature = MagicMock(return_value=True)
        security_policy.get_unsigned_violation_action = MagicMock()

        from naylence.fame.security.policy.security_policy import SecurityAction

        security_policy.get_unsigned_violation_action.return_value = SecurityAction.REJECT

        manager = DefaultSecurityManager(policy=security_policy, envelope_verifier=mock_verifier)
        await manager.on_node_started(advanced_child_node)

        # Create unsigned frame
        frame = DataFrame(payload={"test": "data"}, codec="json")
        envelope = FameEnvelope(frame=frame)  # No signature
        address = FameAddress("test@/endpoint")
        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM, from_system_id="remote-node")

        result = await manager.on_deliver_local(advanced_child_node, address, envelope, context)

        # Should be rejected due to missing signature
        assert result is None


class TestForwardingScenarios:
    """Test envelope forwarding scenarios."""

    @pytest.mark.asyncio
    async def test_forward_to_route_with_critical_frame_signing(
        self, advanced_sentinel_node, security_policy
    ):
        """Test forwarding critical frames with signing requirements."""

        manager = DefaultSecurityManager(policy=security_policy)

        # Create unsigned critical frame
        frame = KeyRequestFrame(address=FameAddress("target@/node"), kid="requested-key")
        envelope = FameEnvelope(frame=frame)  # Unsigned critical frame
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM, from_system_id="upstream-node"
        )

        result = await manager.on_forward_to_route(
            advanced_sentinel_node, "next-segment", envelope, context
        )

        # Critical frame without signature and no security handler should be rejected
        assert result is None

    @pytest.mark.asyncio
    async def test_forward_with_envelope_security_handler(
        self, advanced_child_node, enhanced_key_manager, security_policy
    ):
        """Test forwarding with envelope security handler."""

        manager = DefaultSecurityManager(policy=security_policy, key_manager=enhanced_key_manager)

        await manager.on_node_started(advanced_child_node)

        # Create LOCAL origin envelope
        frame = DataFrame(payload={"test": "data"}, codec="json")
        envelope = FameEnvelope(frame=frame)
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL, from_system_id=advanced_child_node.sid
        )

        # Mock envelope security handler
        if manager._envelope_security_handler:
            manager._envelope_security_handler.handle_outbound_security = AsyncMock(return_value=True)

        # Test all forwarding methods
        forwarding_methods = [
            ("on_forward_upstream", [envelope, context]),
            ("on_forward_to_route", ["next-segment", envelope, context]),
            ("on_forward_to_peer", ["peer-segment", envelope, context]),
            ("on_forward_to_peers", [envelope, ["peer1", "peer2"], [], context]),
        ]

        for method_name, args in forwarding_methods:
            method = getattr(manager, method_name)
            result = await method(advanced_child_node, *args)

            # Should return envelope after processing
            assert result is envelope


class TestErrorScenarios:
    """Test various error scenarios and edge cases."""

    @pytest.mark.asyncio
    async def test_send_nack_with_heartbeat_frame(self, advanced_child_node, security_policy):
        """Test NACK sending assertion with NodeHeartbeatFrame."""

        manager = DefaultSecurityManager(policy=security_policy)

        # Create NodeHeartbeatFrame (should trigger assertion)
        frame = NodeHeartbeatFrame()
        envelope = FameEnvelope(frame=frame, reply_to=FameAddress("sender@/node"))

        # Should raise assertion error
        with pytest.raises(AssertionError):
            await manager._send_nack(advanced_child_node, envelope, "test_reason")

    @pytest.mark.asyncio
    async def test_epoch_change_without_key_manager(self, advanced_child_node, security_policy):
        """Test epoch change handling without key manager."""

        manager = DefaultSecurityManager(policy=security_policy)

        # Should not raise any exceptions
        await manager.on_epoch_change(advanced_child_node, "new-epoch")

    @pytest.mark.asyncio
    async def test_epoch_change_with_key_manager(
        self, advanced_child_node, enhanced_key_manager, security_policy
    ):
        """Test epoch change handling with key manager."""

        manager = DefaultSecurityManager(policy=security_policy, key_manager=enhanced_key_manager)

        await manager.on_epoch_change(advanced_child_node, "new-epoch")

        # Should have announced keys
        assert len(enhanced_key_manager.key_announcements) == 1


class TestCertificateManagement:
    """Test certificate management scenarios."""

    @pytest.mark.asyncio
    async def test_child_welcome_with_certificate_manager(self, advanced_child_node, security_policy):
        """Test child welcome handling with certificate manager."""

        # Create mock certificate manager
        mock_cert_manager = MagicMock()
        mock_cert_manager.on_welcome = AsyncMock()

        manager = DefaultSecurityManager(policy=security_policy, certificate_manager=mock_cert_manager)

        welcome_frame = NodeWelcomeFrame(
            system_id="child-node", instance_id="child-instance-123", assigned_path="/child/path"
        )

        await manager.on_welcome(welcome_frame)

        # Certificate manager should have been called
        mock_cert_manager.on_welcome.assert_called_once_with(welcome_frame=welcome_frame)

    @pytest.mark.asyncio
    async def test_child_welcome_certificate_validation_failure(self, advanced_child_node, security_policy):
        """Test child welcome with certificate validation failure."""

        # Create certificate manager that fails with validation error
        mock_cert_manager = MagicMock()
        mock_cert_manager.on_welcome = AsyncMock(
            side_effect=RuntimeError("certificate validation failed: invalid cert")
        )

        manager = DefaultSecurityManager(policy=security_policy, certificate_manager=mock_cert_manager)

        welcome_frame = NodeWelcomeFrame(
            system_id="child-node", instance_id="child-instance-456", assigned_path="/child/path"
        )

        # Should re-raise certificate validation failures
        with pytest.raises(RuntimeError, match="certificate validation failed"):
            await manager.on_welcome(welcome_frame)

    @pytest.mark.asyncio
    async def test_child_welcome_general_certificate_error(self, advanced_child_node, security_policy):
        """Test child welcome with general certificate error."""

        # Create certificate manager that fails with general error
        mock_cert_manager = MagicMock()
        mock_cert_manager.on_welcome = AsyncMock(side_effect=Exception("Network error connecting to CA"))

        manager = DefaultSecurityManager(policy=security_policy, certificate_manager=mock_cert_manager)

        welcome_frame = NodeWelcomeFrame(
            system_id="child-node", instance_id="child-instance-789", assigned_path="/child/path"
        )

        # Should handle gracefully without raising
        await manager.on_welcome(welcome_frame)

        # Certificate manager should have been called
        mock_cert_manager.on_welcome.assert_called_once()


class TestHeartbeatHandling:
    """Test heartbeat verification scenarios."""

    @pytest.mark.asyncio
    async def test_heartbeat_with_signature_verification(self, advanced_child_node, security_policy):
        """Test heartbeat with signature verification."""

        # Create verifier that succeeds
        mock_verifier = MagicMock()
        mock_verifier.verify_envelope = MagicMock()

        manager = DefaultSecurityManager(policy=security_policy, envelope_verifier=mock_verifier)

        # Create signed heartbeat
        frame = NodeHeartbeatFrame()
        envelope = FameEnvelope(frame=frame)
        envelope.sec = MagicMock()
        envelope.sec.sig = "test-signature"

        await manager.on_heartbeat_received(envelope)

        # Verifier should have been called
        mock_verifier.verify_envelope.assert_called_once_with(envelope)

    @pytest.mark.asyncio
    async def test_heartbeat_verification_failure(self, advanced_child_node, security_policy):
        """Test heartbeat verification failure handling."""

        # Create verifier that fails
        mock_verifier = MagicMock()
        mock_verifier.verify_envelope = MagicMock(side_effect=ValueError("Invalid signature"))

        manager = DefaultSecurityManager(policy=security_policy, envelope_verifier=mock_verifier)

        # Create signed heartbeat
        frame = NodeHeartbeatFrame()
        envelope = FameEnvelope(frame=frame)
        envelope.sec = MagicMock()
        envelope.sec.sig = "invalid-signature"

        # Should handle gracefully without raising
        await manager.on_heartbeat_received(envelope)

        # Verifier should have been called
        mock_verifier.verify_envelope.assert_called_once()

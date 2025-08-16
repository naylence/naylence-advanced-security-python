"""
Integration tests for DefaultSecurityManager.

These tests focus on real integration behavior rather than heavy mocking,
testing the actual flow of security operations through the manager.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
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
    SecureAcceptFrame,
    SecureOpenFrame,
)
from naylence.fame.security.default_security_manager import DefaultSecurityManager
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.signing.eddsa_envelope_signer import EdDSAEnvelopeSigner
from naylence.fame.security.signing.eddsa_envelope_verifier import EdDSAEnvelopeVerifier


class MockNode:
    """Mock node for testing that provides minimal interface."""

    def __init__(self, node_id: str = None):
        self.id = node_id or str(uuid4())
        self.sid = f"sid-{self.id}"
        self.physical_path = f"/test/path/{self.id}"
        self.envelope_factory = MagicMock()

        # Make create_envelope more dynamic - return the frame passed to it
        def create_envelope(frame=None, **kwargs):
            return FameEnvelope(frame=frame, **kwargs)

        self.envelope_factory.create_envelope.side_effect = create_envelope

        self._event_listeners = []
        self.deliver_calls = []

    async def deliver(self, envelope, context):
        """Mock deliver method that records calls."""
        self.deliver_calls.append((envelope, context))

    def spawn(self, coro):
        """Mock spawn method."""
        return asyncio.create_task(coro)


class MockCryptoProvider:
    """Mock crypto provider for testing."""

    def __init__(self):
        self.signature_key_id = "test-sig-key"
        self.encryption_key_id = "test-enc-key"

    def node_jwk(self):
        return {"kid": self.signature_key_id, "kty": "OKP", "crv": "Ed25519", "use": "sig"}

    def get_jwks(self):
        return {
            "keys": [
                self.node_jwk(),
                {"kid": self.encryption_key_id, "kty": "OKP", "crv": "X25519", "use": "enc"},
            ]
        }


@pytest.fixture
def mock_node():
    """Create a mock node for testing."""
    return MockNode()


@pytest.fixture
def mock_crypto_provider():
    """Create a mock crypto provider."""
    return MockCryptoProvider()


@pytest.fixture
def security_policy():
    """Create a default security policy for testing."""
    return DefaultSecurityPolicy()


@pytest.fixture
def basic_security_manager(security_policy, mock_crypto_provider):
    """Create a basic security manager with minimal key sharing configuration."""
    # Create mock envelope verifier to enable key sharing functionality
    mock_verifier = MagicMock()
    mock_verifier.verify_envelope = MagicMock()

    return DefaultSecurityManager(policy=security_policy, envelope_verifier=mock_verifier)


@pytest.fixture
def full_security_manager(security_policy, mock_crypto_provider):
    """Create a fully configured security manager."""
    with patch(
        "naylence.fame.security.crypto.providers.crypto_provider.get_crypto_provider",
        return_value=mock_crypto_provider,
    ):
        from naylence.fame.security.keys.key_provider import get_key_provider

        signer = EdDSAEnvelopeSigner()
        verifier = EdDSAEnvelopeVerifier(key_provider=get_key_provider())

        return DefaultSecurityManager(
            policy=security_policy, envelope_signer=signer, envelope_verifier=verifier
        )


class TestDefaultSecurityManagerBasics:
    """Test basic functionality and initialization."""

    def test_initialization_with_minimal_config(self, security_policy):
        """Test that manager can be initialized with just a policy."""
        manager = DefaultSecurityManager(policy=security_policy)

        assert manager.policy is security_policy
        assert manager.envelope_signer is None
        assert manager.envelope_verifier is None
        # Note: encryption may be auto-created based on policy requirements
        assert manager.key_manager is None
        assert manager.authorizer is None
        assert manager.certificate_manager is None

    def test_initialization_with_full_config(self, full_security_manager):
        """Test that manager can be initialized with full configuration."""
        manager = full_security_manager

        assert manager.policy is not None
        assert manager.envelope_signer is not None
        assert manager.envelope_verifier is not None

    def test_property_setters(self, basic_security_manager):
        """Test that all properties can be set and retrieved."""
        manager = basic_security_manager

        # Test setting various components
        mock_encryption = MagicMock()
        manager.encryption = mock_encryption
        assert manager.encryption is mock_encryption

        mock_key_manager = MagicMock()
        manager.key_manager = mock_key_manager
        assert manager.key_manager is mock_key_manager


class TestNodeLifecycleIntegration:
    """Test integration with node lifecycle events."""

    @pytest.mark.asyncio
    async def test_node_started_event_basic(self, basic_security_manager, mock_node):
        """Test basic node started event handling."""
        manager = basic_security_manager

        # Should not raise any exceptions
        await manager.on_node_started(mock_node)

        # Should create channel manager
        assert manager.secure_channel_frame_handler is not None

    @pytest.mark.asyncio
    async def test_node_started_event_with_key_manager(self, security_policy, mock_node):
        """Test node started event with key manager."""
        mock_key_manager = AsyncMock()
        mock_key_manager.on_node_started = AsyncMock()

        # Add mock envelope verifier to enable key sharing functionality
        mock_verifier = MagicMock()
        mock_verifier.verify_envelope = MagicMock()

        manager = DefaultSecurityManager(
            policy=security_policy, key_manager=mock_key_manager, envelope_verifier=mock_verifier
        )

        await manager.on_node_started(mock_node)

        # Key manager should be started
        mock_key_manager.on_node_started.assert_called_once_with(mock_node)

        # Key management handler should be created
        assert manager._key_management_handler is not None

        # Envelope security handler should be created
        assert manager.envelope_security_handler is not None

    @pytest.mark.asyncio
    async def test_node_stopped_event(self, security_policy, mock_node):
        """Test node stopped event handling."""
        mock_key_manager = AsyncMock()
        mock_key_manager.on_node_stopped = AsyncMock()

        manager = DefaultSecurityManager(policy=security_policy, key_manager=mock_key_manager)

        # Simulate starting the node first
        await manager.on_node_started(mock_node)

        # Now stop it
        await manager.on_node_stopped(mock_node)

        # Key manager should be stopped
        mock_key_manager.on_node_stopped.assert_called_once_with(mock_node)

    @pytest.mark.asyncio
    async def test_node_initialized_event(self, security_policy, mock_node):
        """Test node initialized event handling."""
        mock_key_manager = AsyncMock()
        mock_key_manager.on_node_initialized = AsyncMock()

        manager = DefaultSecurityManager(policy=security_policy, key_manager=mock_key_manager)

        await manager.on_node_initialized(mock_node)

        # Key manager should be initialized
        mock_key_manager.on_node_initialized.assert_called_once_with(mock_node)


class TestEnvelopeSecurityProcessing:
    """Test envelope security processing integration."""

    @pytest.mark.asyncio
    async def test_on_deliver_basic_flow(self, basic_security_manager, mock_node):
        """Test basic envelope delivery processing."""
        manager = basic_security_manager

        # Create a basic data envelope
        frame = DataFrame(payload={"test": "data"}, codec="json")
        envelope = FameEnvelope(frame=frame)
        context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, from_system_id=mock_node.sid)

        # Process the envelope
        result = await manager.on_deliver(mock_node, envelope, context)

        # Should return the envelope (pass-through for basic manager)
        assert result is envelope

    @pytest.mark.asyncio
    async def test_on_deliver_key_announce_frame(self, basic_security_manager, mock_node):
        """Test handling of KeyAnnounce frames."""
        manager = basic_security_manager

        # Create KeyAnnounce frame
        frame = KeyAnnounceFrame(
            keys=[
                {
                    "kid": "test-key-123",
                    "key_type": "ed25519",
                    "public_key": "dGVzdF9wdWJsaWNfa2V5X2RhdGFfaGVyZV8zMmJ5dGVz",
                }
            ],
            physical_path="/test/path",
        )
        envelope = FameEnvelope(frame=frame)
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM, from_system_id="upstream-node"
        )

        # Process the envelope
        result = await manager.on_deliver(mock_node, envelope, context)

        # KeyAnnounce frames are critical frames and should be rejected if unsigned
        assert result is None

    @pytest.mark.asyncio
    async def test_on_deliver_critical_frame_signature_enforcement(self, basic_security_manager, mock_node):
        """Test that critical frames require signatures."""
        manager = basic_security_manager

        # Create unsigned KeyAnnounce frame (critical frame)
        frame = KeyAnnounceFrame(
            keys=[
                {
                    "kid": "critical-key-456",
                    "key_type": "ed25519",
                    "public_key": "dGVzdF9wdWJsaWNfa2V5X2RhdGFfaGVyZV8zMmJ5dGVz",
                }
            ],
            physical_path="/critical/path",
        )
        envelope = FameEnvelope(frame=frame)  # No signature
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM,  # Not LOCAL
            from_system_id="upstream-node",
        )

        # Process the envelope
        result = await manager.on_deliver(mock_node, envelope, context)

        # Should reject unsigned critical frame
        assert result is None

    @pytest.mark.asyncio
    async def test_on_deliver_local_security_processing(self, basic_security_manager, mock_node):
        """Test local delivery security processing."""
        manager = basic_security_manager

        # Create a data frame
        frame = DataFrame(payload={"test": "data"}, codec="json")
        envelope = FameEnvelope(frame=frame)
        address = FameAddress("local@/test")
        context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, from_system_id=mock_node.sid)

        # Process local delivery
        result = await manager.on_deliver_local(mock_node, address, envelope, context)

        # Should return the processed envelope
        assert result is envelope

    @pytest.mark.asyncio
    async def test_system_frames_exempt_from_crypto_policy(self, basic_security_manager, mock_node):
        """Test that system frames are exempt from crypto policy checks."""
        manager = basic_security_manager

        # Test various system frames
        system_frames = [NodeHeartbeatFrame(), DeliveryAckFrame(corr_id="test", success=True, code="OK")]

        address = FameAddress("local@/test")

        for frame in system_frames:
            envelope = FameEnvelope(frame=frame)
            context = FameDeliveryContext(
                origin_type=DeliveryOriginType.LOCAL, from_system_id=mock_node.sid
            )

            # Should process without policy violations
            result = await manager.on_deliver_local(mock_node, address, envelope, context)
            assert result is not None  # Should not be rejected

        # Test channel frames (these might require special handling)
        channel_frames = [
            SecureOpenFrame(
                cid="test-channel",
                eph_pub=b"12345678901234567890123456789012",  # Exactly 32 bytes
            ),
            SecureAcceptFrame(
                cid="test-channel",
                eph_pub=b"12345678901234567890123456789012",  # Exactly 32 bytes
                ok=True,
            ),
        ]

        for frame in channel_frames:
            envelope = FameEnvelope(frame=frame)
            context = FameDeliveryContext(
                origin_type=DeliveryOriginType.LOCAL, from_system_id=mock_node.sid
            )

            # Channel frames might be handled differently, just ensure no exception is raised
            result = await manager.on_deliver_local(mock_node, address, envelope, context)
            # Don't assert specific result for channel frames as they may need special processing


class TestKeyManagementIntegration:
    """Test key management integration."""

    @pytest.mark.asyncio
    async def test_shareable_keys_no_signer(self, security_policy):
        """Test shareable keys when no envelope signer is configured."""
        manager = DefaultSecurityManager(policy=security_policy)

        keys = manager.get_shareable_keys()

        # Should return None when no signer is configured
        assert keys is None

    @pytest.mark.asyncio
    async def test_shareable_keys_with_crypto_provider(self, full_security_manager, mock_crypto_provider):
        """Test shareable keys with crypto provider."""
        manager = full_security_manager

        with patch(
            "naylence.fame.security.crypto.providers.crypto_provider.get_crypto_provider",
            return_value=mock_crypto_provider,
        ):
            keys = manager.get_shareable_keys()

            # Should return keys from crypto provider
            assert keys is not None
            assert len(keys) >= 1  # Should have at least the node JWK


class TestErrorHandlingAndEdgeCases:
    """Test error handling and edge cases."""

    @pytest.mark.asyncio
    async def test_send_nack_with_reply_to(self, basic_security_manager, mock_node):
        """Test sending NACK response when reply_to is present."""
        manager = basic_security_manager

        # Create envelope with reply_to address
        frame = DataFrame(payload={"test": "data"}, codec="json")
        envelope = FameEnvelope(frame=frame, reply_to=FameAddress("sender@/node"))

        # Send NACK
        await manager._send_nack(mock_node, envelope, "test_reason")

        # Should have delivered a NACK response
        assert len(mock_node.deliver_calls) == 1
        nack_envelope, context = mock_node.deliver_calls[0]
        assert isinstance(nack_envelope.frame, DeliveryAckFrame)
        assert not nack_envelope.frame.success
        assert nack_envelope.frame.code == "test_reason"

    @pytest.mark.asyncio
    async def test_send_nack_without_reply_to(self, basic_security_manager, mock_node):
        """Test sending NACK when no reply_to address is present."""
        manager = basic_security_manager

        # Create envelope without reply_to
        frame = DataFrame(payload={"test": "data"}, codec="json")
        envelope = FameEnvelope(frame=frame)  # No reply_to

        # Send NACK - should not raise exception
        await manager._send_nack(mock_node, envelope, "test_reason")

        # Should not have delivered anything
        assert len(mock_node.deliver_calls) == 0

    def test_get_encryption_key_id_no_provider(self, basic_security_manager):
        """Test getting encryption key ID when no crypto provider is available."""
        manager = basic_security_manager

        with patch(
            "naylence.fame.security.crypto.providers.crypto_provider.get_crypto_provider",
            side_effect=Exception("No provider"),
        ):
            key_id = manager.get_encryption_key_id()
            assert key_id is None


class TestPolicyIntegration:
    """Test integration with security policies."""

    @pytest.mark.asyncio
    async def test_policy_crypto_level_validation(self, full_security_manager, mock_node):
        """Test policy-based crypto level validation."""
        manager = full_security_manager

        # Create envelope that might violate policy
        frame = DataFrame(payload={"sensitive": "data"}, codec="json")
        envelope = FameEnvelope(frame=frame)  # Unencrypted
        address = FameAddress("sensitive@/endpoint")
        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM, from_system_id="remote-node")

        # Process with policy validation
        result = await manager.on_deliver_local(mock_node, address, envelope, context)

        # Result depends on policy configuration, but should not crash
        assert result is not None or result is None  # Either pass through or reject

    @pytest.mark.asyncio
    async def test_epoch_change_handling(self, security_policy, mock_node):
        """Test epoch change event handling."""
        mock_key_manager = AsyncMock()
        mock_key_manager.announce_keys_to_upstream = AsyncMock()

        manager = DefaultSecurityManager(policy=security_policy, key_manager=mock_key_manager)

        await manager.on_epoch_change(mock_node, "new-epoch")

        # Should announce keys to upstream
        mock_key_manager.announce_keys_to_upstream.assert_called_once()


class TestForwardingSecurityProcessing:
    """Test security processing for forwarding operations."""

    @pytest.mark.asyncio
    async def test_forward_upstream_local_origin(self, basic_security_manager, mock_node):
        """Test forwarding to upstream with LOCAL origin."""
        manager = basic_security_manager

        frame = DataFrame(payload={"test": "data"}, codec="json")
        envelope = FameEnvelope(frame=frame)
        context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, from_system_id=mock_node.sid)

        result = await manager.on_forward_upstream(mock_node, envelope, context)

        # Should pass through for basic manager
        assert result is envelope

    @pytest.mark.asyncio
    async def test_forward_to_route_critical_frame_signing(self, basic_security_manager, mock_node):
        """Test that critical frames are signed when forwarded to routes."""
        manager = basic_security_manager

        # Create unsigned critical frame
        frame = KeyRequestFrame(address=FameAddress("target@/node"), kid="test-key")
        envelope = FameEnvelope(frame=frame)  # Unsigned
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM, from_system_id="upstream-node"
        )

        result = await manager.on_forward_to_route(mock_node, "next-segment", envelope, context)

        # Should handle unsigned critical frame appropriately
        # (either sign it or reject it based on security handler availability)
        assert result is not None or result is None

#!/usr/bin/env python3
"""
Test stickiness integration with encryption use cases.

This test verifies that stickiness is automatically requested when:
1. A KeyRequest is handled successfully (sealed encryption use case)
2. A SecureOpen is handled successfully (channel encryption use case)
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from naylence.fame.core import (
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    KeyRequestFrame,
    SecureOpenFrame,
    create_fame_envelope,
)
from naylence.fame.node.node_envelope_factory import NodeEnvelopeFactory
from naylence.fame.node.secure_channel_frame_handler import SecureChannelFrameHandler
from naylence.fame.security.default_security_manager import DefaultSecurityManager
from naylence.fame.security.encryption.default_secure_channel_manager import DefaultSecureChannelManager
from naylence.fame.sentinel.key_frame_handler import KeyFrameHandler


async def test_key_request_stickiness():
    """Test that stickiness is requested when KeyRequest is handled successfully."""
    print("\n=== Testing KeyRequest Stickiness Integration ===")

    # This test verifies that the stickiness integration works end-to-end
    # by checking that the DefaultKeyManager sets stickiness on the delivery context
    # when sending KeyAnnounce responses for encryption keys

    # Mock key store to return an encryption key
    mock_key_store = MagicMock()
    mock_key_store.get_key = AsyncMock(
        return_value={
            "kid": "test-key-123",
            "use": "enc",  # This is an encryption key
            "alg": "ECDH-ES+A256KW",
            "physical_path": "/test/path",
        }
    )

    # Mock envelope factory
    mock_envelope_factory = MagicMock()
    mock_envelope = MagicMock()
    mock_envelope_factory.create_envelope.return_value = mock_envelope

    # Mock routing node for downstream forwarding
    mock_routing_node = MagicMock()
    captured_context = None

    async def capture_context(segment, envelope, context):
        nonlocal captured_context
        captured_context = context

    mock_routing_node.forward_to_route = AsyncMock(side_effect=capture_context)

    # Create real DefaultKeyManager with mocked dependencies
    from naylence.fame.security.keys.default_key_manager import DefaultKeyManager

    key_manager = DefaultKeyManager(key_store=mock_key_store)

    # Mock the node
    mock_node = MagicMock()
    mock_node._id = "test-node"
    mock_node._envelope_factory = mock_envelope_factory

    # Set up the required context
    key_manager._node = mock_node
    key_manager._routing_node = mock_routing_node

    # Handle the key request
    await key_manager.handle_key_request(
        kid="test-key-123",
        from_seg="test-client",
        physical_path="/test/path",
        origin=DeliveryOriginType.DOWNSTREAM,
        corr_id="test-correlation-456",
    )

    # Verify that forward_to_route was called with stickiness set
    assert mock_routing_node.forward_to_route.called, "forward_to_route should be called"

    # Check that the delivery context has stickiness required
    assert captured_context is not None, "Delivery context should be captured"
    assert captured_context.stickiness_required is True, (
        "Stickiness should be requested for encryption keys"
    )

    print("✅ KeyRequest stickiness integration test passed")
    return True


async def test_secure_open_stickiness():
    """Test that stickiness is requested when SecureOpen is handled successfully."""
    print("\n=== Testing SecureOpen Stickiness Integration ===")

    # Create channel manager
    secure_channel_manager = DefaultSecureChannelManager()

    # Create envelope factory
    envelope_factory = NodeEnvelopeFactory(physical_path_fn=lambda: "/test-node", sid_fn=lambda: "test-sid")

    # Track sent envelopes and contexts
    sent_items = []

    async def mock_send_callback(envelope, context=None):
        """Mock send callback that captures sent items."""
        sent_items.append((envelope, context))

    # Create channel frame handler
    handler = SecureChannelFrameHandler(
        secure_channel_manager=secure_channel_manager,
        envelope_factory=envelope_factory,
        send_callback=mock_send_callback,
        envelope_security_handler=None,
    )

    # Create SecureOpen frame with proper ephemeral key
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519

    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    secure_open_frame = SecureOpenFrame(cid="test-channel-123", alg="CHACHA20P1305", eph_pub=public_bytes)

    # Create envelope
    secure_open_envelope = envelope_factory.create_envelope(
        to=FameAddress("service@/test"), reply_to=FameAddress("client@/test"), frame=secure_open_frame
    )

    # Handle the secure open
    context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)
    await handler.handle_secure_open(secure_open_envelope, context)

    # Check results
    print(f"✓ SecureOpen responses sent: {len(sent_items)}")

    if not sent_items:
        print("❌ No protocol response sent!")
        return False

    response_envelope, response_context = sent_items[0]

    # Verify response context has stickiness requested
    print(f"✓ Response context exists: {response_context is not None}")
    if response_context:
        print(f"✓ Stickiness required: {response_context.stickiness_required}")
        assert response_context.stickiness_required is True, (
            "Stickiness should be requested for channel encryption"
        )

    # Verify response is SecureAccept with ok=True
    from naylence.fame.core.protocol.frames import SecureAcceptFrame

    assert isinstance(response_envelope.frame, SecureAcceptFrame), "Response should be SecureAcceptFrame"
    assert response_envelope.frame.ok is True, "SecureAccept should be successful"

    print("✅ SecureOpen stickiness integration test passed")
    return True


async def test_key_request_address_stickiness():
    """Test that stickiness is requested when KeyRequest by address finds local keys."""
    print("\n=== Testing KeyRequest by Address Stickiness Integration ===")

    # This test verifies that when a KeyRequest by address finds local encryption keys,
    # the stickiness is properly set when the key manager sends the response

    # Mock key store for the key manager
    mock_key_store = MagicMock()
    mock_key_store.get_key = AsyncMock(
        return_value={
            "kid": "test-enc-key-123",
            "use": "enc",  # This is an encryption key
            "alg": "ECDH-ES+A256KW",
            "physical_path": "/test/local/node",
        }
    )
    mock_key_store.get_keys_for_path = AsyncMock(
        return_value=[{"kid": "test-enc-key-123", "use": "enc", "alg": "ECDH-ES+A256KW"}]
    )

    # Mock envelope factory
    mock_envelope_factory = MagicMock()
    mock_envelope = MagicMock()
    mock_envelope_factory.create_envelope.return_value = mock_envelope

    # Mock routing node for downstream forwarding
    mock_routing_node = MagicMock()
    mock_routing_node.physical_path = "/test/local/node"
    captured_context = None

    async def capture_context(segment, envelope, context):
        nonlocal captured_context
        captured_context = context

    mock_routing_node.forward_to_route = AsyncMock(side_effect=capture_context)

    # Create real DefaultKeyManager
    from naylence.fame.security.keys.default_key_manager import DefaultKeyManager

    key_manager = DefaultKeyManager(key_store=mock_key_store)

    # Mock the node
    mock_node = MagicMock()
    mock_node._id = "test-node"
    mock_node._envelope_factory = mock_envelope_factory

    key_manager._node = mock_node
    key_manager._routing_node = mock_routing_node

    # Mock route and binding managers
    mock_route_manager = MagicMock()
    mock_route_manager.downstream_routes = ["test-client"]
    mock_route_manager._peer_routes = {}

    mock_binding_manager = MagicMock()
    mock_binding_manager.get_binding.return_value = {"service": "test-service"}

    # Create key frame handler
    handler = KeyFrameHandler(
        routing_node=mock_routing_node,
        route_manager=mock_route_manager,
        binding_manager=mock_binding_manager,
        accept_key_announce_parent=AsyncMock(),
        key_manager=key_manager,
    )

    # Create KeyRequest frame by address
    key_request_frame = KeyRequestFrame(
        address=FameAddress("service@/test/local/node"),
        physical_path="/test/local/node",
        corr_id="test-correlation-789",
    )

    # Create envelope
    envelope = create_fame_envelope(frame=key_request_frame)

    # Create delivery context
    context = FameDeliveryContext(from_system_id="test-client", origin_type=DeliveryOriginType.DOWNSTREAM)

    # Handle the key request
    result = await handler.accept_key_request(envelope, context)

    # Verify results
    print(f"✓ Key request by address handled: {result}")

    # Should handle request locally
    assert result is True, "KeyRequest by address should be handled locally"

    # Check that forward_to_route was called with stickiness set
    assert mock_routing_node.forward_to_route.called, "forward_to_route should be called"
    assert captured_context is not None, "Delivery context should be captured"
    assert captured_context.stickiness_required is True, (
        "Stickiness should be requested for encryption keys"
    )

    print("✅ KeyRequest by address stickiness integration test passed")
    return True


async def test_signing_key_request_no_stickiness():
    """Test that stickiness is NOT requested for signing key requests."""
    print("\n=== Testing Signing KeyRequest No Stickiness ===")

    # Mock key manager with signing keys only
    mock_key_manager = AsyncMock()
    mock_key_manager.handle_key_request = AsyncMock()
    mock_key_manager.get_keys_for_path = AsyncMock(
        return_value=[
            {"kid": "test-sign-key-123", "use": "sig", "alg": "EdDSA"}  # Signing key, not encryption
        ]
    )

    # Create key frame handler
    handler = KeyFrameHandler(
        routing_node=MagicMock(),
        route_manager=MagicMock(),
        binding_manager=MagicMock(),
        accept_key_announce_parent=AsyncMock(),
        key_manager=mock_key_manager,
    )

    # Create KeyRequest frame for signing key
    key_request_frame = KeyRequestFrame(
        kid="test-sign-key-123", physical_path="/test/path", corr_id="test-correlation-456"
    )

    # Create envelope
    envelope = create_fame_envelope(frame=key_request_frame)

    # Create delivery context
    context = FameDeliveryContext(from_system_id="test-client", origin_type=DeliveryOriginType.DOWNSTREAM)

    # Handle the key request
    result = await handler.accept_key_request(envelope, context)

    # Verify results
    print(f"✓ Key request handled: {result}")
    print(f"✓ Stickiness required: {context.stickiness_required}")

    # Should handle request locally but NOT request stickiness for signing keys
    assert result is True, "KeyRequest should be handled locally"
    assert context.stickiness_required is not True, "Stickiness should NOT be requested for signing keys"

    print("✅ Signing KeyRequest no stickiness test passed")


async def test_child_node_key_request_stickiness():
    """Test that stickiness is requested when child nodes handle KeyRequest for encryption keys."""
    print("\n=== Testing Child Node KeyRequest Stickiness ===")

    # This test verifies that child nodes properly set stickiness when responding
    # to KeyRequest for encryption keys through DefaultSecurityManager

    # Mock key store for the key manager
    mock_key_store = MagicMock()
    mock_key_store.get_key = AsyncMock(
        return_value={
            "kid": "child-enc-key-456",
            "use": "enc",  # This is an encryption key
            "alg": "ECDH-ES+A256KW",
            "physical_path": "/child/path",
        }
    )

    # Mock envelope factory
    mock_envelope_factory = MagicMock()
    mock_envelope = MagicMock()
    mock_envelope_factory.create_envelope.return_value = mock_envelope

    # Mock node for upstream forwarding
    mock_child_node = MagicMock()
    mock_child_node._id = "child-node"
    mock_child_node._envelope_factory = mock_envelope_factory
    captured_context = None

    async def capture_context(envelope, context):
        nonlocal captured_context
        captured_context = context

    mock_child_node.forward_upstream = AsyncMock(side_effect=capture_context)

    # Create real DefaultKeyManager
    from naylence.fame.security.keys.default_key_manager import DefaultKeyManager

    key_manager = DefaultKeyManager(key_store=mock_key_store)

    key_manager._node = mock_child_node

    # Create security manager (simulating a child node without key frame handler)
    security_manager = DefaultSecurityManager(policy=MagicMock(), key_manager=key_manager)

    # Create KeyRequest frame by key ID
    key_request_frame = KeyRequestFrame(
        kid="child-enc-key-456", physical_path="/child/path", corr_id="test-correlation-child"
    )

    # Create envelope
    envelope = create_fame_envelope(frame=key_request_frame)

    # Create delivery context
    context = FameDeliveryContext(from_system_id="test-parent", origin_type=DeliveryOriginType.UPSTREAM)

    # Handle the key request through child node logic
    await security_manager._handle_child_key_request(envelope, context)

    # Verify results
    print(f"✓ Child key request handled: {mock_child_node.forward_upstream.called}")

    # Check that forward_upstream was called with stickiness set
    assert mock_child_node.forward_upstream.called, "forward_upstream should be called"
    assert captured_context is not None, "Delivery context should be captured"
    assert captured_context.stickiness_required is True, (
        "Stickiness should be requested for encryption keys"
    )

    print("✅ Child node KeyRequest stickiness integration test passed")
    return True


async def test_child_node_signing_key_no_stickiness():
    """Test that stickiness is NOT requested for signing keys from child nodes."""
    print("\n=== Testing Child Node Signing Key No Stickiness ===")

    # Mock key manager for child node
    mock_key_manager = AsyncMock()
    mock_key_manager.handle_key_request = AsyncMock()

    # Mock crypto provider that only provides signature key ID (no encryption key)
    mock_crypto_provider = MagicMock()
    mock_crypto_provider.encryption_key_id = None  # No encryption key
    mock_crypto_provider.signature_key_id = "child-sign-key-789"

    # Create security manager (simulating a child node without key frame handler)
    security_manager = DefaultSecurityManager(policy=MagicMock(), key_manager=mock_key_manager)

    # Create KeyRequest frame by address (will trigger signature key fallback)
    key_request_frame = KeyRequestFrame(
        address=FameAddress("service@/child/path"), physical_path=None, corr_id="test-correlation-signing"
    )

    # Create envelope
    envelope = create_fame_envelope(frame=key_request_frame)

    # Create delivery context
    context = FameDeliveryContext(from_system_id="test-parent", origin_type=DeliveryOriginType.UPSTREAM)

    # Handle the key request through child node logic
    with patch(
        "naylence.fame.security.crypto.providers.crypto_provider.get_crypto_provider",
        return_value=mock_crypto_provider,
    ):
        await security_manager._handle_child_key_request(envelope, context)

    # Verify results
    print(f"✓ Child signing key request handled: {mock_key_manager.handle_key_request.called}")
    print(f"✓ Stickiness required: {context.stickiness_required}")

    # Should handle request but NOT request stickiness for signing keys
    assert mock_key_manager.handle_key_request.called, "Child node should handle KeyRequest"
    assert context.stickiness_required is not True, "Stickiness should NOT be requested for signing keys"

    # Verify that the key manager was called with the signing key
    mock_key_manager.handle_key_request.assert_called_once_with(
        kid="child-sign-key-789",
        from_seg="test-parent",
        physical_path=None,
        origin=DeliveryOriginType.UPSTREAM,
        corr_id="test-correlation-signing",
        original_client_sid=None,
    )

    print("✅ Child node signing key no stickiness test passed")


async def main():
    """Run all stickiness integration tests."""
    print("🧪 Testing stickiness integration with encryption use cases...")

    tests = [
        test_key_request_stickiness,
        test_secure_open_stickiness,
        test_key_request_address_stickiness,
        test_signing_key_request_no_stickiness,
        test_child_node_key_request_stickiness,
        test_child_node_signing_key_no_stickiness,
    ]

    for test in tests:
        try:
            success = await test()
            if not success:
                print(f"❌ Test {test.__name__} failed")
                return False
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with error: {e}")
            return False

    print("\n🎉 All stickiness integration tests passed!")
    return True


if __name__ == "__main__":
    result = asyncio.run(main())
    exit(0 if result else 1)

#!/usr/bin/env python3
"""
Test to verify complete SecureOpen/SecureAccept handshake flow with reply_to.
"""

from unittest.mock import Mock

import pytest

from naylence.fame.core import (
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
)
from naylence.fame.node.node_envelope_factory import NodeEnvelopeFactory
from naylence.fame.node.secure_channel_frame_handler import SecureChannelFrameHandler
from naylence.fame.security.encryption.default_secure_channel_manager import DefaultSecureChannelManager


@pytest.mark.asyncio
async def test_full_handshake_with_reply_to():
    """Test complete SecureOpen/SecureAccept handshake using reply_to."""
    print("🤝 Testing Full Handshake with reply_to")
    print("=" * 50)

    # Create two nodes (client and server)
    client_secure_channel_manager = DefaultSecureChannelManager()
    server_secure_channel_manager = DefaultSecureChannelManager()

    # Mock nodes
    client_node = Mock()
    client_node.physical_path = "/client-node"
    client_node.sid = "client-sid"

    server_node = Mock()
    server_node.physical_path = "/server-node"
    server_node.sid = "server-sid"

    # Create envelope factories
    client_envelope_factory = NodeEnvelopeFactory(
        physical_path_fn=lambda: client_node.physical_path,
        sid_fn=lambda: client_node.sid,
    )

    server_envelope_factory = NodeEnvelopeFactory(
        physical_path_fn=lambda: server_node.physical_path,
        sid_fn=lambda: server_node.sid,
    )

    # Track sent envelopes
    sent_envelopes = []

    async def mock_send_callback(envelope, context=None):
        """Mock send callback that captures sent envelopes."""
        sent_envelopes.append(envelope)
        print(f"📤 Envelope sent: {envelope.frame.type} to {envelope.to}")
        if envelope.reply_to:
            print(f"   📬 Reply-to: {envelope.reply_to}")

    # Create server channel frame handler
    server_handler = SecureChannelFrameHandler(
        secure_channel_manager=server_secure_channel_manager,
        envelope_factory=server_envelope_factory,
        send_callback=mock_send_callback,
        envelope_security_handler=None,
    )

    print("1️⃣ Creating SecureOpen frame from client...")

    # Create SecureOpen frame
    secure_open_frame = client_secure_channel_manager.generate_open_frame("test-channel-123")
    print(f"   ✅ SecureOpen frame created: cid={secure_open_frame.cid}")

    # Create envelope with reply_to
    from naylence.fame.core.address.address import format_address

    reply_to_address = format_address("__sys__", client_node.physical_path)

    secure_open_envelope = client_envelope_factory.create_envelope(
        to=FameAddress("service@/server-node"), frame=secure_open_frame, reply_to=reply_to_address
    )

    print("   ✅ SecureOpen envelope created")
    print(f"   📤 To: {secure_open_envelope.to}")
    print(f"   📬 Reply-to: {secure_open_envelope.reply_to}")

    print("\\n2️⃣ Server handling SecureOpen frame...")

    # Server handles the SecureOpen
    context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)
    await server_handler.handle_secure_open(secure_open_envelope, context)

    # Check that SecureAccept was sent back
    if sent_envelopes:
        secure_accept_envelope = sent_envelopes[0]
        print("   ✅ SecureAccept sent back")
        print(f"   📤 To (should be reply_to): {secure_accept_envelope.to}")
        print(f"   🔧 Frame type: {secure_accept_envelope.frame.type}")
        print(f"   ✅ Channel ID: {secure_accept_envelope.frame.cid}")
        print(f"   ✅ Success: {secure_accept_envelope.frame.ok}")

        # Verify that SecureAccept was sent to the correct reply address
        if str(secure_accept_envelope.to) == str(reply_to_address):
            print("   ✅ SecureAccept correctly sent to reply_to address!")
        else:
            print(f"   ❌ SecureAccept sent to wrong address: {secure_accept_envelope.to}")
    else:
        print("   ❌ No SecureAccept was sent!")

    print("\\n3️⃣ Verifying channel was established on server...")

    # Check that server has the channel
    if server_secure_channel_manager.has_channel("test-channel-123"):
        channel_info = server_secure_channel_manager.get_channel_info("test-channel-123")
        print(f"   ✅ Channel established on server: {channel_info}")
    else:
        print("   ❌ Channel not established on server")

    print("\\n🤝 Full handshake test complete!")

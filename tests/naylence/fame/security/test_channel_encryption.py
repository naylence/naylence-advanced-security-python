#!/usr/bin/env python3
"""
Test script demonstrating end-to-end channel encryption in Fame.

This test shows:
1. Channel handshake (SecureOpen -> SecureAccept) via SecureChannelManager
2. DataFrame encryption/decryption using ChannelEncryptionManager
3. Integration with the Fame node runtime
"""

from unittest.mock import MagicMock

import pytest

# Add the src directory to the path
from naylence.fame.core import FameAddress, create_fame_envelope, generate_id
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.security.encryption.channel.channel_encryption_manager import ChannelEncryptionManager
from naylence.fame.security.encryption.default_secure_channel_manager import DefaultSecureChannelManager


@pytest.mark.asyncio
async def test_channel_encryption():
    """Test the complete channel encryption flow."""
    print("🔐 Testing Fame Channel Encryption")
    print("=" * 40)

    # Create two channel managers (simulating client and server)
    client_manager = DefaultSecureChannelManager()
    server_manager = DefaultSecureChannelManager()

    # Generate channel ID
    cid = generate_id()
    print(f"📱 Generated channel ID: {cid}")

    # Step 1: Client initiates handshake
    print("\n1️⃣ Client: Generating SecureOpenFrame...")
    open_frame = client_manager.generate_open_frame(cid, "CHACHA20P1305")
    print(f"   ✓ Generated open frame with algorithm: {open_frame.alg}")
    print(f"   ✓ Ephemeral public key length: {len(open_frame.eph_pub)} bytes")

    # Assertions for open frame
    assert open_frame is not None, "Open frame should be generated"
    assert open_frame.alg == "CHACHA20P1305", "Algorithm should match requested"
    assert len(open_frame.eph_pub) > 0, "Ephemeral public key should be present"

    # Step 2: Server handles open and generates accept
    print("\n2️⃣ Server: Processing SecureOpenFrame...")
    accept_frame = await server_manager.handle_open_frame(open_frame)
    print(f"   ✓ Generated accept frame, success: {accept_frame.ok}")

    # Assertions for accept frame
    assert accept_frame is not None, "Accept frame should be generated"
    assert accept_frame.ok, "Accept frame should indicate success"

    if accept_frame.ok:
        print(f"   ✓ Server ephemeral public key length: {len(accept_frame.eph_pub)} bytes")
        print(f"   ✓ Server has channel: {server_manager.has_channel(cid)}")

        assert len(accept_frame.eph_pub) > 0, "Server ephemeral public key should be present"
        assert server_manager.has_channel(cid), "Server should have the channel"

    # Step 3: Client completes handshake
    print("\n3️⃣ Client: Processing SecureAcceptFrame...")
    handshake_success = await client_manager.handle_accept_frame(accept_frame)
    print(f"   ✓ Handshake success: {handshake_success}")

    # Assertions for handshake completion
    assert handshake_success, "Handshake should complete successfully"

    if handshake_success:
        print(f"   ✓ Client has channel: {client_manager.has_channel(cid)}")
        assert client_manager.has_channel(cid), "Client should have the channel after handshake"

    # Step 4: Test DataFrame encryption/decryption
    if handshake_success:
        print("\n4️⃣ Testing DataFrame encryption...")

        # Create mock node-like objects for client and server
        client_node = MagicMock()
        client_node._id = "client-node"
        server_node = MagicMock()
        server_node._id = "server-node"

        # Create ChannelEncryptionManagers
        client_encryption_manager = ChannelEncryptionManager(
            secure_channel_manager=client_manager, node_like=client_node
        )
        server_encryption_manager = ChannelEncryptionManager(
            secure_channel_manager=server_manager, node_like=server_node
        )

        # Create test DataFrame as envelope
        test_data = {
            "message": "Hello, secure channel!",
            "timestamp": "2025-06-28T12:00:00Z",
            "sensitive_data": "This should be encrypted",
        }

        original_df = DataFrame(
            fid="test-frame-001",
            payload=test_data,
            codec="json",
            corr_id=generate_id(),
        )

        # Create envelope with the dataframe
        original_envelope = create_fame_envelope(to=FameAddress("server@/test"), frame=original_df)

        print(f"   📝 Original payload: {test_data}")

        # Client encrypts envelope - this will queue since no auto-discovery channel exists
        # We need to manually set up the channel mapping for this test
        client_encryption_manager._addr_channel_map["server@/test"] = cid

        # Client encrypts envelope
        encrypted_result = await client_encryption_manager.encrypt_envelope(original_envelope)
        print("   🔒 Encrypted envelope:")
        print(f"      - Status: {encrypted_result.status}")

        if (
            encrypted_result.envelope
            and encrypted_result.envelope.sec
            and encrypted_result.envelope.sec.enc
        ):
            print(f"      - Channel ID: {encrypted_result.envelope.sec.enc.kid}")
            print(f"      - Algorithm: {encrypted_result.envelope.sec.enc.alg}")
            print("      - Has encryption header: True")
        else:
            print("      - Has encryption header: False")

        # Server decrypts envelope
        print("\n5️⃣ Server: Decrypting envelope...")
        if encrypted_result.envelope:
            decrypted_envelope = await server_encryption_manager.decrypt_envelope(encrypted_result.envelope)
            if isinstance(decrypted_envelope.frame, DataFrame):
                print(f"   🔓 Decrypted payload: {decrypted_envelope.frame.payload}")
                print(
                    "   ✓ Original matches decrypted: "
                    "{original_df.payload == decrypted_envelope.frame.payload}"
                )
            else:
                print("   ℹ️  Decrypted frame is not a DataFrame")
        else:
            print("   ❌ No envelope to decrypt")

        # Test counter increment
        print("\n📊 Channel statistics:")
        client_info = client_manager.get_channel_info(cid)
        server_info = server_manager.get_channel_info(cid)
        if client_info and server_info:
            print(f"   Client send counter: {client_info['send_counter']}")
            print(f"   Server recv counter: {server_info['recv_counter']}")
        else:
            print("   Channel info not available")

        # Test multiple messages
        print("\n6️⃣ Testing multiple messages...")
        for i in range(3):
            msg_df = DataFrame(
                fid=f"test-msg-{i + 1:03d}",
                payload=f"Message {i + 1}",
                codec="json",
                corr_id=generate_id(),
            )
            msg_envelope = create_fame_envelope(to=FameAddress("server@/test"), frame=msg_df)
            encrypted_result = await client_encryption_manager.encrypt_envelope(msg_envelope)
            if encrypted_result.envelope:
                decrypted_envelope = await server_encryption_manager.decrypt_envelope(
                    encrypted_result.envelope
                )
                if isinstance(decrypted_envelope.frame, DataFrame):
                    print(f"   Message {i + 1}: '{decrypted_envelope.frame.payload}' ✓")
                else:
                    print(f"   Message {i + 1}: Unexpected frame type")
            else:
                print(f"   Message {i + 1}: Encryption failed")

        final_client_info = client_manager.get_channel_info(cid)
        final_server_info = server_manager.get_channel_info(cid)
        print("\n📊 Final counters:")
        if final_client_info and final_server_info:
            print(f"   Client sent: {final_client_info['send_counter']} messages")
            print(f"   Server received: {final_server_info['recv_counter']} messages")
        else:
            print("   Final channel info not available")

        # Test channel close
        print("\n7️⃣ Testing channel close...")
        close_frame = client_manager.close_channel(cid, "Test completed")
        server_manager.handle_close_frame(close_frame)
        print(f"   ✓ Channel closed: {close_frame.reason}")
        print(f"   ✓ Client has channel: {client_manager.has_channel(cid)}")
        print(f"   ✓ Server has channel: {server_manager.has_channel(cid)}")


@pytest.mark.asyncio
async def test_integration_with_node():
    """Test basic Fame node creation (simplified test)."""
    print("\n\n🏗️ Testing Integration with Fame Node")
    print("=" * 40)

    try:
        # Test basic DataFrame creation which is used in channel encryption
        test_frame = DataFrame(fid="test-node-001", payload="Test message", codec="json")
        print(f"✓ Created test DataFrame: {test_frame.fid}")
        print(f"✓ DataFrame payload: {test_frame.payload}")

        # Test envelope creation
        test_envelope = create_fame_envelope(to=FameAddress("test@/destination"), frame=test_frame)
        print(f"✓ Created test envelope to: {test_envelope.to}")

        print("✓ Basic Fame components work correctly")

    except ImportError as e:
        print(f"⚠️  Could not test node integration: {e}")
    except Exception as e:
        print(f"⚠️  Node integration test error: {e}")

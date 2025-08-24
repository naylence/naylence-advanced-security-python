#!/usr/bin/env python3
"""
Tests for channel handshake failure handling in the ChannelEncryptionManager.
This module verifies that:
1. Failed channel handshakes properly notify queued envelopes
2. Delivery NACKs are sent for DataFrames with reply_to addresses
3. No NACKs are sent for non-DataFrames or envelopes without reply_to
4. EnvelopeSecurityHandler properly propagates channel failures
"""

from unittest.mock import ANY, AsyncMock, Mock

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryAckFrame,
    DeliveryOriginType,
    FameAddress,
    FameEnvelope,
    SecureOpenFrame,
    generate_id,
)
from naylence.fame.node.envelope_security_handler import EnvelopeSecurityHandler
from naylence.fame.security.encryption.channel.channel_encryption_manager import ChannelEncryptionManager


class TestChannelHandshakeFailureHandling:
    """Test suite for channel handshake failure handling."""

    @pytest.mark.asyncio
    async def test_channel_handshake_failure_sends_delivery_nack(self):
        """Test that channel handshake failures send delivery NACKs for DataFrames
        with reply_to addresses.
        """
        print("🧪 Testing channel handshake failure sends delivery NACK")

        # Create mock dependencies
        mock_node = Mock()
        mock_node.physical_path = "/test-node"
        mock_node.sid = "test-node-123"

        # Mock envelope factory
        mock_envelope_factory = Mock()
        mock_nack_envelope = Mock()
        mock_envelope_factory.create_envelope.return_value = mock_nack_envelope
        mock_node._envelope_factory = mock_envelope_factory

        # Mock deliver method
        mock_deliver = AsyncMock()
        mock_node.deliver = mock_deliver

        # Create channel encryption manager
        manager = ChannelEncryptionManager(node_like=mock_node)

        # Create test DataFrame envelope with reply_to
        data_frame = DataFrame(
            payload={"test": "data"},
            codec="json",
        )

        envelope = FameEnvelope(
            id="test-envelope-123",
            to=FameAddress("destination@/test/destination"),
            reply_to=FameAddress("sender@/test/sender"),
            frame=data_frame,
        )

        # Queue the envelope (simulating it waiting for channel handshake)
        destination_str = "destination@/test/destination"
        manager._pending_envelopes[destination_str] = [envelope]

        # Simulate channel handshake failure
        channel_id = f"auto-{destination_str}-abc123"
        await manager.notify_channel_failed(channel_id, "negative_secure_accept")

        # Verify that envelope factory was called to create NACK
        mock_envelope_factory.create_envelope.assert_called_once()
        call_args = mock_envelope_factory.create_envelope.call_args

        # Verify NACK envelope parameters
        assert call_args.kwargs["to"] == envelope.reply_to

        # Verify the NACK frame is a DeliveryAckFrame
        nack_frame = call_args.kwargs["frame"]
        assert isinstance(nack_frame, DeliveryAckFrame)
        assert nack_frame.ok is False
        assert nack_frame.code == "channel_handshake_failed"
        # corr_id should be passed to the envelope, not the frame anymore
        nack_corr_id = call_args.kwargs.get("corr_id")
        assert nack_corr_id == envelope.corr_id
        assert nack_frame.reason and "negative_secure_accept" in nack_frame.reason

        # Verify that deliver was called to send the NACK
        mock_deliver.assert_called_once_with(mock_nack_envelope, ANY)

        # Verify delivery context
        delivered_context = mock_deliver.call_args[0][1]
        assert delivered_context.origin_type == DeliveryOriginType.LOCAL
        assert delivered_context.from_system_id == "test-node-123"

        # Verify queue was cleared
        assert destination_str not in manager._pending_envelopes

        print("✅ Channel handshake failure delivery NACK test passed")

    @pytest.mark.asyncio
    async def test_channel_handshake_failure_no_nack_for_non_dataframe(self):
        """Test that non-DataFrame envelopes don't get delivery NACKs even with reply_to."""
        print("🧪 Testing no NACK for non-DataFrame on channel handshake failure")

        # Create mock dependencies
        mock_node = Mock()
        mock_node.physical_path = "/test-node"
        mock_node.sid = "test-node-123"

        # Mock envelope factory
        mock_envelope_factory = Mock()
        mock_node._envelope_factory = mock_envelope_factory

        # Create channel encryption manager
        manager = ChannelEncryptionManager(node_like=mock_node)

        # Create test SecureOpenFrame envelope with reply_to
        secure_open_frame = SecureOpenFrame(
            cid="test-channel-123",
            alg="CHACHA20P1305",
            eph_pub=b"test-ephemeral-key-32-bytes-long",
        )

        envelope = FameEnvelope(
            id="test-envelope-456",
            to=FameAddress("destination@/test/destination"),
            reply_to=FameAddress("sender@/test/sender"),
            frame=secure_open_frame,
        )

        # Queue the envelope (simulating it waiting for channel handshake)
        destination_str = "destination@/test/destination"
        manager._pending_envelopes[destination_str] = [envelope]

        # Simulate channel handshake failure
        channel_id = f"auto-{destination_str}-xyz789"
        await manager.notify_channel_failed(channel_id, "connection_timeout")

        # Verify that envelope factory was NOT called (no NACK for non-DataFrame)
        mock_envelope_factory.create_envelope.assert_not_called()

        # Verify queue was still cleared
        assert destination_str not in manager._pending_envelopes

        print("✅ No NACK for non-DataFrame test passed")

    @pytest.mark.asyncio
    async def test_channel_handshake_failure_no_nack_without_reply_to(self):
        """Test that DataFrames without reply_to don't get delivery NACKs."""
        print("🧪 Testing no NACK for DataFrame without reply_to on channel handshake failure")

        # Create mock dependencies
        mock_node = Mock()
        mock_node.physical_path = "/test-node"
        mock_node.sid = "test-node-123"

        # Mock envelope factory
        mock_envelope_factory = Mock()
        mock_node._envelope_factory = mock_envelope_factory

        # Create channel encryption manager
        manager = ChannelEncryptionManager(node_like=mock_node)

        # Create test DataFrame envelope WITHOUT reply_to
        data_frame = DataFrame(
            payload={"test": "data"},
            codec="json",
        )

        envelope = FameEnvelope(
            id="test-envelope-789",
            to=FameAddress("destination@/test/destination"),
            reply_to=None,  # No reply_to address
            frame=data_frame,
        )

        # Queue the envelope (simulating it waiting for channel handshake)
        destination_str = "destination@/test/destination"
        manager._pending_envelopes[destination_str] = [envelope]

        # Simulate channel handshake failure
        channel_id = f"auto-{destination_str}-def456"
        await manager.notify_channel_failed(channel_id, "authentication_failed")

        # Verify that envelope factory was NOT called (no NACK without reply_to)
        mock_envelope_factory.create_envelope.assert_not_called()

        # Verify queue was still cleared
        assert destination_str not in manager._pending_envelopes

        print("✅ No NACK without reply_to test passed")

    @pytest.mark.asyncio
    async def test_channel_handshake_failure_notification(self):
        """Test that ChannelEncryptionManager properly handles channel failure notifications."""
        print("🧪 Testing channel handshake failure notification")

        # Create a ChannelEncryptionManager to test the failure notification
        channel_encryption_manager = ChannelEncryptionManager()

        # Test destination and simulate queued envelopes
        test_destination = "test-destination"

        # Manually add some mock envelopes to the pending queue to simulate
        # envelopes waiting for channel establishment
        test_envelope1 = Mock()
        test_envelope1.id = "env-1"
        test_envelope2 = Mock()
        test_envelope2.id = "env-2"

        # Add to pending queue
        channel_encryption_manager._pending_envelopes[test_destination] = [test_envelope1, test_envelope2]
        channel_encryption_manager._handshake_in_progress.add(test_destination)

        # Verify envelopes are in queue
        assert test_destination in channel_encryption_manager._pending_envelopes
        assert len(channel_encryption_manager._pending_envelopes[test_destination]) == 2
        assert test_destination in channel_encryption_manager._handshake_in_progress

        # Call notify_channel_failed (simulating what would happen when
        # negative SecureAcceptFrame is received)
        channel_id = f"auto-{test_destination}-12345"
        await channel_encryption_manager.notify_channel_failed(channel_id, "negative_secure_accept")

        # Verify that the handshake failure was handled correctly
        # The pending envelopes should be removed from the queue
        assert test_destination not in channel_encryption_manager._pending_envelopes, (
            "Pending envelopes should be cleared"
        )
        assert test_destination not in channel_encryption_manager._handshake_in_progress, (
            "Handshake should no longer be in progress"
        )

        print("✅ Channel handshake failure notification test passed")

    @pytest.mark.asyncio
    async def test_envelope_security_handler_channel_failure(self):
        """Test that EnvelopeSecurityHandler properly calls channel failure notification."""
        print("🧪 Testing EnvelopeSecurityHandler channel failure notification")

        # Create a mock node and dependencies
        node_like = Mock()
        security_policy = Mock()
        key_mgmt_handler = Mock()

        # Create real ChannelEncryptionManager with mock notification tracking
        channel_encryption_manager = ChannelEncryptionManager()

        # Track calls to notify_channel_failed
        original_notify_failed = channel_encryption_manager.notify_channel_failed
        notify_failed_calls = []

        async def track_notify_failed(channel_id, reason="handshake_failed"):
            notify_failed_calls.append((channel_id, reason))
            await original_notify_failed(channel_id, reason)

        channel_encryption_manager.notify_channel_failed = track_notify_failed

        # Create envelope security handler
        envelope_security_handler = EnvelopeSecurityHandler(
            node_like=node_like,
            security_policy=security_policy,
            key_management_handler=key_mgmt_handler,
            encryption_manager=channel_encryption_manager,
        )

        # Test the channel handshake failure handling
        test_destination = "test-destination"
        channel_id = f"auto-{test_destination}-12345"

        await envelope_security_handler.handle_channel_handshake_failed(
            channel_id, test_destination, "negative_secure_accept"
        )

        # Verify that notify_channel_failed was called
        assert len(notify_failed_calls) == 1
        assert notify_failed_calls[0][0] == channel_id
        assert notify_failed_calls[0][1] == "negative_secure_accept"

        print("✅ EnvelopeSecurityHandler channel failure test passed")

    @pytest.mark.asyncio
    async def test_multiple_envelopes_in_failed_queue(self):
        """Test that multiple envelopes in a failed queue are handled appropriately."""
        print("🧪 Testing multiple envelopes in failed queue")

        # Create mock dependencies
        mock_node = Mock()
        mock_node.physical_path = "/test-node"
        mock_node.sid = "test-node-123"

        # Mock envelope factory
        mock_envelope_factory = Mock()

        def create_mock_envelope(*args, **kwargs):
            envelope = Mock()
            envelope.id = f"nack-{generate_id()}"
            return envelope

        mock_envelope_factory.create_envelope.side_effect = create_mock_envelope
        mock_node._envelope_factory = mock_envelope_factory

        # Mock deliver method
        mock_deliver = AsyncMock()
        mock_node.deliver = mock_deliver

        # Create channel encryption manager
        manager = ChannelEncryptionManager(node_like=mock_node)

        # Create multiple test DataFrame envelopes with reply_to
        envelopes = []
        for i in range(3):
            data_frame = DataFrame(
                payload={"test": f"data-{i}"},
                codec="json",
            )

            envelope = FameEnvelope(
                id=f"test-envelope-{i}",
                to=FameAddress("destination@/test/destination"),
                reply_to=FameAddress(f"sender-{i}@/test/sender"),
                frame=data_frame,
            )
            envelopes.append(envelope)

        # Add one envelope without reply_to (should not get NACK)
        data_frame_no_reply = DataFrame(
            payload={"test": "data-no-reply"},
            codec="json",
        )

        envelope_no_reply = FameEnvelope(
            id="test-envelope-no-reply",
            to=FameAddress("destination@/test/destination"),
            reply_to=None,
            frame=data_frame_no_reply,
        )
        envelopes.append(envelope_no_reply)

        # Queue all envelopes (simulating them waiting for channel handshake)
        destination_str = "destination@/test/destination"
        manager._pending_envelopes[destination_str] = envelopes

        # Simulate channel handshake failure
        channel_id = f"auto-{destination_str}-multi123"
        await manager.notify_channel_failed(channel_id, "connection_refused")

        # Verify that envelope factory was called 3 times (only for envelopes with reply_to)
        assert mock_envelope_factory.create_envelope.call_count == 3

        # Verify that deliver was called 3 times (only for envelopes with reply_to)
        assert mock_deliver.call_count == 3

        # Verify all calls had proper NACK frames
        for call_args in mock_envelope_factory.create_envelope.call_args_list:
            nack_frame = call_args.kwargs["frame"]
            assert isinstance(nack_frame, DeliveryAckFrame)
            assert nack_frame.ok is False
            assert nack_frame.code == "channel_handshake_failed"
            assert nack_frame.reason and "connection_refused" in nack_frame.reason

        # Verify queue was cleared
        assert destination_str not in manager._pending_envelopes

        print("✅ Multiple envelopes in failed queue test passed")

    @pytest.mark.asyncio
    async def test_mixed_frame_types_in_failed_queue(self):
        """Test handling of mixed frame types (DataFrame and others) in a failed queue."""
        print("🧪 Testing mixed frame types in failed queue")

        # Create mock dependencies
        mock_node = Mock()
        mock_node.physical_path = "/test-node"
        mock_node.sid = "test-node-123"

        # Mock envelope factory
        mock_envelope_factory = Mock()
        mock_nack_envelope = Mock()
        mock_envelope_factory.create_envelope.return_value = mock_nack_envelope
        mock_node._envelope_factory = mock_envelope_factory

        # Mock deliver method
        mock_deliver = AsyncMock()
        mock_node.deliver = mock_deliver

        # Create channel encryption manager
        manager = ChannelEncryptionManager(node_like=mock_node)

        # Create mixed envelope types
        envelopes = []

        # DataFrame with reply_to (should get NACK)
        data_frame = DataFrame(
            payload={"test": "data"},
            codec="json",
        )

        data_envelope = FameEnvelope(
            id="test-data-envelope",
            to=FameAddress("destination@/test/destination"),
            reply_to=FameAddress("sender@/test/sender"),
            frame=data_frame,
        )
        envelopes.append(data_envelope)

        # SecureOpenFrame with reply_to (should NOT get NACK)
        secure_open_frame = SecureOpenFrame(
            cid="test-channel-456",
            alg="CHACHA20P1305",
            eph_pub=b"test-ephemeral-key-32-bytes-long",
        )

        secure_envelope = FameEnvelope(
            id="test-secure-envelope",
            to=FameAddress("destination@/test/destination"),
            reply_to=FameAddress("sender@/test/sender"),
            frame=secure_open_frame,
        )
        envelopes.append(secure_envelope)

        # Queue all envelopes
        destination_str = "destination@/test/destination"
        manager._pending_envelopes[destination_str] = envelopes

        # Simulate channel handshake failure
        channel_id = f"auto-{destination_str}-mixed789"
        await manager.notify_channel_failed(channel_id, "handshake_timeout")

        # Verify that envelope factory was called only once (only for DataFrame)
        mock_envelope_factory.create_envelope.assert_called_once()

        # Verify that deliver was called only once (only for DataFrame)
        mock_deliver.assert_called_once()

        # Verify the NACK was for the DataFrame
        call_args = mock_envelope_factory.create_envelope.call_args
        assert call_args.kwargs["to"] == data_envelope.reply_to

        nack_frame = call_args.kwargs["frame"]
        assert isinstance(nack_frame, DeliveryAckFrame)
        # corr_id should be passed to the envelope, not the frame anymore
        nack_corr_id = call_args.kwargs.get("corr_id")
        assert nack_corr_id == data_envelope.corr_id

        # Verify queue was cleared
        assert destination_str not in manager._pending_envelopes

        print("✅ Mixed frame types in failed queue test passed")


# Standalone integration test
@pytest.mark.asyncio
async def test_full_channel_handshake_failure_integration():
    """
    Integration test for the complete channel handshake failure flow.
    This simulates the full process from queuing envelopes through handshake failure.
    """
    print("🧪 Testing full channel handshake failure integration")

    # Create mock node with all necessary dependencies
    mock_node = Mock()
    mock_node.physical_path = "/integration-test-node"
    mock_node.sid = "integration-test-node-456"

    # Mock envelope factory
    mock_envelope_factory = Mock()

    def create_nack_envelope(*args, **kwargs):
        envelope = Mock()
        envelope.id = f"nack-{generate_id()}"
        envelope.to = kwargs.get("to")
        envelope.frame = kwargs.get("frame")
        envelope.corr_id = kwargs.get("corr_id")
        return envelope

    mock_envelope_factory.create_envelope.side_effect = create_nack_envelope
    mock_node._envelope_factory = mock_envelope_factory

    # Mock deliver method
    delivered_envelopes = []

    async def track_delivered(envelope, context):
        delivered_envelopes.append((envelope, context))

    mock_node.deliver = track_delivered

    # Create dependencies for EnvelopeSecurityHandler
    security_policy = Mock()
    key_mgmt_handler = Mock()

    # Create channel encryption manager
    channel_encryption_manager = ChannelEncryptionManager(node_like=mock_node)

    # Create envelope security handler
    envelope_security_handler = EnvelopeSecurityHandler(
        node_like=mock_node,
        security_policy=security_policy,
        key_management_handler=key_mgmt_handler,
        encryption_manager=channel_encryption_manager,
    )

    # Create test DataFrame envelope
    data_frame = DataFrame(
        payload={"integration": "test", "message": "hello world"},
        codec="json",
    )

    envelope = FameEnvelope(
        id="integration-test-envelope",
        to=FameAddress("remote-service@/remote/node"),
        reply_to=FameAddress("local-client@/integration-test-node"),
        frame=data_frame,
        corr_id="integration-test-correlation",
    )

    # Simulate envelope being queued for channel handshake
    destination_str = "remote-service@/remote/node"
    channel_encryption_manager._pending_envelopes[destination_str] = [envelope]
    channel_encryption_manager._handshake_in_progress.add(destination_str)

    # Simulate channel handshake failure through the security handler
    channel_id = f"auto-{destination_str}-integration123"
    await envelope_security_handler.handle_channel_handshake_failed(
        channel_id, destination_str, "peer_authentication_failed"
    )

    # Verify the complete flow
    assert len(delivered_envelopes) == 1, "Should have delivered exactly one NACK envelope"

    nack_envelope, delivery_context = delivered_envelopes[0]

    # Verify delivery context
    assert delivery_context.origin_type == DeliveryOriginType.LOCAL
    assert delivery_context.from_system_id == "integration-test-node-456"

    # Verify NACK envelope
    assert nack_envelope.to == envelope.reply_to
    assert isinstance(nack_envelope.frame, DeliveryAckFrame)
    assert nack_envelope.frame.ok is False
    assert nack_envelope.frame.code == "channel_handshake_failed"
    # corr_id should be on the envelope, not the frame anymore
    assert nack_envelope.corr_id == "integration-test-correlation"
    assert nack_envelope.frame.reason and "peer_authentication_failed" in nack_envelope.frame.reason

    # Verify cleanup
    assert destination_str not in channel_encryption_manager._pending_envelopes
    assert destination_str not in channel_encryption_manager._handshake_in_progress

    print("✅ Full channel handshake failure integration test passed")


if __name__ == "__main__":
    # This allows running the test file directly for development
    import asyncio

    async def run_all_tests():
        test_class = TestChannelHandshakeFailureHandling()

        print("🚀 Running Channel Handshake Failure Handling Tests")
        print("=" * 60)

        await test_class.test_channel_handshake_failure_sends_delivery_nack()
        await test_class.test_channel_handshake_failure_no_nack_for_non_dataframe()
        await test_class.test_channel_handshake_failure_no_nack_without_reply_to()
        await test_class.test_channel_handshake_failure_notification()
        await test_class.test_envelope_security_handler_channel_failure()
        await test_class.test_multiple_envelopes_in_failed_queue()
        await test_class.test_mixed_frame_types_in_failed_queue()
        await test_full_channel_handshake_failure_integration()

        print("\n🎉 All channel handshake failure handling tests passed!")
        print("\n📝 Test Coverage Summary:")
        print("   ✅ Delivery NACKs sent for DataFrames with reply_to")
        print("   ✅ No NACKs sent for non-DataFrames")
        print("   ✅ No NACKs sent for envelopes without reply_to")
        print("   ✅ Queue cleanup on channel failure")
        print("   ✅ EnvelopeSecurityHandler integration")
        print("   ✅ Multiple envelope handling")
        print("   ✅ Mixed frame type handling")
        print("   ✅ Full integration flow")

    asyncio.run(run_all_tests())

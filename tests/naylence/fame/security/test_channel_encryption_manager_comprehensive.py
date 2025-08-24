#!/usr/bin/env python3
"""
Comprehensive unit tests for ChannelEncryptionManager to achieve 85%+ coverage.

This test suite focuses on covering all methods, error conditions, and edge cases
that are currently not covered by existing integration tests.
"""

import base64
import json
import os
import time
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryAckFrame,
    EncryptionHeader,
    FameAddress,
    SecureOpenFrame,
    SecurityHeader,
    create_fame_envelope,
)
from naylence.fame.security.encryption.channel.channel_encryption_manager import (
    ChannelEncryptionManager,
    _make_json_serializable,
)
from naylence.fame.security.encryption.encryption_manager import (
    EncryptionStatus,
)
from naylence.fame.security.encryption.secure_channel_manager import (
    SecureChannelManager,
    SecureChannelState,
)
from naylence.fame.util.task_spawner import TaskSpawner


class MockTaskSpawnerNode(TaskSpawner):
    """Mock node that implements TaskSpawner for testing async operations."""

    def __init__(self):
        super().__init__()
        self._id = "test-node"
        self.sid = "test-sid"
        self.physical_path = "/test-node"
        self.deliver = AsyncMock()
        self._envelope_factory = Mock()
        self._envelope_factory.create_envelope = Mock()


class TestChannelEncryptionManagerComprehensive:
    """Comprehensive tests for ChannelEncryptionManager."""

    @pytest.fixture
    def secure_channel_manager(self):
        """Create a mock channel manager."""
        manager = MagicMock(spec=SecureChannelManager)
        manager.channels = {}

        # Mock the interface methods
        def has_channel(channel_id):
            return channel_id in manager.channels

        def add_channel(channel_id, channel_state):
            manager.channels[channel_id] = channel_state

        def remove_channel(channel_id):
            if channel_id in manager.channels:
                del manager.channels[channel_id]

        manager.has_channel = MagicMock(side_effect=has_channel)
        manager.add_channel = MagicMock(side_effect=add_channel)
        manager.remove_channel = MagicMock(side_effect=remove_channel)

        # Mock generate_open_frame method
        manager.generate_open_frame = Mock()
        mock_frame = SecureOpenFrame(cid="test-channel", alg="CHACHA20P1305", eph_pub=b"0" * 32)
        manager.generate_open_frame.return_value = mock_frame

        return manager

    @pytest.fixture
    def mock_node(self):
        """Create a mock node with TaskSpawner capability."""
        return MockTaskSpawnerNode()

    @pytest.fixture
    def basic_node(self):
        """Create a basic mock node without TaskSpawner."""
        node = Mock()
        node._id = "test-node"
        node.sid = "test-sid"
        node.physical_path = "/test-node"
        node.deliver = AsyncMock()
        node._envelope_factory = Mock()
        node._envelope_factory.create_envelope = Mock()
        return node

    @pytest.fixture
    def encryption_manager(self, secure_channel_manager, mock_node):
        """Create ChannelEncryptionManager instance."""
        return ChannelEncryptionManager(secure_channel_manager=secure_channel_manager, node_like=mock_node)

    @pytest.fixture
    def basic_encryption_manager(self, secure_channel_manager, basic_node):
        """Create ChannelEncryptionManager with basic node."""
        return ChannelEncryptionManager(secure_channel_manager=secure_channel_manager, node_like=basic_node)

    def test_init_with_none_parameters(self):
        """Test initialization with None parameters."""
        manager = ChannelEncryptionManager(secure_channel_manager=None, node_like=None)
        assert manager._secure_channel_manager is None
        assert manager._node_like is None
        assert manager._pending_envelopes == {}
        assert manager._handshake_in_progress == set()
        assert manager._addr_channel_map == {}

    def test_is_channel_algorithm(self, encryption_manager):
        """Test _is_channel_algorithm method."""
        # Test supported algorithm
        assert encryption_manager._is_channel_algorithm("chacha20-poly1305-channel")

        # Test unsupported algorithms
        assert not encryption_manager._is_channel_algorithm("aes-256-gcm")
        assert not encryption_manager._is_channel_algorithm("chacha20-poly1305")
        assert not encryption_manager._is_channel_algorithm("unknown")
        assert not encryption_manager._is_channel_algorithm("")

    async def test_encrypt_envelope_no_payload(self, encryption_manager):
        """Test encrypt_envelope with DataFrame having no payload."""
        data_frame = DataFrame(payload=None)
        envelope = create_fame_envelope(frame=data_frame)

        result = await encryption_manager.encrypt_envelope(envelope)

        assert result.status == EncryptionStatus.SKIPPED
        assert result.envelope == envelope

    async def test_encrypt_envelope_empty_string_payload(self, encryption_manager):
        """Test encrypt_envelope with empty string payload."""
        data_frame = DataFrame(payload="")
        envelope = create_fame_envelope(frame=data_frame)

        result = await encryption_manager.encrypt_envelope(envelope)

        assert result.status == EncryptionStatus.SKIPPED
        assert result.envelope == envelope

    async def test_encrypt_envelope_no_destination(self, encryption_manager):
        """Test encrypt_envelope with no destination information."""
        data_frame = DataFrame(payload="test data")
        envelope = create_fame_envelope(frame=data_frame)  # No 'to' field

        result = await encryption_manager.encrypt_envelope(envelope, opts=None)

        assert result.status == EncryptionStatus.SKIPPED
        assert result.envelope == envelope

    async def test_encrypt_envelope_destination_from_options(
        self, encryption_manager, secure_channel_manager
    ):
        """Test encrypt_envelope gets destination from options."""
        data_frame = DataFrame(payload="test data")
        envelope = create_fame_envelope(frame=data_frame)  # No 'to' field

        # Set up a mock channel
        channel_id = "auto-option-dest-123"
        channel_state = SecureChannelState(
            key=os.urandom(32),
            send_counter=0,
            recv_counter=0,
            nonce_prefix=os.urandom(4),
            expires_at=time.time() + 3600,
            algorithm="CHACHA20P1305",
        )
        secure_channel_manager.add_channel(channel_id, channel_state)

        opts = {"destination": "option-dest"}

        with patch.object(encryption_manager, "_find_existing_channel", return_value=channel_id):
            with patch.object(encryption_manager, "_encrypt_with_channel") as mock_encrypt:
                mock_encrypt.return_value = envelope
                result = await encryption_manager.encrypt_envelope(envelope, opts=opts)

                assert result.status == EncryptionStatus.OK
                mock_encrypt.assert_called_once_with(envelope, channel_id)

    async def test_encrypt_envelope_no_secure_channel_manager(self):
        """Test encrypt_envelope with no channel manager."""
        manager = ChannelEncryptionManager(secure_channel_manager=None, node_like=None)

        data_frame = DataFrame(payload="test data")
        envelope = create_fame_envelope(to=FameAddress("dest@/test"), frame=data_frame)

        result = await manager.encrypt_envelope(envelope)

        assert result.status == EncryptionStatus.SKIPPED
        assert result.envelope == envelope

    async def test_find_existing_channel_no_manager(self):
        """Test _find_existing_channel with no channel manager."""
        manager = ChannelEncryptionManager(secure_channel_manager=None, node_like=None)

        result = await manager._find_existing_channel("dest")

        assert result is None

    async def test_find_existing_channel_cached(self, encryption_manager, secure_channel_manager):
        """Test _find_existing_channel with cached channel."""
        destination = "test-dest"
        channel_id = "cached-channel-123"

        # Set up cached mapping and existing channel
        encryption_manager._addr_channel_map[destination] = channel_id
        secure_channel_manager.add_channel(channel_id, Mock())

        result = await encryption_manager._find_existing_channel(destination)

        assert result == channel_id

    async def test_find_existing_channel_cached_but_missing(
        self, encryption_manager, secure_channel_manager
    ):
        """Test _find_existing_channel with cached channel that no longer exists."""
        destination = "test-dest"
        channel_id = "missing-channel-123"

        # Set up cached mapping but no actual channel
        encryption_manager._addr_channel_map[destination] = channel_id
        # No channels exist in the manager

        result = await encryption_manager._find_existing_channel(destination)

        assert result is None

    async def test_find_existing_channel_direct_match(self, encryption_manager, secure_channel_manager):
        """Test _find_existing_channel with direct channel match."""
        destination = "test-dest"
        channel_id = f"auto-{destination}-123"

        # Set up direct channel (no cached mapping)
        secure_channel_manager.add_channel(channel_id, Mock())

        result = await encryption_manager._find_existing_channel(destination)

        assert result == channel_id
        # Verify it gets cached
        assert encryption_manager._addr_channel_map[destination] == channel_id

    async def test_queue_and_initiate_handshake_no_task_spawner(self, basic_encryption_manager):
        """Test _queue_and_initiate_handshake with node that's not a TaskSpawner."""
        destination = FameAddress("test-dest@/test")
        destination_str = str(destination)
        envelope = create_fame_envelope(to=destination, frame=DataFrame(payload="test"))

        with patch.object(basic_encryption_manager, "_initiate_channel_handshake") as mock_handshake:
            await basic_encryption_manager._queue_and_initiate_handshake(
                envelope, destination, destination_str, None
            )

            # Verify envelope is queued
            assert destination_str in basic_encryption_manager._pending_envelopes
            assert envelope in basic_encryption_manager._pending_envelopes[destination_str]

            # Verify sync handshake was called
            mock_handshake.assert_called_once_with(destination)

    async def test_queue_and_initiate_handshake_already_in_progress(self, encryption_manager):
        """Test _queue_and_initiate_handshake when handshake already in progress."""
        destination = FameAddress("test-dest@/test")
        destination_str = str(destination)
        envelope = create_fame_envelope(to=destination, frame=DataFrame(payload="test"))

        # Mark handshake as already in progress
        encryption_manager._handshake_in_progress.add(destination_str)

        await encryption_manager._queue_and_initiate_handshake(envelope, destination, destination_str, None)

        # Verify envelope is still queued
        assert destination_str in encryption_manager._pending_envelopes
        assert envelope in encryption_manager._pending_envelopes[destination_str]

    async def test_decrypt_envelope_non_dataframe(self, encryption_manager):
        """Test decrypt_envelope with non-DataFrame."""
        frame = SecureOpenFrame(cid="test", alg="CHACHA20P1305", eph_pub=b"0" * 32)
        envelope = create_fame_envelope(frame=frame)

        result = await encryption_manager.decrypt_envelope(envelope)

        assert result == envelope

    async def test_decrypt_envelope_no_security_header(self, encryption_manager):
        """Test decrypt_envelope with no security header."""
        data_frame = DataFrame(payload="test data")
        envelope = create_fame_envelope(frame=data_frame)

        result = await encryption_manager.decrypt_envelope(envelope)

        assert result == envelope

    async def test_decrypt_envelope_no_encryption_header(self, encryption_manager):
        """Test decrypt_envelope with security header but no encryption header."""
        data_frame = DataFrame(payload="test data")
        envelope = create_fame_envelope(frame=data_frame)
        envelope.sec = SecurityHeader()  # No enc field

        result = await encryption_manager.decrypt_envelope(envelope)

        assert result == envelope

    async def test_decrypt_envelope_non_channel_algorithm(self, encryption_manager):
        """Test decrypt_envelope with non-channel encryption algorithm."""
        data_frame = DataFrame(payload="test data")
        envelope = create_fame_envelope(frame=data_frame)
        envelope.sec = SecurityHeader(enc=EncryptionHeader(alg="aes-256-gcm", kid="test", val="nonce"))

        result = await encryption_manager.decrypt_envelope(envelope)

        assert result == envelope

    async def test_decrypt_envelope_missing_channel_id(self, encryption_manager):
        """Test decrypt_envelope with missing channel ID."""
        data_frame = DataFrame(payload="test data")
        envelope = create_fame_envelope(frame=data_frame)
        envelope.sec = SecurityHeader(
            enc=EncryptionHeader(alg="chacha20-poly1305-channel", kid=None, val="nonce")
        )

        result = await encryption_manager.decrypt_envelope(envelope)

        assert result == envelope

    async def test_decrypt_envelope_invalid_nonce(self, encryption_manager):
        """Test decrypt_envelope with invalid nonce."""
        data_frame = DataFrame(payload="test data")
        envelope = create_fame_envelope(frame=data_frame)
        envelope.sec = SecurityHeader(
            enc=EncryptionHeader(alg="chacha20-poly1305-channel", kid="test", val="invalid-hex")
        )

        result = await encryption_manager.decrypt_envelope(envelope)

        assert result == envelope

    async def test_decrypt_envelope_no_secure_channel_manager(self):
        """Test decrypt_envelope with no channel manager."""
        manager = ChannelEncryptionManager(secure_channel_manager=None, node_like=None)

        data_frame = DataFrame(payload="test data")
        envelope = create_fame_envelope(frame=data_frame)
        envelope.sec = SecurityHeader(
            enc=EncryptionHeader(alg="chacha20-poly1305-channel", kid="test", val="abcd1234")
        )

        result = await manager.decrypt_envelope(envelope)

        assert result == envelope

    async def test_decrypt_envelope_channel_not_available(self, encryption_manager, secure_channel_manager):
        """Test decrypt_envelope with channel not in manager."""
        data_frame = DataFrame(payload="test data")
        envelope = create_fame_envelope(frame=data_frame)
        envelope.sec = SecurityHeader(
            enc=EncryptionHeader(alg="chacha20-poly1305-channel", kid="missing", val="abcd1234")
        )

        # No channels exist in the manager

        result = await encryption_manager.decrypt_envelope(envelope)

        assert result == envelope

    @patch("naylence.fame.security.encryption.channel.channel_encryption_manager.require_crypto")
    async def test_decrypt_envelope_successful(
        self, mock_require_crypto, encryption_manager, secure_channel_manager
    ):
        """Test successful decryption."""
        # Create test data
        test_payload = {"message": "hello world"}
        plaintext = json.dumps(test_payload, separators=(",", ":")).encode("utf-8")

        # Set up channel
        channel_id = "test-channel"
        channel_key = os.urandom(32)
        channel_state = SecureChannelState(
            key=channel_key,
            send_counter=0,
            recv_counter=0,
            nonce_prefix=os.urandom(4),
            expires_at=time.time() + 3600,
            algorithm="CHACHA20P1305",
        )
        secure_channel_manager.add_channel(channel_id, channel_state)

        # Create encrypted payload
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        nonce = os.urandom(12)
        aead = ChaCha20Poly1305(channel_key)
        ad = channel_id.encode("utf-8")
        ciphertext = aead.encrypt(nonce, plaintext, ad)

        # Create envelope with encrypted data
        data_frame = DataFrame(payload=base64.b64encode(ciphertext).decode("ascii"), codec="b64")
        envelope = create_fame_envelope(frame=data_frame)
        envelope.sec = SecurityHeader(
            enc=EncryptionHeader(alg="chacha20-poly1305-channel", kid=channel_id, val=nonce.hex())
        )
        envelope.reply_to = FameAddress("reply@test")
        envelope.sid = "sender-sid"

        result = await encryption_manager.decrypt_envelope(envelope)

        # Verify decryption worked
        assert result == envelope
        assert envelope.frame.payload == test_payload  # type: ignore
        assert envelope.frame.codec == "json"  # type: ignore
        # After decryption, the security header is cleared if there's no signature
        assert envelope.sec is None

        # Verify address learning
        assert encryption_manager._addr_channel_map[str(envelope.reply_to)] == channel_id
        assert encryption_manager._addr_channel_map[envelope.sid] == channel_id

    async def test_decrypt_envelope_decryption_failure(self, encryption_manager, secure_channel_manager):
        """Test decryption failure with invalid ciphertext."""
        # Set up channel
        channel_id = "test-channel"
        channel_key = os.urandom(32)
        channel_state = SecureChannelState(
            key=channel_key,
            send_counter=0,
            recv_counter=0,
            nonce_prefix=os.urandom(4),
            expires_at=time.time() + 3600,
            algorithm="CHACHA20P1305",
        )
        secure_channel_manager.add_channel(channel_id, channel_state)

        # Create envelope with invalid encrypted data
        data_frame = DataFrame(payload="invalid-base64-data!")
        envelope = create_fame_envelope(frame=data_frame)
        envelope.sec = SecurityHeader(
            enc=EncryptionHeader(
                alg="chacha20-poly1305-channel",
                kid=channel_id,
                val="abcdef123456789012345678",  # valid hex nonce
            )
        )

        with patch("naylence.fame.security.encryption.channel.channel_encryption_manager.require_crypto"):
            result = await encryption_manager.decrypt_envelope(envelope)

        # Should return original envelope on failure
        assert result == envelope

    def test_initiate_channel_handshake_no_secure_channel_manager(self, encryption_manager):
        """Test _initiate_channel_handshake with no channel manager."""
        encryption_manager._secure_channel_manager = None

        # Should not crash
        encryption_manager._initiate_channel_handshake("dest")

    def test_initiate_channel_handshake_send_failure(self, encryption_manager, secure_channel_manager):
        """Test _initiate_channel_handshake when send fails."""
        destination = "test-dest"

        with patch.object(encryption_manager, "_send_secure_open_frame_sync", return_value=False):
            encryption_manager._initiate_channel_handshake(destination)

            # Should complete without error

    def test_initiate_channel_handshake_exception(self, encryption_manager, secure_channel_manager):
        """Test _initiate_channel_handshake with exception."""
        destination = "test-dest"

        with patch.object(
            encryption_manager, "_send_secure_open_frame_sync", side_effect=Exception("test error")
        ):
            encryption_manager._initiate_channel_handshake(destination)

            # Should handle exception gracefully

    def test_establish_channel_with_handshake_no_manager(self):
        """Test _establish_channel_with_handshake with no channel manager."""
        manager = ChannelEncryptionManager(secure_channel_manager=None, node_like=None)

        result = manager._establish_channel_with_handshake("dest")

        assert result is None

    def test_establish_channel_with_handshake_send_failure(self, encryption_manager):
        """Test _establish_channel_with_handshake when send fails."""
        destination = "test-dest"

        with patch.object(encryption_manager, "_send_secure_open_frame_sync", return_value=False):
            result = encryption_manager._establish_channel_with_handshake(destination)

            assert result is not None  # Still creates temporary channel

    def test_establish_channel_with_handshake_exception(self, encryption_manager):
        """Test _establish_channel_with_handshake with exception."""
        destination = "test-dest"

        with patch.object(
            encryption_manager, "_send_secure_open_frame_sync", side_effect=Exception("test error")
        ):
            result = encryption_manager._establish_channel_with_handshake(destination)

            assert result is None

    def test_send_secure_open_frame_sync_no_node(self, encryption_manager):
        """Test _send_secure_open_frame_sync with no node."""
        encryption_manager._node_like = None

        frame = SecureOpenFrame(cid="test", alg="CHACHA20P1305", eph_pub=b"0" * 32)
        result = encryption_manager._send_secure_open_frame_sync(frame, "dest")

        assert result is False

    def test_send_secure_open_frame_sync_no_envelope_factory(self, encryption_manager, basic_node):
        """Test _send_secure_open_frame_sync with no envelope factory."""
        basic_node._envelope_factory = None
        encryption_manager._node_like = basic_node

        frame = SecureOpenFrame(cid="test", alg="CHACHA20P1305", eph_pub=b"0" * 32)
        result = encryption_manager._send_secure_open_frame_sync(frame, "dest")

        assert result is False

    def test_send_secure_open_frame_sync_no_physical_path(self, encryption_manager, basic_node):
        """Test _send_secure_open_frame_sync with no physical path."""
        basic_node.physical_path = None

        frame = SecureOpenFrame(cid="test", alg="CHACHA20P1305", eph_pub=b"0" * 32)
        result = encryption_manager._send_secure_open_frame_sync(frame, "dest")

        assert result is False

    def test_send_secure_open_frame_sync_not_task_spawner(self, basic_encryption_manager, basic_node):
        """Test _send_secure_open_frame_sync with non-TaskSpawner node."""
        frame = SecureOpenFrame(cid="test", alg="CHACHA20P1305", eph_pub=b"0" * 32)
        result = basic_encryption_manager._send_secure_open_frame_sync(frame, "dest")

        assert result is False

    def test_send_secure_open_frame_sync_exception(self, encryption_manager):
        """Test _send_secure_open_frame_sync with exception."""
        frame = SecureOpenFrame(cid="test", alg="CHACHA20P1305", eph_pub=b"0" * 32)

        with patch.object(
            encryption_manager._node_like, "_envelope_factory", side_effect=Exception("test error")
        ):
            result = encryption_manager._send_secure_open_frame_sync(frame, "dest")

            assert result is False

    async def test_deliver_secure_open_async_no_node(self, encryption_manager):
        """Test _deliver_secure_open_async with no node."""
        encryption_manager._node_like = None

        envelope = Mock()
        await encryption_manager._deliver_secure_open_async(envelope)

        # Should complete without error

    async def test_deliver_secure_open_async_exception(self, encryption_manager):
        """Test _deliver_secure_open_async with delivery exception."""
        envelope = Mock()
        envelope.frame.cid = "test-channel"

        encryption_manager._node_like.deliver.side_effect = Exception("delivery failed")

        await encryption_manager._deliver_secure_open_async(envelope)

        # Should handle exception gracefully

    async def test_notify_channel_established_unexpected_format(self, encryption_manager):
        """Test notify_channel_established with unexpected channel ID format."""
        channel_id = "unexpected-format"

        await encryption_manager.notify_channel_established(channel_id)

        # Should complete without error

    async def test_notify_channel_established_insufficient_parts(self, encryption_manager):
        """Test notify_channel_established with insufficient channel ID parts."""
        channel_id = "auto-incomplete"

        await encryption_manager.notify_channel_established(channel_id)

        # Should complete without error

    async def test_notify_channel_established_no_pending_queue(self, encryption_manager):
        """Test notify_channel_established with no pending queue."""
        channel_id = "auto-dest-123"

        await encryption_manager.notify_channel_established(channel_id)

        # Should complete without error

    async def test_notify_channel_established_no_secure_channel_manager(self):
        """Test notify_channel_established with no channel manager."""
        manager = ChannelEncryptionManager(secure_channel_manager=None, node_like=None)

        channel_id = "auto-dest-123"
        destination = "dest"
        envelope = create_fame_envelope(frame=DataFrame(payload="test"))
        manager._pending_envelopes[destination] = [envelope]

        await manager.notify_channel_established(channel_id)

        # Should clear the queue even without channel manager
        assert destination not in manager._pending_envelopes

    async def test_notify_channel_established_encryption_failure(
        self, encryption_manager, secure_channel_manager
    ):
        """Test notify_channel_established with encryption failure."""
        channel_id = "auto-dest-123"
        destination = "dest"
        envelope = create_fame_envelope(frame=DataFrame(payload="test"))
        encryption_manager._pending_envelopes[destination] = [envelope]

        # Set up channel
        secure_channel_manager.add_channel(channel_id, Mock())

        with patch.object(
            encryption_manager, "_encrypt_with_channel", side_effect=Exception("encryption failed")
        ):
            await encryption_manager.notify_channel_established(channel_id)

            # Should handle encryption failure gracefully

    async def test_notify_channel_established_no_task_spawner(
        self, basic_encryption_manager, secure_channel_manager
    ):
        """Test notify_channel_established with non-TaskSpawner node."""
        channel_id = "auto-dest-123"
        destination = "dest"
        envelope = create_fame_envelope(frame=DataFrame(payload="test"))
        basic_encryption_manager._pending_envelopes[destination] = [envelope]

        # Set up channel
        secure_channel_manager.add_channel(channel_id, Mock())

        with patch.object(basic_encryption_manager, "_encrypt_with_channel", return_value=envelope):
            await basic_encryption_manager.notify_channel_established(channel_id)

            # Should complete without spawning tasks

    async def test_notify_channel_failed_unexpected_format(self, encryption_manager):
        """Test notify_channel_failed with unexpected channel ID format."""
        channel_id = "unexpected-format"

        await encryption_manager.notify_channel_failed(channel_id, "test reason")

        # Should complete without error

    async def test_notify_channel_failed_insufficient_parts(self, encryption_manager):
        """Test notify_channel_failed with insufficient channel ID parts."""
        channel_id = "auto-incomplete"

        await encryption_manager.notify_channel_failed(channel_id, "test reason")

        # Should complete without error

    async def test_notify_channel_failed_no_pending_queue(self, encryption_manager):
        """Test notify_channel_failed with no pending queue."""
        channel_id = "auto-dest-123"

        await encryption_manager.notify_channel_failed(channel_id, "test reason")

        # Should complete without error

    async def test_notify_channel_failed_with_envelopes(self, encryption_manager):
        """Test notify_channel_failed processes queued envelopes."""
        channel_id = "auto-dest-123"
        destination = "dest"
        envelope = create_fame_envelope(frame=DataFrame(payload="test"))
        encryption_manager._pending_envelopes[destination] = [envelope]

        with patch.object(encryption_manager, "_handle_failed_envelope") as mock_handle:
            await encryption_manager.notify_channel_failed(channel_id, "test reason")

            mock_handle.assert_called_once_with(envelope, destination, channel_id, "test reason")

    async def test_deliver_queued_envelope_async_no_node(self, encryption_manager):
        """Test _deliver_queued_envelope_async with no node."""
        encryption_manager._node_like = None

        envelope = Mock()
        envelope.id = "test-envelope"

        await encryption_manager._deliver_queued_envelope_async(envelope)

        # Should complete without error

    async def test_deliver_queued_envelope_async_exception(self, encryption_manager):
        """Test _deliver_queued_envelope_async with delivery exception."""
        envelope = Mock()
        envelope.id = "test-envelope"

        encryption_manager._node_like.deliver.side_effect = Exception("delivery failed")

        await encryption_manager._deliver_queued_envelope_async(envelope)

        # Should handle exception gracefully

    def test_encrypt_with_channel_no_secure_channel_manager(self, encryption_manager):
        """Test _encrypt_with_channel with no channel manager."""
        encryption_manager._secure_channel_manager = None

        envelope = create_fame_envelope(frame=DataFrame(payload="test"))
        result = encryption_manager._encrypt_with_channel(envelope, "channel-id")

        assert result == envelope

    def test_encrypt_with_channel_non_dataframe(self, encryption_manager, secure_channel_manager):
        """Test _encrypt_with_channel with non-DataFrame."""
        frame = SecureOpenFrame(cid="test", alg="CHACHA20P1305", eph_pub=b"0" * 32)
        envelope = create_fame_envelope(frame=frame)

        result = encryption_manager._encrypt_with_channel(envelope, "channel-id")

        assert result == envelope

    def test_encrypt_with_channel_missing_channel(self, encryption_manager, secure_channel_manager):
        """Test _encrypt_with_channel with missing channel."""
        envelope = create_fame_envelope(frame=DataFrame(payload="test"))
        # No channels exist in the manager

        result = encryption_manager._encrypt_with_channel(envelope, "missing-channel")

        assert result == envelope

    def test_encrypt_with_channel_successful(self, encryption_manager, secure_channel_manager):
        """Test successful _encrypt_with_channel."""
        # Set up channel
        channel_id = "test-channel"
        channel_key = os.urandom(32)
        channel_state = SecureChannelState(
            key=channel_key,
            send_counter=0,
            recv_counter=0,
            nonce_prefix=os.urandom(4),
            expires_at=time.time() + 3600,
            algorithm="CHACHA20P1305",
        )
        secure_channel_manager.add_channel(channel_id, channel_state)

        # Test different payload types
        test_payloads = [
            {"message": "dict payload"},
            ["list", "payload"],
            "string payload",
            b"bytes payload",
        ]

        for payload in test_payloads:
            envelope = create_fame_envelope(frame=DataFrame(payload=payload))
            result = encryption_manager._encrypt_with_channel(envelope, channel_id)

            # Verify encryption was applied
            assert result.sec is not None
            assert result.sec.enc is not None
            assert result.sec.enc.alg == "chacha20-poly1305-channel"
            assert result.sec.enc.kid == channel_id
            assert result.frame.codec == "b64"

    def test_encrypt_with_channel_pydantic_payload(self, encryption_manager, secure_channel_manager):
        """Test _encrypt_with_channel with Pydantic model payload."""
        # Set up channel
        channel_id = "test-channel"
        channel_key = os.urandom(32)
        channel_state = SecureChannelState(
            key=channel_key,
            send_counter=0,
            recv_counter=0,
            nonce_prefix=os.urandom(4),
            expires_at=time.time() + 3600,
            algorithm="CHACHA20P1305",
        )
        secure_channel_manager.add_channel(channel_id, channel_state)

        # Create mock Pydantic-like object
        mock_payload = Mock()
        mock_payload.model_dump = Mock(return_value={"field": "value"})

        envelope = create_fame_envelope(frame=DataFrame(payload=mock_payload))
        result = encryption_manager._encrypt_with_channel(envelope, channel_id)

        # Verify model_dump was called
        mock_payload.model_dump.assert_called_once()
        assert result.sec.enc.alg == "chacha20-poly1305-channel"

    def test_encrypt_with_channel_encryption_exception(self, encryption_manager, secure_channel_manager):
        """Test _encrypt_with_channel with encryption exception."""
        # Set up channel
        channel_id = "test-channel"
        channel_key = os.urandom(32)
        channel_state = SecureChannelState(
            key=channel_key,
            send_counter=0,
            recv_counter=0,
            nonce_prefix=os.urandom(4),
            expires_at=time.time() + 3600,
            algorithm="CHACHA20P1305",
        )
        secure_channel_manager.add_channel(channel_id, channel_state)

        envelope = create_fame_envelope(frame=DataFrame(payload="test"))

        with patch("os.urandom", side_effect=Exception("crypto error")):
            result = encryption_manager._encrypt_with_channel(envelope, channel_id)

            # Should return original envelope on error
            assert result == envelope

    def test_find_channel_for_destination_no_manager(self):
        """Test _find_channel_for_destination with no channel manager."""
        manager = ChannelEncryptionManager(secure_channel_manager=None, node_like=None)

        result = manager._find_channel_for_destination("dest")

        assert result is None

    def test_find_channel_for_destination_cached(self, encryption_manager, secure_channel_manager):
        """Test _find_channel_for_destination with cached channel."""
        destination = "test-dest"
        channel_id = "cached-channel"

        encryption_manager._addr_channel_map[destination] = channel_id
        secure_channel_manager.add_channel(channel_id, Mock())

        result = encryption_manager._find_channel_for_destination(destination)

        assert result == channel_id

    def test_find_channel_for_destination_direct(self, encryption_manager, secure_channel_manager):
        """Test _find_channel_for_destination with direct channel."""
        destination = "test-dest"
        channel_id = f"auto-{destination}-123"

        secure_channel_manager.add_channel(channel_id, Mock())

        result = encryption_manager._find_channel_for_destination(destination)

        assert result == channel_id
        assert encryption_manager._addr_channel_map[destination] == channel_id

    def test_find_channel_for_destination_not_found(self, encryption_manager, secure_channel_manager):
        """Test _find_channel_for_destination with no matching channel."""
        destination = "test-dest"
        secure_channel_manager.add_channel("other-channel", Mock())

        result = encryption_manager._find_channel_for_destination(destination)

        assert result is None

    async def test_initiate_channel_handshake_async_no_manager(self, encryption_manager):
        """Test _initiate_channel_handshake_async with no channel manager."""
        encryption_manager._secure_channel_manager = None

        await encryption_manager._initiate_channel_handshake_async("dest", "dest")

        # Should complete without error and clean up tracking
        assert "dest" not in encryption_manager._handshake_in_progress

    async def test_initiate_channel_handshake_async_send_failure(
        self, encryption_manager, secure_channel_manager
    ):
        """Test _initiate_channel_handshake_async when send fails."""
        destination = "dest"

        with patch.object(encryption_manager, "_send_secure_open_frame_async", return_value=False):
            await encryption_manager._initiate_channel_handshake_async(destination, destination)

            # Should complete and clean up tracking
            assert destination not in encryption_manager._handshake_in_progress

    async def test_initiate_channel_handshake_async_exception(
        self, encryption_manager, secure_channel_manager
    ):
        """Test _initiate_channel_handshake_async with exception."""
        destination = "dest"
        encryption_manager._handshake_in_progress.add(destination)

        with patch.object(
            encryption_manager, "_send_secure_open_frame_async", side_effect=Exception("test error")
        ):
            await encryption_manager._initiate_channel_handshake_async(destination, destination)

            # Should clean up tracking even on exception
            assert destination not in encryption_manager._handshake_in_progress

    async def test_send_secure_open_frame_async_no_node(self, encryption_manager):
        """Test _send_secure_open_frame_async with no node."""
        encryption_manager._node_like = None

        frame = SecureOpenFrame(cid="test", alg="CHACHA20P1305", eph_pub=b"0" * 32)
        result = await encryption_manager._send_secure_open_frame_async(frame, "dest")

        assert result is False

    async def test_send_secure_open_frame_async_no_envelope_factory(self, encryption_manager):
        """Test _send_secure_open_frame_async with no envelope factory."""
        encryption_manager._node_like._envelope_factory = None

        frame = SecureOpenFrame(cid="test", alg="CHACHA20P1305", eph_pub=b"0" * 32)
        result = await encryption_manager._send_secure_open_frame_async(frame, "dest")

        assert result is False

    async def test_send_secure_open_frame_async_no_physical_path(self, encryption_manager):
        """Test _send_secure_open_frame_async with no physical path."""
        encryption_manager._node_like.physical_path = None

        frame = SecureOpenFrame(cid="test", alg="CHACHA20P1305", eph_pub=b"0" * 32)
        result = await encryption_manager._send_secure_open_frame_async(frame, "dest")

        assert result is False

    async def test_send_secure_open_frame_async_exception(self, encryption_manager):
        """Test _send_secure_open_frame_async with exception."""
        frame = SecureOpenFrame(cid="test", alg="CHACHA20P1305", eph_pub=b"0" * 32)

        with patch.object(
            encryption_manager, "_deliver_secure_open_async", side_effect=Exception("test error")
        ):
            result = await encryption_manager._send_secure_open_frame_async(frame, "dest")

            assert result is False

    async def test_handle_failed_envelope_non_dataframe(self, encryption_manager):
        """Test _handle_failed_envelope with non-DataFrame."""
        frame = SecureOpenFrame(cid="test", alg="CHACHA20P1305", eph_pub=b"0" * 32)
        envelope = create_fame_envelope(frame=frame)

        await encryption_manager._handle_failed_envelope(envelope, "dest", "channel", "reason")

        # Should complete without sending NACK

    async def test_handle_failed_envelope_no_reply_to(self, encryption_manager):
        """Test _handle_failed_envelope with no reply_to address."""
        envelope = create_fame_envelope(frame=DataFrame(payload="test"))

        await encryption_manager._handle_failed_envelope(envelope, "dest", "channel", "reason")

        # Should complete without sending NACK

    async def test_handle_failed_envelope_with_reply_to(self, encryption_manager):
        """Test _handle_failed_envelope with reply_to address."""
        envelope = create_fame_envelope(frame=DataFrame(payload="test"))
        envelope.reply_to = FameAddress("reply@test")

        with patch.object(encryption_manager, "_send_delivery_nack") as mock_send_nack:
            await encryption_manager._handle_failed_envelope(envelope, "dest", "channel", "reason")

            mock_send_nack.assert_called_once_with(envelope, "channel_handshake_failed: reason")

    async def test_handle_failed_envelope_nack_exception(self, encryption_manager):
        """Test _handle_failed_envelope when NACK sending fails."""
        envelope = create_fame_envelope(frame=DataFrame(payload="test"))
        envelope.reply_to = FameAddress("reply@test")

        with patch.object(encryption_manager, "_send_delivery_nack", side_effect=Exception("nack failed")):
            await encryption_manager._handle_failed_envelope(envelope, "dest", "channel", "reason")

            # Should handle exception gracefully

    async def test_send_delivery_nack_no_node(self, encryption_manager):
        """Test _send_delivery_nack with no node."""
        encryption_manager._node_like = None

        envelope = create_fame_envelope(frame=DataFrame(payload="test"))
        await encryption_manager._send_delivery_nack(envelope, "reason")

        # Should complete without error

    async def test_send_delivery_nack_no_envelope_factory(self, encryption_manager):
        """Test _send_delivery_nack with no envelope factory."""
        encryption_manager._node_like._envelope_factory = None

        envelope = create_fame_envelope(frame=DataFrame(payload="test"))
        await encryption_manager._send_delivery_nack(envelope, "reason")

        # Should complete without error

    async def test_send_delivery_nack_successful(self, encryption_manager):
        """Test successful _send_delivery_nack."""
        # Set up frame and envelope with corr_id
        data_frame = DataFrame(payload="test")

        envelope = create_fame_envelope(frame=data_frame)
        envelope.reply_to = FameAddress("reply@test")
        envelope.corr_id = "test-correlation-id"

        # Mock envelope factory
        mock_nack_envelope = Mock()
        mock_nack_envelope.id = "nack-envelope-id"
        encryption_manager._node_like._envelope_factory.create_envelope.return_value = mock_nack_envelope

        await encryption_manager._send_delivery_nack(envelope, "test reason")

        # Verify envelope factory was called with correct arguments
        create_call = encryption_manager._node_like._envelope_factory.create_envelope.call_args
        assert create_call[1]["to"] == FameAddress(str(envelope.reply_to))
        assert isinstance(create_call[1]["frame"], DeliveryAckFrame)
        # corr_id should be passed to the envelope, not the frame anymore
        assert create_call[1]["corr_id"] == "test-correlation-id"
        assert create_call[1]["frame"].ok is False
        assert create_call[1]["frame"].code == "channel_handshake_failed"
        assert create_call[1]["frame"].reason == "test reason"

        # Verify delivery was called
        encryption_manager._node_like.deliver.assert_called_once()

    async def test_send_delivery_nack_exception(self, encryption_manager):
        """Test _send_delivery_nack with exception during creation."""
        envelope = create_fame_envelope(frame=DataFrame(payload="test"))
        envelope.reply_to = FameAddress("reply@test")

        with patch("naylence.fame.core.DeliveryAckFrame", side_effect=Exception("frame creation failed")):
            await encryption_manager._send_delivery_nack(envelope, "reason")

            # Should handle exception gracefully


class TestMakeJsonSerializable:
    """Test the _make_json_serializable helper function."""

    def test_pydantic_v2_model_dump(self):
        """Test with Pydantic v2 style object."""
        obj = Mock()
        obj.model_dump = Mock(return_value={"field": "value"})

        result = _make_json_serializable(obj)

        assert result == {"field": "value"}
        obj.model_dump.assert_called_once()

    def test_pydantic_v1_dict(self):
        """Test with Pydantic v1 style object."""
        obj = Mock()
        # Remove model_dump to test fallback
        del obj.model_dump
        obj.dict = Mock(return_value={"field": "value"})

        result = _make_json_serializable(obj)

        assert result == {"field": "value"}
        obj.dict.assert_called_once()

    def test_generic_object_with_dict(self):
        """Test with generic object having __dict__."""

        class TestObj:
            def __init__(self):
                self.field = "value"

        obj = TestObj()
        result = _make_json_serializable(obj)

        assert result == {"field": "value"}

    def test_already_serializable(self):
        """Test with already serializable object."""
        obj = {"field": "value"}
        result = _make_json_serializable(obj)

        assert result == obj

    def test_primitive_types(self):
        """Test with primitive types."""
        for obj in ["string", 123, 45.67, True, None]:
            result = _make_json_serializable(obj)
            assert result == obj

#!/usr/bin/env python3
"""
Tests for envelope security handling during node attachment.

This module verifies that the EnvelopeSecurityHandler properly handles
signed envelopes and key management during the node attachment process,
including edge cases where system ID, physical path, or other context
may not be available yet.
"""

from unittest.mock import AsyncMock, Mock

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.core.protocol.security_header import SecurityHeader, SignatureHeader
from naylence.fame.node.envelope_security_handler import EnvelopeSecurityHandler
from naylence.fame.security.encryption.channel.channel_encryption_manager import ChannelEncryptionManager


class TestEnvelopeSecurityDuringAttachment:
    """Test suite for envelope security handling during node attachment."""

    @pytest.mark.asyncio
    async def test_signed_envelope_during_attachment_with_no_system_id(self):
        """Test that signed envelopes can be processed even when from_system_id
        is None (during attachment).
        """
        print("🧪 Testing signed envelope processing during attachment without system ID")

        # Create mock dependencies
        mock_node = Mock()
        mock_node.physical_path = "/test-node"
        mock_node.sid = "test-node-123"

        # Create dependencies for EnvelopeSecurityHandler
        security_policy = Mock()
        key_mgmt_handler = Mock()

        # Mock that key is available for verification
        key_mgmt_handler.has_key = AsyncMock(return_value=True)

        # Mock envelope verifier
        envelope_verifier = Mock()
        envelope_verifier.verify_envelope = AsyncMock()

        # Create channel encryption manager
        channel_encryption_manager = ChannelEncryptionManager(node_like=mock_node)

        # Create envelope security handler
        envelope_security_handler = EnvelopeSecurityHandler(
            node_like=mock_node,
            security_policy=security_policy,
            key_management_handler=key_mgmt_handler,
            encryption_manager=channel_encryption_manager,
        )

        # Set envelope verifier
        envelope_security_handler._envelope_verifier = envelope_verifier

        # Create a signed DataFrame
        data_frame = DataFrame(
            payload={"test": "data"},
            codec="json",
        )

        # Create envelope with signature
        signature = SignatureHeader(kid="test-signing-key-123", val="mock-signature-data")

        envelope = FameEnvelope(
            id="test-envelope-123",
            to=FameAddress("destination@/test/destination"),
            frame=data_frame,
            sec=SecurityHeader(sig=signature),
        )

        # Create delivery context WITHOUT from_system_id (simulating attachment)
        context = FameDeliveryContext(
            from_system_id=None,  # This is the key test case - no system ID during attachment
            origin_type=DeliveryOriginType.DOWNSTREAM,
        )

        # Process the envelope - this should NOT crash
        should_continue = await envelope_security_handler.handle_signed_envelope(envelope, context)

        # Verify processing succeeded
        assert should_continue is True

        # Verify that key verification was attempted (key was available)
        key_mgmt_handler.has_key.assert_called_once_with("test-signing-key-123")
        envelope_verifier.verify_envelope.assert_called_once()

        print("✅ Signed envelope during attachment (no system ID) test passed")

    @pytest.mark.asyncio
    async def test_signed_envelope_during_attachment_missing_key(self):
        """Test that signed envelopes are queued when verification key is missing during attachment."""
        print("🧪 Testing signed envelope queuing when key missing during attachment")

        # Create mock dependencies
        mock_node = Mock()
        mock_node.physical_path = "/test-node"
        mock_node.sid = "test-node-123"

        # Create dependencies for EnvelopeSecurityHandler
        security_policy = Mock()
        key_mgmt_handler = Mock()

        # Mock that key is NOT available
        key_mgmt_handler.has_key = AsyncMock(return_value=False)
        key_mgmt_handler._pending_envelopes = {}
        key_mgmt_handler._maybe_request_signing_key = AsyncMock()

        # Mock envelope verifier
        envelope_verifier = Mock()

        # Create channel encryption manager
        channel_encryption_manager = ChannelEncryptionManager(node_like=mock_node)

        # Create envelope security handler
        envelope_security_handler = EnvelopeSecurityHandler(
            node_like=mock_node,
            security_policy=security_policy,
            key_management_handler=key_mgmt_handler,
            encryption_manager=channel_encryption_manager,
        )

        # Set envelope verifier
        envelope_security_handler._envelope_verifier = envelope_verifier

        # Create a signed DataFrame
        data_frame = DataFrame(
            payload={"test": "data"},
            codec="json",
        )

        # Create envelope with signature
        signature = SignatureHeader(kid="missing-signing-key-456", val="mock-signature-data")

        envelope = FameEnvelope(
            id="test-envelope-456",
            to=FameAddress("destination@/test/destination"),
            frame=data_frame,
            sec=SecurityHeader(sig=signature),
        )

        # Create delivery context during attachment
        context = FameDeliveryContext(
            from_system_id="remote-system", origin_type=DeliveryOriginType.DOWNSTREAM
        )

        # Process the envelope - this should queue it since key is missing
        should_continue = await envelope_security_handler.handle_signed_envelope(envelope, context)

        # Verify processing was queued (should_continue = False)
        assert should_continue is False

        # Verify that key lookup was attempted
        key_mgmt_handler.has_key.assert_called_once_with("missing-signing-key-456")

        # Verify key request was attempted
        key_mgmt_handler._maybe_request_signing_key.assert_called_once()

        # Verify envelope was queued in the key management handler
        assert "missing-signing-key-456" in key_mgmt_handler._pending_envelopes
        queued_items = key_mgmt_handler._pending_envelopes["missing-signing-key-456"]
        assert len(queued_items) == 1
        queued_envelope, queued_context = queued_items[0]
        assert queued_envelope == envelope
        assert queued_context == context

        print("✅ Signed envelope queuing (missing key during attachment) test passed")

    @pytest.mark.asyncio
    async def test_signed_envelope_during_attachment_with_missing_physical_path(self):
        """Test that signed envelopes are handled when physical_path is missing during attachment."""
        print("🧪 Testing signed envelope processing during attachment without physical path")

        # Create mock dependencies
        mock_node = Mock()
        mock_node.physical_path = None  # Physical path not set yet during attachment
        mock_node.sid = None  # SID also not set yet

        # Create dependencies for EnvelopeSecurityHandler
        security_policy = Mock()
        key_mgmt_handler = Mock()

        # Mock that key is NOT available
        key_mgmt_handler.has_key = AsyncMock(return_value=False)
        key_mgmt_handler._pending_envelopes = {}
        key_mgmt_handler._maybe_request_signing_key = AsyncMock()

        # Mock envelope verifier
        envelope_verifier = Mock()

        # Create channel encryption manager
        channel_encryption_manager = ChannelEncryptionManager(node_like=mock_node)

        # Create envelope security handler
        envelope_security_handler = EnvelopeSecurityHandler(
            node_like=mock_node,
            security_policy=security_policy,
            key_management_handler=key_mgmt_handler,
            encryption_manager=channel_encryption_manager,
        )

        # Set envelope verifier
        envelope_security_handler._envelope_verifier = envelope_verifier

        # Create a signed DataFrame
        data_frame = DataFrame(
            payload={"test": "data"},
            codec="json",
        )

        # Create envelope with signature
        signature = SignatureHeader(kid="test-key-789", val="mock-signature-data")

        envelope = FameEnvelope(
            id="test-envelope-789",
            to=FameAddress("destination@/test/destination"),
            frame=data_frame,
            sec=SecurityHeader(sig=signature),
        )

        # Create delivery context during attachment
        context = FameDeliveryContext(
            from_system_id="remote-system", origin_type=DeliveryOriginType.DOWNSTREAM
        )

        # Process the envelope - this should handle gracefully despite missing physical_path
        should_continue = await envelope_security_handler.handle_signed_envelope(envelope, context)

        # Verify processing was queued (should_continue = False since key missing)
        assert should_continue is False

        # Verify that key lookup was attempted
        key_mgmt_handler.has_key.assert_called_once_with("test-key-789")

        # Verify key request was attempted (even without physical_path)
        key_mgmt_handler._maybe_request_signing_key.assert_called_once()

        # Verify envelope was queued
        assert "test-key-789" in key_mgmt_handler._pending_envelopes
        queued_items = key_mgmt_handler._pending_envelopes["test-key-789"]
        assert len(queued_items) == 1
        queued_envelope, queued_context = queued_items[0]
        assert queued_envelope == envelope
        assert queued_context == context

        print("✅ Signed envelope during attachment (missing physical path) test passed")

    @pytest.mark.asyncio
    async def test_envelope_security_context_missing_properties(self):
        """Test that envelope security handling works with minimal context properties."""
        print("🧪 Testing envelope security with minimal context properties")

        # Create mock dependencies
        mock_node = Mock()
        mock_node.physical_path = "/test-node"
        mock_node.sid = "test-node-123"

        # Create dependencies for EnvelopeSecurityHandler
        security_policy = Mock()
        key_mgmt_handler = Mock()
        key_mgmt_handler.has_key = AsyncMock(return_value=True)

        # Mock envelope verifier
        envelope_verifier = Mock()
        envelope_verifier.verify_envelope = AsyncMock()

        # Create channel encryption manager
        channel_encryption_manager = ChannelEncryptionManager(node_like=mock_node)

        # Create envelope security handler
        envelope_security_handler = EnvelopeSecurityHandler(
            node_like=mock_node,
            security_policy=security_policy,
            key_management_handler=key_mgmt_handler,
            encryption_manager=channel_encryption_manager,
        )

        # Set envelope verifier
        envelope_security_handler._envelope_verifier = envelope_verifier

        # Create a signed DataFrame
        data_frame = DataFrame(
            payload={"test": "data"},
            codec="json",
        )

        # Create envelope with signature
        signature = SignatureHeader(kid="test-key-context", val="mock-signature-data")

        envelope = FameEnvelope(
            id="test-envelope-context",
            to=FameAddress("destination@/test/destination"),
            frame=data_frame,
            sec=SecurityHeader(sig=signature),
        )

        # Test with minimal context - testing that missing context properties are handled gracefully
        minimal_context = FameDeliveryContext(
            from_system_id="test-system", origin_type=DeliveryOriginType.DOWNSTREAM
        )

        should_continue = await envelope_security_handler.handle_signed_envelope(envelope, minimal_context)

        # Should still work with minimal context
        assert should_continue is True

        # Verify that key verification was attempted
        key_mgmt_handler.has_key.assert_called_with("test-key-context")
        envelope_verifier.verify_envelope.assert_called()

        print("✅ Envelope security with minimal context properties test passed")

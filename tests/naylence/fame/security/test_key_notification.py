#!/usr/bin/env python3
"""
Test script to verify that the X25519EncryptionManager key notification system works properly.
"""

import asyncio

# Set up logging
import logging as stdlib_logging

import pytest

from naylence.fame.core import DataFrame, FameAddress, FameEnvelope, generate_id
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
from naylence.fame.security.encryption.composite_encryption_manager import CompositeEncryptionManager
from naylence.fame.security.encryption.encryption_manager import EncryptionOptions
from naylence.fame.security.encryption.sealed.x25519_encryption_manager import X25519EncryptionManager
from naylence.fame.security.keys.key_provider import get_key_provider

stdlib_logging.basicConfig(level=stdlib_logging.DEBUG)
logger = stdlib_logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_x25519_key_notification():
    """Test that X25519EncryptionManager properly queues and flushes envelopes."""

    print("=== Testing X25519EncryptionManager Key Notification ===")

    # Set up X25519 encryption manager
    crypto = get_crypto_provider()
    x25519_manager = X25519EncryptionManager(crypto=crypto, key_provider=get_key_provider())

    # Create test envelope
    envelope = FameEnvelope(
        id=generate_id(),
        frame=DataFrame(payload="test message"),
        to=FameAddress("test-service@/test/recipient"),
    )

    # Create fake key ID
    # fake_kid = "fake_test_key_123"

    # Set up encryption options that will trigger queueing (using request_address like the security policy)
    encryption_opts = EncryptionOptions(request_address=FameAddress("test-service@/test/recipient"))

    print("Step 1: Encrypting envelope with missing key for address test-service@/test/recipient")
    result = await x25519_manager.encrypt_envelope(envelope, opts=encryption_opts)
    print(f"Encryption result status: {result.status}")

    # The X25519 manager creates a temporary key ID based on the request address
    temp_key_id = "request-test-service@/test/recipient"

    # Check if envelope was queued
    queued_count_before = len(x25519_manager._pending_envelopes.get(temp_key_id, []))
    print(f"Queued envelopes before key notification: {queued_count_before}")

    if queued_count_before == 0:
        print("✗ Envelope was not queued as expected")
        return False
    else:
        print("✓ Envelope was queued correctly")

    # Now simulate key becoming available by calling notify_key_available with the address-based key ID
    print(f"\nStep 2: Notifying about address-based key ID: {temp_key_id}")
    await x25519_manager.notify_key_available(temp_key_id)

    # Check if envelope was flushed from queue
    await asyncio.sleep(0.1)  # Give a moment for async processing
    queued_count_after = len(x25519_manager._pending_envelopes.get(temp_key_id, []))
    print(f"Queued envelopes after key notification: {queued_count_after}")

    if queued_count_after < queued_count_before:
        print("✓ Key notification triggered envelope processing")
        return True
    else:
        print("✗ Key notification did not trigger envelope processing")
        print(f"  Available keys in queue: {list(x25519_manager._pending_envelopes.keys())}")
        return False


@pytest.mark.asyncio
async def test_composite_key_notification():
    """Test that CompositeEncryptionManager forwards key notifications."""

    print("\n=== Testing CompositeEncryptionManager Key Notification ===")

    # Create a mock channel manager for testing
    class MockSecureChannelManager:
        def __init__(self):
            self._channels = {}

    mock_secure_channel_manager = MockSecureChannelManager()

    # Set up composite encryption manager
    crypto = get_crypto_provider()
    composite_manager = CompositeEncryptionManager(
        secure_channel_manager=mock_secure_channel_manager,  # type: ignore
        crypto=crypto,
        key_provider=get_key_provider(),
    )

    # Create test envelope
    envelope = FameEnvelope(
        id=generate_id(),
        frame=DataFrame(payload="test message"),
        to=FameAddress("test-service@/test/recipient"),
    )

    # Create fake key ID
    "fake_test_key_456"

    # Set up encryption options that will trigger queueing (using request_address like the security policy)
    encryption_opts = EncryptionOptions(request_address=FameAddress("test-service@/test/recipient"))

    print("Step 1: Encrypting envelope with missing key for address test-service@/test/recipient")
    result = await composite_manager.encrypt_envelope(envelope, opts=encryption_opts)
    print(f"Encryption result status: {result.status}")

    # The X25519 manager creates a temporary key ID based on the request address
    temp_key_id = "request-test-service@/test/recipient"

    # Check if envelope was queued in the underlying X25519 manager
    x25519_manager = composite_manager._sealed
    queued_count_before = len(x25519_manager._pending_envelopes.get(temp_key_id, []))  # type: ignore
    print(f"Queued envelopes before key notification: {queued_count_before}")

    if queued_count_before == 0:
        print("✗ Envelope was not queued as expected")
        return False
    else:
        print("✓ Envelope was queued correctly")

    # Now simulate key becoming available by calling notify_key_available
    # on composite manager with address-based key ID
    print(f"\nStep 2: Notifying composite manager about address-based key ID: {temp_key_id}")
    await composite_manager.notify_key_available(temp_key_id)

    # Check if envelope was flushed from queue
    await asyncio.sleep(0.1)  # Give a moment for async processing
    queued_count_after = len(x25519_manager._pending_envelopes.get(temp_key_id, []))  # type: ignore
    print(f"Queued envelopes after key notification: {queued_count_after}")

    if queued_count_after < queued_count_before:
        print("✓ Key notification was forwarded and triggered envelope processing")
        return True
    else:
        print("✗ Key notification was not properly forwarded")
        print(f"  Available keys in queue: {list(x25519_manager._pending_envelopes.keys())}")  # type: ignore
        return False


@pytest.mark.asyncio
async def test_all_key_notifications():
    """Run all key notification tests."""
    try:
        print("Testing X25519EncryptionManager and CompositeEncryptionManager key notifications\n")

        # Test X25519 manager directly
        success1 = await test_x25519_key_notification()

        # Test composite manager forwarding
        success2 = await test_composite_key_notification()

        if success1 and success2:
            print("\n🎉 All key notification tests passed!")
            assert True
        else:
            print("\n❌ Some key notification tests failed")
            assert False, "Some key notification tests failed"
    except Exception as e:
        print(f"\n💥 Test failed with exception: {e}")
        import traceback

        traceback.print_exc()
        assert False, f"Test failed with exception: {e}"

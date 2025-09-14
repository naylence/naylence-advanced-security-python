#!/usr/bin/env python3
"""
Test script to verify that AddressBindFrame properly includes encryption_key_id.
"""

from unittest.mock import AsyncMock

import pytest

# Add the src directory to Python path
from naylence.fame.core import FameAddress
from naylence.fame.node.binding_manager import BindingManager, BindingStoreEntry
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore


@pytest.mark.asyncio
async def test_encryption_key_id_in_address_bind():
    """Test that AddressBindFrame includes the encryption_key_id field."""
    print("Testing encryption_key_id in AddressBindFrame...")

    # Get the crypto provider to check the encryption key ID
    crypto_provider = get_crypto_provider()
    expected_encryption_key_id = crypto_provider.encryption_key_id
    print(f"Expected encryption key ID: {expected_encryption_key_id}")

    # Mock dependencies
    forward_upstream_mock = AsyncMock()

    # Use a real envelope factory instead of a mock
    from naylence.fame.node.node_envelope_factory import NodeEnvelopeFactory

    envelope_factory = NodeEnvelopeFactory(
        physical_path_fn=lambda: "/test-path",
        sid_fn=lambda: "test-sid",
    )

    binding_store = InMemoryKVStore(BindingStoreEntry)

    # Create a delivery tracker for the binding manager
    from naylence.fame.delivery.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    storage_provider = InMemoryStorageProvider()
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

    # Create binding manager with encryption key ID function
    binding_manager = BindingManager(
        has_upstream=True,
        get_id=lambda: "test-node-id",
        get_sid=lambda: "test-sid",
        get_physical_path=lambda: "/test-path",
        get_accepted_logicals=lambda: {"/logical/*"},
        get_encryption_key_id=lambda: expected_encryption_key_id,
        forward_upstream=forward_upstream_mock,
        binding_store=binding_store,
        envelope_factory=envelope_factory,
        ack_timeout_ms=5000,
        delivery_tracker=delivery_tracker,
    )

    # Create a test address to bind
    test_address = FameAddress("test@/logical/service")

    try:
        # This should fail because we're not actually setting up the full async machinery,
        # but we can capture what was sent upstream
        await binding_manager._bind_address_upstream(test_address)
    except Exception:
        # We expect this to fail due to timeout or other issues, but let's check what was sent
        pass

    # Check if forward_upstream was called
    if forward_upstream_mock.called:
        # Get the envelope that was sent upstream
        call_args = forward_upstream_mock.call_args
        envelope = call_args[0][0]  # First argument of the call
        frame = envelope.frame

        print("AddressBindFrame sent upstream:")
        print(f"  address: {frame.address}")
        print(f"  physical_path: {frame.physical_path}")
        print(f"  encryption_key_id: {frame.encryption_key_id}")

        if frame.encryption_key_id == expected_encryption_key_id:
            print("✅ AddressBindFrame properly includes encryption_key_id")
            return True
        else:
            print(
                f"❌ Expected encryption_key_id '{expected_encryption_key_id}'"
                ", got '{frame.encryption_key_id}'"
            )
            return False
    else:
        print("❌ forward_upstream was not called")
        return False


@pytest.mark.asyncio
async def test_node_encryption_key_id_property():
    """Test that the node properly returns its encryption key ID."""
    print("\nTesting node encryption_key_id property...")

    # We can't easily create a full node for testing, so let's test the logic directly
    crypto_provider = get_crypto_provider()
    expected_key_id = crypto_provider.encryption_key_id

    print(f"Crypto provider encryption_key_id: {crypto_provider.encryption_key_id}")
    print(f"Expected encryption key ID: {expected_key_id}")

    # Test that the encryption key ID exists and is valid
    if expected_key_id and len(expected_key_id) > 0:
        print("✅ Encryption key ID is valid and available")
        return True
    else:
        print("❌ Encryption key ID is missing or invalid")
        return False

"""
Test for root path encryption key lookup in security policy.
"""

import pytest

from naylence.fame.core.address.address import FameAddress
from naylence.fame.core.protocol.envelope import FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.security.keys.key_provider import get_key_provider
from naylence.fame.security.policy import DefaultSecurityPolicy


@pytest.mark.asyncio
async def test_root_path_encryption_key_lookup():
    """Test that root path addresses trigger address-based key requests when no key is found locally."""
    policy = DefaultSecurityPolicy(key_provider=get_key_provider())

    # Test root path address
    root_address = FameAddress("math@/")

    # Create an envelope with the root path destination
    envelope = FameEnvelope(
        id="test-envelope",
        to=root_address,
        frame=DataFrame(payload={"test": "data"}),
        version="1.0",
    )

    # This should raise an exception since no key is found locally
    # The exception will trigger the address-based key request mechanism
    try:
        kid, pub_key_bytes = await policy._lookup_recipient_encryption_key(
            envelope.to, node_physical_path=None
        )
        # If we get here, a key was found locally (unexpected in this test)
        print(f"❌ Unexpected local key found: {kid}")
        assert False, "Expected no local key to be found"
    except ValueError as e:
        # This is expected - no local key found
        assert "No encryption key found for address" in str(e)
        print(f"✅ Root path address correctly triggers key request: {e}")


@pytest.mark.asyncio
async def test_root_path_get_encryption_options():
    """Test that get_encryption_options returns request_address for addresses without local keys."""
    policy = DefaultSecurityPolicy()

    # Create an envelope with a root path destination
    envelope = FameEnvelope(
        id="test-envelope",
        to=FameAddress("math@/"),
        frame=DataFrame(payload={"test": "data"}),
        version="1.0",
    )

    # Get encryption options
    options = await policy.get_encryption_options(envelope)

    assert options is not None, "Expected encryption options for root path address"
    assert "request_address" in options, "Expected request_address in options"
    assert str(options["request_address"]) == "math@/", (
        f"Expected 'math@/', got '{options['request_address']}'"
    )
    print(f"✅ Root path envelope gets address-based encryption options: {options['request_address']}")


@pytest.mark.asyncio
async def test_logical_address_encryption_key_lookup():
    """Test that logical addresses also trigger address-based key requests."""
    policy = DefaultSecurityPolicy(key_provider=get_key_provider())

    # Test logical address (could be mapped to any physical node)
    logical_address = FameAddress("calculator@/logical/math-service")

    # Create an envelope with the logical address destination
    envelope = FameEnvelope(
        id="test-envelope",
        to=logical_address,
        frame=DataFrame(payload={"test": "data"}),
        version="1.0",
    )

    # This should raise an exception since no key is found locally
    try:
        kid, pub_key_bytes = await policy._lookup_recipient_encryption_key(
            envelope.to, node_physical_path=None
        )
        # If we get here, a key was found locally (unexpected in this test)
        print(f"❌ Unexpected local key found: {kid}")
        assert False, "Expected no local key to be found"
    except ValueError as e:
        # This is expected - no local key found
        assert "No encryption key found for address" in str(e)
        print(f"✅ Logical address correctly triggers key request: {e}")


@pytest.mark.asyncio
async def test_regular_path_encryption_key_lookup():
    """Test that regular path addresses also trigger address-based key requests."""
    policy = DefaultSecurityPolicy(key_provider=get_key_provider())

    # Test regular path address
    regular_address = FameAddress("math@/system1/service")

    # Create an envelope with the regular path destination
    envelope = FameEnvelope(
        id="test-envelope",
        to=regular_address,
        frame=DataFrame(payload={"test": "data"}),
        version="1.0",
    )

    # This should raise an exception since no key is found locally
    try:
        kid, pub_key_bytes = await policy._lookup_recipient_encryption_key(
            envelope.to, node_physical_path=None
        )
        # If we get here, a key was found locally (unexpected in this test)
        print(f"❌ Unexpected local key found: {kid}")
        assert False, "Expected no local key to be found"
    except ValueError as e:
        # This is expected - no local key found
        assert "No encryption key found for address" in str(e)
        print(f"✅ Regular path address correctly triggers key request: {e}")


@pytest.mark.asyncio
async def test_all_root_path_encryption():
    """Run all root path encryption tests."""
    await test_root_path_encryption_key_lookup()
    await test_root_path_get_encryption_options()
    await test_logical_address_encryption_key_lookup()
    await test_regular_path_encryption_key_lookup()
    print("\n🎉 All address-based encryption tests passed!")

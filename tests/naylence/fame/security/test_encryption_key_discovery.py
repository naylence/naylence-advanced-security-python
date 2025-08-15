#!/usr/bin/env python3
"""
Test encryption key discovery and envelope encryption flow.
"""

import pytest

from naylence.fame.core import DeliveryOriginType, FameAddress, FameDeliveryContext
from naylence.fame.core.protocol.envelope import FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
from naylence.fame.security.keys.key_store import get_key_store
from naylence.fame.security.policy import DefaultSecurityPolicy


@pytest.mark.asyncio
async def test_encryption_key_discovery():
    """Test the encryption key discovery flow."""
    print("=== Testing Encryption Key Discovery ===")

    # 1. Setup crypto provider and get keys
    crypto = get_crypto_provider()
    jwks = crypto.get_jwks()

    print(f"Generated {len(jwks['keys'])} keys:")
    encryption_key = None

    for key in jwks["keys"]:
        kid = key.get("kid", "NO_KID")
        use = key.get("use", "sig")
        kty = key.get("kty", "unknown")
        print(f"  - {kid}: {use} ({kty})")

        if use == "sig":
            # signing_key = key
            pass
        elif use == "enc":
            encryption_key = key

    # 2. Setup key store and add keys
    key_store = get_key_store()

    # Add keys to the key store for a test system
    test_system_id = "test-node-123"
    test_path = f"/{test_system_id}"

    # Add all keys to the key store - need to mark with physical_path
    for key in jwks["keys"]:
        key["physical_path"] = test_path

    await key_store.add_keys(jwks["keys"], physical_path=test_path)

    print(f"\nAdded keys to key store for path: {test_path}")

    # Debug: check what was actually stored
    stored_keys = list(await key_store.get_keys_for_path(test_path))
    print(f"Verification: {len(stored_keys)} keys stored for path {test_path}")
    for key in stored_keys:
        print(f"  - {key.get('kid', 'NO_KID')}: {key.get('use', 'sig')}")

    # 3. Test security policy key lookup
    security_policy = DefaultSecurityPolicy()

    # Create a test envelope
    envelope = FameEnvelope(
        frame=DataFrame(payload={"message": "Hello, encrypted world!"}, codec="json"),
        to=FameAddress(f"{test_system_id}@{test_path}/test-service"),
    )

    context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, from_system_id="sender-123")

    print(f"\nTest envelope target: {envelope.to}")

    # 4. Test encryption options lookup
    try:
        encryption_opts = await security_policy.get_encryption_options(envelope, context)

        if encryption_opts:
            recip_kid = encryption_opts.get("recip_kid")
            recip_pub = encryption_opts.get("recip_pub")

            print("\n✅ Successfully looked up encryption options:")
            print(f"   Recipient KID: {recip_kid}")
            print(f"   Public key bytes length: {len(recip_pub) if recip_pub else 0}")

            # Verify the key matches what we stored
            if encryption_key and recip_kid == encryption_key.get("kid"):
                print("✅ Key ID matches the encryption key we stored")
            else:
                print("❌ Key ID doesn't match expected encryption key")

        else:
            print("❌ No encryption options returned")

    except Exception as e:
        print(f"❌ Error looking up encryption options: {e}")

    # 5. Test with a non-existent recipient
    print("\n--- Testing with non-existent recipient ---")
    envelope_bad = FameEnvelope(
        frame=DataFrame(payload={"message": "test"}, codec="json"),
        to=FameAddress("nonexistent@/unknown-node/service"),
    )

    try:
        encryption_opts_bad = await security_policy.get_encryption_options(envelope_bad, context)
        if encryption_opts_bad:
            print("❌ Unexpected: got encryption options for non-existent recipient")
        else:
            print("✅ Correctly returned None for non-existent recipient")
    except Exception as e:
        print(f"✅ Correctly failed to find key for non-existent recipient: {e}")

    print("\n=== Test completed ===")

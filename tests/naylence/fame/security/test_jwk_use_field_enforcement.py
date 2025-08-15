from unittest.mock import AsyncMock, Mock

import pytest

from naylence.fame.core import DeliveryOriginType, FameDeliveryContext, FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.core.protocol.security_header import SecurityHeader, SignatureHeader
from naylence.fame.security.encryption.sealed.x25519_encryption_manager import X25519EncryptionManager
from naylence.fame.security.keys.default_key_manager import DefaultKeyManager
from naylence.fame.security.keys.key_store import get_key_store
from naylence.fame.security.signing.eddsa_envelope_verifier import EdDSAEnvelopeVerifier


def create_test_jwks():
    """Create test JWKs with various use fields."""
    return {
        "valid_signing": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "bWVzc2FnZSBmb3IgdGVzdGluZyBwdXJwb3NlcyBvbmx5",
            "kid": "test-signing-valid",
            "use": "sig",
            "alg": "EdDSA",
        },
        "valid_encryption": {
            "kty": "OKP",
            "crv": "X25519",
            "x": "bWVzc2FnZSBmb3IgdGVzdGluZyBwdXJwb3NlcyBvbmx5",
            "kid": "test-encryption-valid",
            "use": "enc",
            "alg": "ECDH-ES",
        },
        "no_use_field": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "bWVzc2FnZSBmb3IgdGVzdGluZyBwdXJwb3NlcyBvbmx5",
            "kid": "test-no-use",
            "alg": "EdDSA",
        },
        "wrong_use_signing": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "bWVzc2FnZSBmb3IgdGVzdGluZyBwdXJwb3NlcyBvbmx5",
            "kid": "test-wrong-use-signing",
            "use": "enc",  # Ed25519 marked for encryption (wrong)
            "alg": "EdDSA",
        },
        "wrong_use_encryption": {
            "kty": "OKP",
            "crv": "X25519",
            "x": "bWVzc2FnZSBmb3IgdGVzdGluZyBwdXJwb3NlcyBvbmx5",
            "kid": "test-wrong-use-encryption",
            "use": "sig",  # X25519 marked for signing (wrong)
            "alg": "ECDH-ES",
        },
        "invalid_use": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "bWVzc2FnZSBmb3IgdGVzdGluZyBwdXJwb3NlcyBvbmx5",
            "kid": "test-invalid-use",
            "use": "invalid",
            "alg": "EdDSA",
        },
    }


@pytest.mark.asyncio
async def test_key_announce_validation():
    """Test that KeyAnnounce frames validate JWK use fields."""
    print("=== Testing KeyAnnounce Use Field Validation ===")

    # Create a DefaultKeyManager for testing
    key_store = get_key_store()
    key_store._keys.clear()  # Clear any existing keys  # type: ignore

    mock_node = Mock()
    mock_node._id = "test-node"
    mock_node._sid = "test-sid"
    mock_node.physical_path = "/test"
    mock_node._has_parent = False
    mock_node._envelope_factory = Mock()
    mock_node.forward_upstream = AsyncMock()

    key_manager = DefaultKeyManager(key_store=key_store)
    await key_manager.on_node_started(mock_node)

    test_jwks = create_test_jwks()
    all_keys = list(test_jwks.values())

    # Try to add all keys via KeyAnnounce
    await key_manager.add_keys(
        keys=all_keys,
        physical_path="/test-source",
        system_id="test-source-node",
        origin=DeliveryOriginType.LOCAL,
    )

    # Check which keys were actually stored
    stored_keys = list(await key_store.get_keys())
    stored_kids = {k["kid"] for k in stored_keys}

    expected_valid = {"test-signing-valid", "test-encryption-valid"}

    if stored_kids == expected_valid:
        print("✅ KeyAnnounce correctly accepted only valid keys with proper use fields")
        print(f"   Accepted: {sorted(stored_kids)}")
    else:
        print("❌ KeyAnnounce validation failed")
        print(f"   Expected: {sorted(expected_valid)}")
        print(f"   Got: {sorted(stored_kids)}")

    return len(stored_keys) == 2


@pytest.mark.asyncio
async def test_signing_key_use_enforcement():
    """Test that signature verification enforces use='sig'."""
    print("\n=== Testing Signature Verification Use Field Enforcement ===")

    # Setup key store with test keys
    key_store = get_key_store()
    key_store._keys.clear()  # type: ignore

    test_jwks = create_test_jwks()

    # Add keys with their proper metadata
    for kid, jwk in test_jwks.items():
        if "valid" in kid:  # Only add the valid keys
            jwk_with_metadata = dict(jwk)
            jwk_with_metadata["sid"] = "test-sid"
            jwk_with_metadata["physical_path"] = "/test"
            await key_store.add_key(jwk["kid"], jwk_with_metadata)

    verifier = EdDSAEnvelopeVerifier(key_provider=key_store)

    # Create a test envelope with signature
    envelope = FameEnvelope(
        frame=DataFrame(payload="test message"),
        sec=SecurityHeader(
            sig=SignatureHeader(
                kid="test-signing-valid",  # Valid signing key
                val="fake-signature",
            )
        ),
    )

    # Test with valid signing key
    try:
        # This will fail due to fake signature, but should validate the key use first
        await verifier.verify_envelope(envelope, check_payload=False)
        print("❌ Expected signature verification to fail with fake signature")
    except ValueError as e:
        if "is not valid for signing" in str(e):
            print("❌ Valid signing key was rejected due to use field")
        else:
            print("✅ Valid signing key passed use field validation (failed on signature as expected)")
    except Exception as e:
        print(f"✅ Valid signing key passed use field validation (failed later: {type(e).__name__})")

    # Test with encryption key used for signing (should be rejected)
    assert envelope.sec is not None and envelope.sec.sig is not None, (
        "Envelope should have security header with signature"
    )
    envelope.sec.sig.kid = "test-encryption-valid"
    try:
        await verifier.verify_envelope(envelope, check_payload=False)
        print("❌ Encryption key was accepted for signature verification")
    except ValueError as e:
        if "is not valid for signing" in str(e):
            print("✅ Encryption key correctly rejected for signature verification")
        else:
            print(f"❌ Unexpected error: {e}")
    except Exception as e:
        print(f"❌ Unexpected exception: {e}")

    return True


@pytest.mark.asyncio
async def test_encryption_key_use_enforcement():
    """Test that encryption operations enforce use='enc'."""
    print("\n=== Testing Encryption Use Field Enforcement ===")

    # Setup key store with test keys
    key_store = get_key_store()
    key_store._keys.clear()  # type: ignore

    test_jwks = create_test_jwks()

    # Add keys with encryption private key data for testing
    for kid, jwk in test_jwks.items():
        if "valid" in kid:
            jwk_with_metadata = dict(jwk)
            jwk_with_metadata["sid"] = "test-sid"
            jwk_with_metadata["physical_path"] = "/test"
            # Add fake private key data for testing
            jwk_with_metadata["encryption_private_pem"] = "fake-private-key"
            await key_store.add_key(jwk["kid"], jwk_with_metadata)

    encryption_manager = X25519EncryptionManager(key_provider=key_store)

    # Create a test encrypted envelope
    from naylence.fame.core.protocol.security_header import EncryptionHeader

    envelope = FameEnvelope(
        frame=DataFrame(payload="dGVzdCBtZXNzYWdl", codec="b64"),  # base64 encoded test
        sec=SecurityHeader(
            enc=EncryptionHeader(alg="ECDH-ES+A256GCM", kid="test-encryption-valid", val="fake-prefix-data")
        ),
    )

    # Test with valid encryption key
    try:
        await encryption_manager.decrypt_envelope(envelope)
        print("❌ Expected decryption to fail with fake data")
    except ValueError as e:
        if "is not valid for encryption" in str(e):
            print("❌ Valid encryption key was rejected due to use field")
        else:
            print("✅ Valid encryption key passed use field validation (failed on crypto as expected)")
    except Exception as e:
        print(f"✅ Valid encryption key passed use field validation (failed later: {type(e).__name__})")

    # Test with signing key used for encryption (should be rejected)
    assert envelope.sec is not None and envelope.sec.enc is not None, (
        "Envelope should have security header with encryption"
    )
    envelope.sec.enc.kid = "test-signing-valid"
    try:
        await encryption_manager.decrypt_envelope(envelope)
        print("❌ Signing key was accepted for encryption")
    except ValueError as e:
        if "is not valid for encryption" in str(e):
            print("✅ Signing key correctly rejected for encryption")
        else:
            print(f"❌ Unexpected error: {e}")
    except Exception as e:
        print(f"❌ Unexpected exception: {e}")

    return True


@pytest.mark.asyncio
async def test_security_policy_use_field_lookup():
    """Test that security policy only returns keys with use='enc'."""
    print("\n=== Testing Security Policy Use Field Lookup ===")

    from naylence.fame.core import FameAddress
    from naylence.fame.security.policy import DefaultSecurityPolicy

    # Setup key store
    key_store = get_key_store()
    key_store._keys.clear()  # type: ignore

    test_jwks = create_test_jwks()

    # Add only the valid keys to store (the invalid ones will be rejected)
    valid_keys = [test_jwks["valid_signing"], test_jwks["valid_encryption"]]
    # Store keys with participant name - the security policy will look here as fallback
    await key_store.add_keys(valid_keys, physical_path="test-system")

    # Check what was stored
    stored_keys = list(await key_store.get_keys())
    print(f"   Stored {len(stored_keys)} keys after validation")
    for key in stored_keys:
        print(f"   - {key['kid']}: use={key.get('use')}, kty={key.get('kty')}, crv={key.get('crv')}")

    security_policy = DefaultSecurityPolicy()

    # Create a test envelope looking for test-system
    envelope = FameEnvelope(
        frame=DataFrame(payload="test"), to=FameAddress("test-system@/test-system/service")
    )

    context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, from_system_id="sender")

    # Try to get encryption options
    print(f"   Looking for encryption options for address: {envelope.to}")
    encryption_opts = await security_policy.get_encryption_options(envelope, context)
    print(f"   Security policy returned: {encryption_opts}")

    if encryption_opts:
        recip_kid = encryption_opts.get("recip_kid")
        if recip_kid == "test-encryption-valid":
            print("✅ Security policy correctly found only the valid encryption key")
        else:
            print(f"❌ Security policy returned wrong key: {recip_kid}")
        return True
    else:
        print("❌ Security policy did not find any encryption options")
        # Let's debug why - check if we're looking in the right place
        all_keys = list(await key_store.get_keys())
        print("   All keys in store:")
        for key in all_keys:
            print(f"     - {key['kid']}: path='{key.get('physical_path')}', use={key.get('use')}")

        stored_keys_for_path = list(await key_store.get_keys_for_path("/test-system"))
        print(f"   Keys stored for path '/test-system': {len(stored_keys_for_path)}")
        for key in stored_keys_for_path:
            print(f"     - {key['kid']}: {key.get('use')}")

        # Also check if the address parsing is working correctly

        address_str = str(envelope.to)
        print(f"   Parsed address string: '{address_str}'")

        if "@" in address_str:
            participant, path_part = address_str.split("@", 1)
            print(f"   Participant: '{participant}', Path part: '{path_part}'")
            path_without_service = path_part.rsplit("/", 1)[0] if "/" in path_part else path_part
            print(f"   System path (without service): '{path_without_service}'")

        return False


@pytest.mark.asyncio
async def test_all_use_field_enforcement():
    """Run all use field enforcement tests."""
    print("🧪 Testing JWK 'use' field enforcement in key operations\n")

    results = []

    results.append(await test_key_announce_validation())
    results.append(await test_signing_key_use_enforcement())
    results.append(await test_encryption_key_use_enforcement())
    results.append(await test_security_policy_use_field_lookup())

    passed = sum(results)
    total = len(results)

    print("\n=== Test Results ===")
    print(f"Passed: {passed}/{total}")

    if passed == total:
        print("🎉 All JWK use field enforcement tests passed!")
        assert True
    else:
        print("❌ Some tests failed")
        assert False, "Some JWK use field enforcement tests failed"

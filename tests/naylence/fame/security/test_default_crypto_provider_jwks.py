#!/usr/bin/env python3
"""
Test script to verify DefaultCryptoProvider JWKS generation after simplification
"""

from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider


def test_jwks_generation():
    """Test that JWKS is correctly generated with both signing and encryption keys."""

    # Test with auto-generated keys
    provider = DefaultCryptoProvider()

    # Get JWKS
    jwks = provider.get_jwks()

    # Should have keys array
    assert "keys" in jwks
    keys = jwks["keys"]

    # Should have exactly 2 keys (one for signing, one for encryption)
    assert len(keys) == 2

    # Find signing and encryption keys
    signing_key = None
    encryption_key = None

    for key in keys:
        if key.get("use") == "sig":
            signing_key = key
        elif key.get("use") == "enc":
            encryption_key = key

    # Both keys should exist
    assert signing_key is not None, "Missing signing key"
    assert encryption_key is not None, "Missing encryption key"

    # Verify signing key properties
    assert signing_key["kid"] == provider.signature_key_id
    assert signing_key["alg"] == "EdDSA"
    assert signing_key["kty"] == "OKP"
    assert signing_key["crv"] == "Ed25519"

    # Verify encryption key properties
    assert encryption_key["kid"] == provider.encryption_key_id
    assert encryption_key["alg"] == "ECDH-ES"
    assert encryption_key["kty"] == "OKP"
    assert encryption_key["crv"] == "X25519"

    print("✓ JWKS generation test passed")


def test_jwks_with_provided_keys():
    """Test JWKS generation with user-provided keys."""

    # Generate test keys first
    from naylence.fame.security.crypto.key_factories.ed25519_key_factory import create_ed25519_keypair
    from naylence.fame.security.crypto.key_factories.x25519_key_factory import create_x25519_keypair

    sig_keypair = create_ed25519_keypair("test-sig")
    enc_keypair = create_x25519_keypair("test-enc")

    # Create provider with provided keys
    provider = DefaultCryptoProvider(
        signature_private_pem=sig_keypair.private_pem,
        signature_public_pem=sig_keypair.public_pem,
        signature_key_id="test-sig",
        encryption_private_pem=enc_keypair.private_pem,
        encryption_public_pem=enc_keypair.public_pem,
        encryption_key_id="test-enc",
    )

    # Get JWKS
    jwks = provider.get_jwks()

    # Should have keys array
    assert "keys" in jwks
    keys = jwks["keys"]

    # Should have exactly 2 keys
    assert len(keys) == 2

    # Find signing and encryption keys
    signing_key = None
    encryption_key = None

    for key in keys:
        if key.get("use") == "sig":
            signing_key = key
        elif key.get("use") == "enc":
            encryption_key = key

    # Both keys should exist
    assert signing_key is not None, "Missing signing key"
    assert encryption_key is not None, "Missing encryption key"

    # Verify key IDs match what we provided
    assert signing_key["kid"] == "test-sig"
    assert encryption_key["kid"] == "test-enc"

    print("✓ JWKS with provided keys test passed")


if __name__ == "__main__":
    test_jwks_generation()
    test_jwks_with_provided_keys()
    print("✓ All DefaultCryptoProvider JWKS tests passed!")

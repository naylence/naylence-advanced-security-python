#!/usr/bin/env python3
"""
Test script to verify crypto provider certificate functionality.
"""

from naylence.fame.security.cert.internal_ca_service import create_test_ca
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
from tests.test_ca_helpers import TestCryptoProviderHelper


def test_certificate_functionality():
    """Test that crypto provider can generate certificates and x5c JWKs."""

    # Get crypto provider instance and set it up with CA
    provider = get_crypto_provider()
    ca_cert_pem, ca_key_pem = create_test_ca()

    # Configure the provider with CA credentials
    setattr(provider, "_test_ca_cert_pem", ca_cert_pem)
    setattr(provider, "_test_ca_key_pem", ca_key_pem)

    print("Testing DefaultCryptoProvider certificate functionality...")

    # Set node context to trigger certificate generation
    provider.set_node_context(
        node_id="test-crypto-node",
        physical_path="/test/crypto-path",
        logicals=["crypto-logical.test"],
    )

    # Generate certificate using helper
    TestCryptoProviderHelper.ensure_test_certificate(provider)

    # Test 1: Check if certificate is generated
    cert_pem = provider.node_certificate_pem()
    if cert_pem:
        print("✓ Node certificate generated successfully")
        print(f"Certificate preview: {cert_pem[:100]}...")
    else:
        print("✗ No certificate generated")
        assert False, "No certificate generated"

    # Test 2: Check if node JWK includes x5c
    node_jwk = provider.node_jwk()
    if node_jwk:
        print("✓ Node JWK generated successfully")
        print(f"JWK keys: {list(node_jwk.keys())}")

        if "x5c" in node_jwk:
            print("✓ x5c certificate chain included in JWK")
            print(f"Certificate chain length: {len(node_jwk['x5c'])}")
        else:
            print("✗ No x5c in JWK")
            assert False, "No x5c in JWK"
    else:
        print("✗ No node JWK generated")
        assert False, "No node JWK generated"

    # Test 3: Compare with regular JWKS
    regular_jwks = provider.get_jwks()
    print(f"Regular JWKS has {len(regular_jwks['keys'])} keys")
    print(f"Node JWK type: {node_jwk.get('kty')}, use: {node_jwk.get('use')}")

    # Test 4: Verify certificate can be parsed
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        print("✓ Certificate parsed successfully")
        print(f"Certificate subject: {cert.subject}")
        print(f"Certificate issuer: {cert.issuer}")

        # Check for SAN extension
        from cryptography.x509.oid import ExtensionOID

        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_uris = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
            print(f"✓ SAN URIs found: {san_uris}")
        except Exception as e:
            print(f"SAN extension check: {e}")

    except Exception as e:
        print(f"✗ Certificate parsing failed: {e}")
        assert False, f"Certificate parsing failed: {e}"

    print("\n✓ All certificate functionality tests passed!")


if __name__ == "__main__":
    success = test_certificate_functionality()
    exit(0 if success else 1)

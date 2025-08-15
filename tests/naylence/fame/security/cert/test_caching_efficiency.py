#!/usr/bin/env python3
"""Test certificate chain validation caching efficiency."""

import os
import tempfile

from naylence.fame.security.cert.util import public_key_from_x5c
from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider


def test_caching_efficiency():
    """Test that trust anchor validation is cached properly."""
    print("=== Testing Certificate Validation Caching ===\n")

    # Set up environment with CA
    from naylence.fame.security.cert.ca_service import create_test_ca

    ca_cert_pem, ca_key_pem = create_test_ca()

    with (
        tempfile.NamedTemporaryFile(mode="w", suffix="_ca_cert.pem", delete=False) as ca_cert_file,
        tempfile.NamedTemporaryFile(mode="w", suffix="_ca_key.pem", delete=False) as ca_key_file,
    ):
        ca_cert_file.write(ca_cert_pem)
        ca_key_file.write(ca_key_pem)
        ca_cert_file.flush()
        ca_key_file.flush()

        try:
            # Set environment variables
            os.environ["FAME_CA_CERT_FILE"] = ca_cert_file.name
            os.environ["FAME_CA_KEY_FILE"] = ca_key_file.name

            # Create crypto provider and generate a certificate
            provider = DefaultCryptoProvider()
            provider.set_node_context(
                node_id="cache-test-node",
                physical_path="/cache/test/path",
                logicals=["service.test.cache"],
            )

            # Get the node JWK with certificate
            jwk = provider.node_jwk()
            x5c = jwk.get("x5c", [])

            if not x5c:
                print("❌ No x5c found in JWK")
                return

            print(f"✓ Got certificate chain with {len(x5c)} certificates")
            print(
                f"✓ Trust store contains "
                f"{len(ca_cert_pem.split('-----BEGIN CERTIFICATE-----')) - 1} certificates"
            )

            # Test multiple validations with the same x5c and trust store
            print("\n🧪 Testing caching efficiency...")

            validation_count = 5
            for i in range(validation_count):
                print(f"  Validation {i + 1}/{validation_count}...")
                try:
                    # Use the same parameters for all validations to test caching
                    public_key = public_key_from_x5c(
                        x5c,
                        enforce_name_constraints=True,  # Use consistent parameters
                        trust_store_pem=ca_cert_pem,
                    )
                    print(f"    ✓ Public key extracted (type: {type(public_key).__name__})")
                except Exception as e:
                    print(f"    ❌ Validation failed: {e}")

            # Test with different trust store content (should not use cache)
            print("\n🧪 Testing with different trust store (should bypass cache)...")
            different_ca_cert, _ = create_test_ca()

            try:
                public_key = public_key_from_x5c(
                    x5c,
                    enforce_name_constraints=True,  # Use consistent parameters
                    trust_store_pem=different_ca_cert,
                )
                print("    ❌ Unexpected success with different CA")
            except Exception as e:
                print(f"    ✓ Correctly failed with different CA: {e}")

            # Test return_cert=True (should not use cache)
            print("\n🧪 Testing with return_cert=True (should bypass cache)...")
            try:
                public_key, cert = public_key_from_x5c(
                    x5c,
                    enforce_name_constraints=True,  # Use consistent parameters
                    trust_store_pem=ca_cert_pem,
                    return_cert=True,
                )
                print("    ✓ Public key and certificate extracted")
                print(f"      - Public key type: {type(public_key).__name__}")
                print(f"      - Certificate type: {type(cert).__name__}")
            except Exception as e:
                print(f"    ❌ return_cert validation failed: {e}")

        finally:
            # Clean up
            if "FAME_CA_CERT_FILE" in os.environ:
                del os.environ["FAME_CA_CERT_FILE"]
            if "FAME_CA_KEY_FILE" in os.environ:
                del os.environ["FAME_CA_KEY_FILE"]

            os.unlink(ca_cert_file.name)
            os.unlink(ca_key_file.name)

    print("\n=== Caching Test Complete ===")
    print("\n💡 Look for 'trust_anchor_validation_start' debug logs:")
    print("   - Should appear once for the first validation")
    print("   - Should be absent for subsequent identical validations (cached)")
    print("   - Should appear again when trust store content changes")


if __name__ == "__main__":
    test_caching_efficiency()

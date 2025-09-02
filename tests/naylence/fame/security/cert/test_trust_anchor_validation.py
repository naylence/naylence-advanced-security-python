#!/usr/bin/env python3
"""Test trust anchor validation with different scenarios."""

import os
import tempfile

from naylence.fame.security.cert.util import _validate_chain
from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider


def test_trust_anchor_validation():
    """Test trust anchor validation with matching and non-matching CAs."""
    print("=== Testing Trust Anchor Validation ===\n")

    # Import after the function definition to avoid circular imports
    from naylence.fame.security.cert.internal_ca_service import create_test_ca

    # Create a real test CA
    ca_cert_pem, ca_key_pem = create_test_ca()

    # Create temporary files for CA cert and key
    with (
        tempfile.NamedTemporaryFile(mode="w", suffix="_ca_cert.pem", delete=False) as ca_cert_file,
        tempfile.NamedTemporaryFile(mode="w", suffix="_ca_key.pem", delete=False) as ca_key_file,
    ):
        # Write the real test CA certificate and key
        ca_cert_file.write(ca_cert_pem)
        ca_key_file.write(ca_key_pem)

        ca_cert_file.flush()
        ca_key_file.flush()

        # Test 1: Valid trust anchor validation
        print("1. Testing valid trust anchor validation...")
        try:
            # Set environment variables
            os.environ["FAME_CA_CERT_FILE"] = ca_cert_file.name
            os.environ["FAME_CA_KEY_FILE"] = ca_key_file.name

            # Create crypto provider and set node context
            provider = DefaultCryptoProvider()
            provider.set_node_context(
                node_id="test-trust-node",
                physical_path="/test/trust/path",
                logicals=["service.trust.test"],
            )

            # Get the node JWK which will include the certificate in x5c
            jwk = provider.node_jwk()
            if "x5c" not in jwk:
                print("   ⚠️  No x5c in JWK, skipping certificate validation test")
                return

            x5c = jwk["x5c"]
            print(f"   ✓ Got certificate chain with {len(x5c)} certificates")

            # Create a trust store with our CA
            with open(ca_cert_file.name) as ca_file:
                trust_store_content = ca_file.read()

            # Validate the certificate chain against the trust store
            _validate_chain(x5c, enforce_name_constraints=False, trust_store_pem=trust_store_content)
            print("   ✓ Certificate chain validation passed")

        except Exception as e:
            print(f"   ❌ Valid trust anchor test failed: {e}")
            import traceback

            traceback.print_exc()

        # Test 2: Invalid trust anchor validation
        print("\n2. Testing invalid trust anchor validation...")
        try:
            if "x5c" in locals():
                # Create a different CA certificate for the trust store (valid format)
                different_ca_content = """-----BEGIN CERTIFICATE-----
MIIB1zCCAYOgAwIBAgIUXXX9999999999999999999999999XwBQYDK2VwMDQxGjAY
BgNVBAMMEUZhbWUgVGVzdCBSb290IENBMRAwDgYDVQQKDAdOYXlsZW5jZTAgFw0y
NTA3MDMyMTUzMzRaGA8yMDQ1MDcwMzIxNTMzNFowNDEaMBgGA1UEAwwRRmFtZSBU
ZXN0IFJvb3QgQ0ExEDAOBgNVBAoMB05heWxlbmNlMCowBQYDK2VwAyEADifferent
VQHEFsSkP9wNUr7CvBKK97rMKhQrKkdNMwajUzBRMB0GA1UdDgQWBBT3+dqjJHNS
eKLCUnQLKnquwHn3BTAfBgNVHSMEGDAWgBT3+dqjJHNSeKLCUnQLKnquwHn3BTAP
BgNVHRMBAf8EBTADAQH/MAUGAytlcANBAGLAVvzSlEpqJfmvfLQVgBV+E/zzb/Vn
dDzIZD5Fx8vNgm68i+gGOr6Ni3BBXL+7iP3SbJ4ZZdpCjjqhmnz1LQU=
-----END CERTIFICATE-----"""

                # This should fail because the certificate was issued by our CA, not the different CA
                _validate_chain(x5c, enforce_name_constraints=False, trust_store_pem=different_ca_content)
                print("   ❌ Expected validation failure, but it passed!")
            else:
                print("   ⚠️  No certificate chain available for testing")

        except ValueError as e:
            if "not rooted in a trusted anchor" in str(e):
                print("   ✓ Certificate chain validation correctly failed")
            elif "No valid certificates found in trust store" in str(e):
                print("   ✓ Invalid certificate in trust store correctly detected")
            else:
                print(f"   ⚠️  Unexpected validation failure: {e}")
        except Exception as e:
            print(f"   ❌ Unexpected error: {e}")

        # Test 3: Empty trust store
        print("\n3. Testing empty trust store...")
        try:
            if "x5c" in locals():
                _validate_chain(
                    x5c, enforce_name_constraints=False, trust_store_pem="# Empty trust store\n"
                )
                print("   ❌ Expected validation failure, but it passed!")
            else:
                print("   ⚠️  No certificate chain available for testing")

        except ValueError as e:
            if "No valid certificates found in trust store" in str(e):
                print("   ✓ Empty trust store correctly detected")
            else:
                print(f"   ⚠️  Unexpected validation failure: {e}")
        except Exception as e:
            print(f"   ❌ Unexpected error: {e}")

        # Clean up environment variables
        if "FAME_CA_CERT_FILE" in os.environ:
            del os.environ["FAME_CA_CERT_FILE"]
        if "FAME_CA_KEY_FILE" in os.environ:
            del os.environ["FAME_CA_KEY_FILE"]

        # Clean up temporary files
        os.unlink(ca_cert_file.name)
        os.unlink(ca_key_file.name)

    print("\n=== Trust Anchor Validation Test Complete ===")


if __name__ == "__main__":
    test_trust_anchor_validation()

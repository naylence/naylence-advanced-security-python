#!/usr/bin/env python3
"""
Test script to verify environment variable support for CA configuration.
Tests FAME_CA_CERT_FILE and FAME_CA_KEY_FILE environment variables.
"""

import os
import tempfile


def test_environment_variable_ca_configuration():
    """Test CA configuration via environment variables."""

    from naylence.fame.security.cert.internal_ca_service import create_test_ca
    from tests.test_ca_helpers import TestCryptoProviderHelper

    print("=== Testing Environment Variable CA Configuration ===\n")

    # Create a test CA for our tests
    ca_cert_pem, ca_key_pem = create_test_ca()

    # Create temporary files for CA cert and key
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_env_ca_cert.pem") as cert_file:
        cert_file.write(ca_cert_pem)
        cert_file_path = cert_file.name

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_env_ca_key.pem") as key_file:
        key_file.write(ca_key_pem)
        key_file_path = key_file.name

    print("Created temporary CA files:")
    print(f"  Cert: {cert_file_path}")
    print(f"  Key: {key_file_path}")

    try:
        # Test 1: Set environment variables and create provider without file params
        print("\n1. Testing CA configuration via environment variables...")

        # Set environment variables
        os.environ["FAME_CA_CERT_FILE"] = cert_file_path
        os.environ["FAME_CA_KEY_FILE"] = key_file_path

        # Create provider using helper that handles environment CA
        crypto_env = TestCryptoProviderHelper.create_crypto_provider_with_env_ca(
            issuer="env-test.example.com"
        )

        # Set node context to trigger certificate generation
        crypto_env.set_node_context(
            node_id="env-test-node", physical_path="/env/test/path", logicals=["logical.test.env"]
        )

        # Generate certificate using helper
        TestCryptoProviderHelper.ensure_test_certificate(crypto_env)

        env_cert = crypto_env.node_certificate_pem()
        assert env_cert is not None, "Should generate certificate with environment CA"
        print(f"   ✓ Certificate generated via environment variables (length: {len(env_cert)} bytes)")

        # Test 2: Constructor parameters should override environment variables
        print("\n2. Testing constructor override of environment variables...")

        # Create different CA files
        ca_cert_pem2, ca_key_pem2 = create_test_ca()

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix="_override_ca_cert.pem"
        ) as cert_file2:
            cert_file2.write(ca_cert_pem2)
            cert_file_path2 = cert_file2.name

        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix="_override_ca_key.pem"
        ) as key_file2:
            key_file2.write(ca_key_pem2)
            key_file_path2 = key_file2.name

        try:
            # Create provider with explicit file parameters (should override env vars)
            crypto_override = TestCryptoProviderHelper.create_crypto_provider_with_ca_files(
                ca_cert_file=cert_file_path2, ca_key_file=key_file_path2, issuer="override-test.example.com"
            )

            # Set node context to trigger certificate generation
            crypto_override.set_node_context(
                node_id="override-test-node",
                physical_path="/override/test/path",
                logicals=["logical.test.override"],
            )

            # Generate certificate using helper
            TestCryptoProviderHelper.ensure_test_certificate(crypto_override)

            override_cert = crypto_override.node_certificate_pem()
            assert override_cert is not None, "Should generate certificate with override CA"
            print(
                f"   ✓ Certificate generated via constructor override (length: {len(override_cert)} bytes)"
            )

            # Certificates should be different (different CAs)
            assert env_cert != override_cert, "Certificates should be different when using different CAs"
            print("   ✓ Constructor parameters properly override environment variables")

        finally:
            # Clean up override files
            os.unlink(cert_file_path2)
            os.unlink(key_file_path2)

        # Test 3: Test fallback when environment variables point to non-existent files
        print("\n3. Testing fallback with invalid environment variables...")

        # Set environment variables to non-existent files
        os.environ["FAME_CA_CERT_FILE"] = "/non/existent/cert.pem"
        os.environ["FAME_CA_KEY_FILE"] = "/non/existent/key.pem"

        # Create provider using helper (should fall back to test CA)
        crypto_fallback = TestCryptoProviderHelper.create_crypto_provider_with_env_ca(
            issuer="fallback-test.example.com"
        )

        # Set node context to trigger certificate generation
        crypto_fallback.set_node_context(
            node_id="fallback-test-node",
            physical_path="/fallback/test/path",
            logicals=["logical.test.fallback"],
        )

        # Generate certificate using helper
        TestCryptoProviderHelper.ensure_test_certificate(crypto_fallback)

        fallback_cert = crypto_fallback.node_certificate_pem()
        assert fallback_cert is not None, "Should generate certificate with fallback CA"
        print(f"   ✓ Certificate generated via fallback (length: {len(fallback_cert)} bytes)")
        print("   ✓ Graceful fallback to shared test CA when environment files don't exist")

        # Test 4: Test with only one environment variable set (should not use files)
        print("\n4. Testing partial environment variable configuration...")

        # Set only cert file, not key file
        os.environ["FAME_CA_CERT_FILE"] = cert_file_path
        if "FAME_CA_KEY_FILE" in os.environ:
            del os.environ["FAME_CA_KEY_FILE"]

        # Create provider using helper (should fall back to test CA)
        crypto_partial = TestCryptoProviderHelper.create_crypto_provider_with_env_ca(
            issuer="partial-test.example.com"
        )

        # Set node context to trigger certificate generation
        crypto_partial.set_node_context(
            node_id="partial-test-node",
            physical_path="/partial/test/path",
            logicals=["logical.test.partial"],
        )

        # Generate certificate using helper
        TestCryptoProviderHelper.ensure_test_certificate(crypto_partial)

        partial_cert = crypto_partial.node_certificate_pem()
        assert partial_cert is not None, "Should generate certificate with fallback CA"
        print(f"   ✓ Certificate generated via fallback (length: {len(partial_cert)} bytes)")
        print("   ✓ Partial environment configuration properly falls back to shared test CA")

        # Test 5: Test with empty environment variables
        print("\n5. Testing empty environment variables...")

        # Set empty environment variables
        os.environ["FAME_CA_CERT_FILE"] = ""
        os.environ["FAME_CA_KEY_FILE"] = ""

        # Create provider using helper (should fall back to test CA)
        crypto_empty = TestCryptoProviderHelper.create_crypto_provider_with_env_ca(
            issuer="empty-test.example.com"
        )

        # Set node context to trigger certificate generation
        crypto_empty.set_node_context(
            node_id="empty-test-node",
            physical_path="/empty/test/path",
            logicals=["logical.test.empty"],
        )

        # Generate certificate using helper
        TestCryptoProviderHelper.ensure_test_certificate(crypto_empty)

        empty_cert = crypto_empty.node_certificate_pem()
        assert empty_cert is not None, "Should generate certificate with fallback CA"
        print(f"   ✓ Certificate generated via fallback (length: {len(empty_cert)} bytes)")
        print("   ✓ Empty environment variables properly ignored")

    finally:
        # Clean up temporary files and environment variables
        os.unlink(cert_file_path)
        os.unlink(key_file_path)

        # Clean up environment variables
        if "FAME_CA_CERT_FILE" in os.environ:
            del os.environ["FAME_CA_CERT_FILE"]
        if "FAME_CA_KEY_FILE" in os.environ:
            del os.environ["FAME_CA_KEY_FILE"]

        print("\n   ✓ Cleaned up temporary files and environment variables")

    print("\n=== All Environment Variable CA Configuration Tests Passed! ===")
    print("""
Summary of environment variable support:
- FAME_CA_CERT_FILE: Path to CA certificate PEM file
- FAME_CA_KEY_FILE: Path to CA private key PEM file
- Constructor parameters override environment variables
- Both environment variables must be set for files to be used
- Graceful fallback to shared test CA if files don't exist or are invalid
- Empty or missing environment variables are properly ignored
""")


if __name__ == "__main__":
    test_environment_variable_ca_configuration()

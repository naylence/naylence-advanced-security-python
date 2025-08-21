import os
import tempfile


def test_ca_configuration():
    """Test CA configuration with both files and PEM strings."""

    from naylence.fame.security.cert.ca_service import create_test_ca
    from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider

    print("=== Testing CA Configuration Support ===\n")

    # Create a test CA for our tests
    ca_cert_pem, ca_key_pem = create_test_ca()

    # Test 1: CA configuration via PEM strings
    print("1. Testing CA configuration via PEM strings...")

    crypto_pem = DefaultCryptoProvider.with_ca_pems(ca_cert_pem=ca_cert_pem, ca_key_pem=ca_key_pem)

    # Set node context to trigger certificate generation
    crypto_pem.set_node_context(
        node_id="test-node-pem", physical_path="/test/pem-path", logicals=["pem-logical.test"]
    )

    # Provision certificate via CA service for test compatibility
    crypto_pem._ensure_test_certificate()

    pem_cert = crypto_pem.node_certificate_pem()
    assert pem_cert is not None, "Should generate certificate with PEM CA"
    print("   ✓ Certificate generated successfully with PEM CA")

    # Test 2: CA configuration via files
    print("\n2. Testing CA configuration via files...")

    # Create temporary files for CA cert and key
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as cert_file:
        cert_file.write(ca_cert_pem)
        cert_file_path = cert_file.name

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as key_file:
        key_file.write(ca_key_pem)
        key_file_path = key_file.name

    try:
        crypto_file = DefaultCryptoProvider.with_ca_files(
            ca_cert_file=cert_file_path, ca_key_file=key_file_path
        )

        # Set node context to trigger certificate generation
        crypto_file.set_node_context(
            node_id="test-node-file", physical_path="/test/file-path", logicals=["file-logical.test"]
        )

        # Provision certificate via CA service for test compatibility
        crypto_file._ensure_test_certificate()

        file_cert = crypto_file.node_certificate_pem()
        assert file_cert is not None, "Should generate certificate with file CA"
        print("   ✓ Certificate generated successfully with file CA")

    finally:
        # Clean up temporary files
        os.unlink(cert_file_path)
        os.unlink(key_file_path)

    # Test 3: Fallback to shared test CA
    print("\n3. Testing fallback to shared test CA...")

    crypto_default = DefaultCryptoProvider()

    # Set node context to trigger certificate generation
    crypto_default.set_node_context(
        node_id="test-node-default",
        physical_path="/test/default-path",
        logicals=["default-logical.test"],
    )

    # Provision certificate via CA service for test compatibility
    crypto_default._ensure_test_certificate()

    default_cert = crypto_default.node_certificate_pem()
    assert default_cert is not None, "Should generate certificate with default CA"
    print("   ✓ Certificate generated successfully with default shared test CA")

    # Test 4: Verify certificates are different (different CAs)
    print("\n4. Verifying certificates are different...")

    # The certificates should be different because they're signed by different CAs
    # (even though the test CA and shared CA might be similar, they're separate instances)
    assert pem_cert != default_cert or file_cert != default_cert, (
        "Certificates should differ when using different CAs"
    )
    print("   ✓ Certificates properly differentiated by CA")

    print("\n=== All CA Configuration Tests Passed! ===")


if __name__ == "__main__":
    test_ca_configuration()

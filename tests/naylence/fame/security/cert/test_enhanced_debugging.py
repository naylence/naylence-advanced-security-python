#!/usr/bin/env python3
"""
Test enhanced debugging information for CA and certificate operations.
"""

import logging
import os
import tempfile

# Enable debug logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")


def test_enhanced_debugging():
    """Test the enhanced debugging features."""

    from naylence.fame.security.cert.ca_service import create_test_ca
    from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider

    print("=== Testing Enhanced Certificate Debugging ===\n")

    # Create a test CA
    ca_cert_pem, ca_key_pem = create_test_ca()

    # Create temporary files
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_debug_ca_cert.pem") as cert_file:
        cert_file.write(ca_cert_pem)
        cert_file_path = cert_file.name

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_debug_ca_key.pem") as key_file:
        key_file.write(ca_key_pem)
        key_file_path = key_file.name

    try:
        print("1. Creating crypto provider with environment variables...")

        # Set environment variables
        os.environ["FAME_CA_CERT_FILE"] = cert_file_path
        os.environ["FAME_CA_KEY_FILE"] = key_file_path

        # Create provider - this should show CA debug info
        crypto = DefaultCryptoProvider(issuer="debug-test.example.com", algorithm="EdDSA")

        print("\n2. Setting node context to generate certificate...")

        # Set node context - this should show detailed certificate info
        crypto.set_node_context(
            node_id="debug-test-node",
            physical_path="/debug/test/node",
            logicals=["service.test.debug", "api.test.debug"],
        )

        # Provision certificate via CA service for test compatibility
        crypto._ensure_test_certificate()

        cert = crypto.node_certificate_pem()
        print(f"\n3. Certificate generated successfully (length: {len(cert)} bytes)")

        print("\n4. Testing certificate validation with enhanced debugging...")

        # Now test the certificate validation debugging
        import base64

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from naylence.fame.security.cert.util import public_key_from_x5c

        # Convert certificate to x5c format
        cert_obj = x509.load_pem_x509_certificate(cert.encode())
        cert_der = cert_obj.public_bytes(serialization.Encoding.DER)
        x5c = [base64.b64encode(cert_der).decode()]

        # Create a trust store with the CA certificate
        trust_store_path = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_trust_store.pem")
        trust_store_path.write(ca_cert_pem)
        trust_store_path.close()

        try:
            # This should show detailed trust validation debugging
            public_key_from_x5c(x5c, trust_store_pem=trust_store_path.name, enforce_name_constraints=False)
            print("✓ Certificate validation passed with enhanced debugging")
        except Exception as e:
            print(f"Certificate validation failed: {e}")
        finally:
            os.unlink(trust_store_path.name)

    finally:
        # Clean up
        os.unlink(cert_file_path)
        os.unlink(key_file_path)

        # Clean up environment variables
        if "FAME_CA_CERT_FILE" in os.environ:
            del os.environ["FAME_CA_CERT_FILE"]
        if "FAME_CA_KEY_FILE" in os.environ:
            del os.environ["FAME_CA_KEY_FILE"]

    print("\n=== Enhanced Debugging Test Complete ===")


if __name__ == "__main__":
    test_enhanced_debugging()

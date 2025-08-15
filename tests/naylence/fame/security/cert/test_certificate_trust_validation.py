#!/usr/bin/env python3
"""
Test certificate trust validation at node startup.

This test demonstrates that nodes will fail to start if their certificate
is not rooted in a trusted CA specified by FAME_CA_CERTS.
"""

import asyncio
import os
import tempfile

import pytest

try:
    import sys

    from naylence.fame.core import SecuritySettings, SigningMaterial
    from naylence.fame.security.cert.ca_service import create_test_ca
    from naylence.fame.security.cert.default_certificate_manager import DefaultCertificateManager
    from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider

    print("✓ Fame imports successful")
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)


def test_certificate_trust_validation():
    """Test certificate validation against trusted CA certs."""
    print("=== Testing Certificate Trust Validation ===\n")

    # Create a certificate manager for testing validation functions
    security_settings = SecuritySettings(signing_material=SigningMaterial.X509_CHAIN)
    cert_manager = DefaultCertificateManager(security_settings)

    # Create two different CA certificates
    print("1. Creating test CA certificates...")
    trusted_ca_cert, trusted_ca_key = create_test_ca()
    different_ca_cert, different_ca_key = create_test_ca()

    print("   ✓ Created trusted CA")
    print("   ✓ Created different CA (not trusted)")

    # Set up environment with trusted CA
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as trust_file:
        trust_file.write(trusted_ca_cert)
        trust_file.flush()
        trusted_ca_path = trust_file.name

    try:
        # Test 1: Valid certificate (issued by trusted CA)
        print("\n2. Testing valid certificate scenario...")

        # Create a temporary file for the trusted CA cert
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as trusted_cert_file:
            trusted_cert_file.write(trusted_ca_cert)
            trusted_cert_file.flush()
            trusted_cert_path = trusted_cert_file.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as trusted_key_file:
            trusted_key_file.write(trusted_ca_key)
            trusted_key_file.flush()
            trusted_key_path = trusted_key_file.name

        # Debug: Print CA certificate details
        try:
            from cryptography import x509

            ca_cert = x509.load_pem_x509_certificate(trusted_ca_cert.encode())
            print(f"   CA cert subject: {ca_cert.subject}")
            print(f"   CA cert serial: {ca_cert.serial_number}")
        except Exception as e:
            print(f"   CA cert parse error: {e}")

        # Set environment to use the trusted CA for both signing and trust validation
        os.environ["FAME_CA_CERT_FILE"] = trusted_cert_path
        os.environ["FAME_CA_KEY_FILE"] = trusted_key_path
        os.environ["FAME_CA_CERTS"] = trusted_cert_path  # Trust store

        # Create crypto provider and generate certificate with trusted CA
        provider = DefaultCryptoProvider()
        provider.set_node_context(
            node_id="test-valid-node", physical_path="/test/valid/path", logicals=["service.valid.test"]
        )

        # Generate certificate using trusted CA (via CA service, not test method)
        # We'll use the CA service directly to ensure we use the same CA
        try:
            from naylence.fame.security.cert.ca_service import CASigningService
            from naylence.fame.util.util import secure_digest

            physical_path = "/test/valid/path"
            computed_sid = secure_digest(physical_path)

            ca_service = CASigningService(trusted_ca_cert, trusted_ca_key)
            cert_pem = ca_service.sign_node_cert(
                public_key_pem=provider._signature_public_pem,
                node_id="test-valid-node",
                node_sid=computed_sid,
                physical_path=physical_path,
                logicals=["service.valid.test"],
            )

            # Store the certificate manually
            provider.store_signed_certificate(cert_pem)
            print("   ✓ Certificate generated using trusted CA")

        except Exception as e:
            print(f"   ❌ Failed to generate certificate: {e}")
            pytest.fail(f"Failed to generate certificate with trusted CA: {e}")

        # Debug: Check the generated certificate
        node_cert_pem = provider.node_certificate_pem()
        if node_cert_pem:
            try:
                node_cert = x509.load_pem_x509_certificate(node_cert_pem.encode())
                print(f"   Node cert subject: {node_cert.subject}")
                print(f"   Node cert issuer: {node_cert.issuer}")
                print(f"   Node cert serial: {node_cert.serial_number}")
            except Exception as e:
                print(f"   Node cert parse error: {e}")

        # Validate the certificate
        is_valid = cert_manager._validate_certificate_against_trust_anchors(provider, "test-valid-node")
        print(f"   Valid certificate validation result: {'✅ PASS' if is_valid else '❌ FAIL'}")
        assert is_valid, "Certificate issued by trusted CA should be valid"

        # Test 2: Invalid certificate (issued by different CA)
        print("\n3. Testing invalid certificate scenario...")

        # Create another provider with a different CA for signing
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as different_cert_file:
            different_cert_file.write(different_ca_cert)
            different_cert_file.flush()
            different_cert_path = different_cert_file.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as different_key_file:
            different_key_file.write(different_ca_key)
            different_key_file.flush()
            different_key_path = different_key_file.name

        # Set environment to use different CA for signing but keep trusted CA for validation
        os.environ["FAME_CA_CERT_FILE"] = different_cert_path
        os.environ["FAME_CA_KEY_FILE"] = different_key_path
        # Keep FAME_CA_CERTS pointing to trusted CA

        provider2 = DefaultCryptoProvider()
        provider2.set_node_context(
            node_id="test-invalid-node",
            physical_path="/test/invalid/path",
            logicals=["service.invalid.test"],
        )

        # Generate certificate using different CA
        try:
            from naylence.fame.security.cert.ca_service import CASigningService
            from naylence.fame.util.util import secure_digest

            physical_path = "/test/invalid/path"
            computed_sid = secure_digest(physical_path)

            ca_service2 = CASigningService(different_ca_cert, different_ca_key)
            cert_pem2 = ca_service2.sign_node_cert(
                public_key_pem=provider2._signature_public_pem,
                node_id="test-invalid-node",
                node_sid=computed_sid,
                physical_path=physical_path,
                logicals=["service.invalid.test"],
            )

            # Store the certificate manually
            provider2.store_signed_certificate(cert_pem2)
            print("   ✓ Certificate generated using different CA")

        except Exception as e:
            print(f"   ❌ Failed to generate certificate: {e}")
            pytest.fail(f"Failed to generate certificate with different CA: {e}")

        # Validate against trusted CA (should fail)
        is_valid = cert_manager._validate_certificate_against_trust_anchors(provider2, "test-invalid-node")
        print(
            f"   Invalid certificate validation result: {'✅ REJECTED' if not is_valid else '❌ ACCEPTED'}"
        )
        assert not is_valid, "Certificate issued by different CA should be rejected"

        # Test 3: Missing trust store
        print("\n4. Testing missing trust store scenario...")
        if "FAME_CA_CERTS" in os.environ:
            del os.environ["FAME_CA_CERTS"]

        is_valid = cert_manager._validate_certificate_against_trust_anchors(provider, "test-no-trust-store")
        print(
            f"   Missing trust store validation result: {'✅ REJECTED' if not is_valid else '❌ ACCEPTED'}"
        )
        assert not is_valid, "Validation should fail when FAME_CA_CERTS is not set"

        print("\n✅ All certificate trust validation tests passed!")

    finally:
        # Clean up
        try:
            os.unlink(trusted_ca_path)
            # Clean up other temp files that might have been created
            for env_var in ["FAME_CA_CERT_FILE", "FAME_CA_KEY_FILE"]:
                if env_var in os.environ and os.path.exists(os.environ[env_var]):
                    try:
                        os.unlink(os.environ[env_var])
                    except OSError:
                        pass
        except OSError:
            pass

        # Clean up environment variables
        for var in ["FAME_CA_CERT_FILE", "FAME_CA_KEY_FILE", "FAME_CA_CERTS"]:
            if var in os.environ:
                del os.environ[var]


async def test_node_startup_with_invalid_certificate():
    """Test that ensure_node_certificate fails when certificate is not trusted."""
    print("\n=== Testing Node Startup Certificate Validation ===\n")

    # Create a certificate manager for testing validation functions
    security_settings = SecuritySettings(signing_material=SigningMaterial.X509_CHAIN)
    cert_manager = DefaultCertificateManager(security_settings)

    # Create trusted and untrusted CAs
    print("1. Setting up CA certificates...")
    trusted_ca_cert, trusted_ca_key = create_test_ca()
    untrusted_ca_cert, untrusted_ca_key = create_test_ca()

    with (
        tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as trusted_file,
        tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as untrusted_file,
    ):
        trusted_file.write(trusted_ca_cert)
        trusted_file.flush()
        untrusted_file.write(untrusted_ca_cert)
        untrusted_file.flush()

        trusted_ca_path = trusted_file.name
        untrusted_ca_path = untrusted_file.name

    try:
        # Scenario: Node already has certificate from untrusted CA, but trust store only has trusted CA
        print("\n2. Testing node with existing untrusted certificate...")

        # Generate certificate with untrusted CA
        os.environ["FAME_CA_CERT_FILE"] = untrusted_ca_path
        os.environ["FAME_CA_KEY_FILE"] = untrusted_ca_path

        provider = DefaultCryptoProvider()
        provider.set_node_context(
            node_id="test-untrusted-node",
            physical_path="/test/untrusted/path",
            logicals=["service.untrusted.test"],
        )
        # Generate certificate with untrusted CA
        try:
            from naylence.fame.security.cert.ca_service import CASigningService
            from naylence.fame.util.util import secure_digest

            physical_path = "/test/untrusted/path"
            computed_sid = secure_digest(physical_path)

            ca_service = CASigningService(untrusted_ca_cert, untrusted_ca_key)
            cert_pem = ca_service.sign_node_cert(
                public_key_pem=provider._signature_public_pem,
                node_id="test-untrusted-node",
                node_sid=computed_sid,
                physical_path=physical_path,
                logicals=["service.untrusted.test"],
            )

            # Store the certificate manually
            provider.store_signed_certificate(cert_pem)
            print("   ✓ Certificate generated using untrusted CA")

        except Exception as e:
            print(f"   ❌ Failed to generate certificate: {e}")
            pytest.fail(f"Failed to generate certificate with untrusted CA: {e}")

        # Set trust store to only trust the trusted CA
        os.environ["FAME_CA_CERTS"] = trusted_ca_path

        # Try to start node (should fail certificate validation)
        success = await cert_manager._ensure_node_certificate(
            crypto_provider=provider,
            node_id="test-untrusted-node",
            physical_path="/test/untrusted/path",
            logicals=["service.untrusted.test"],
        )

        print(
            f"   Node startup with untrusted certificate: "
            f"{'❌ FAILED (expected)' if not success else '✅ SUCCEEDED (unexpected)'}"
        )
        assert not success, "Node startup should fail when existing certificate is not trusted"

        print("\n✅ Node startup certificate validation test passed!")
        print("   ✓ Nodes with untrusted certificates correctly fail to start")

    finally:
        # Clean up
        try:
            os.unlink(trusted_ca_path)
            os.unlink(untrusted_ca_path)
        except OSError:
            pass

        # Clean up environment variables
        for var in ["FAME_CA_CERT_FILE", "FAME_CA_KEY_FILE", "FAME_CA_CERTS"]:
            if var in os.environ:
                del os.environ[var]


async def main():
    """Run all tests."""
    print("🛡️ Certificate Trust Validation Tests")
    print("=" * 50)

    try:
        # Test the validation function directly
        test1_success = test_certificate_trust_validation()

        # Test node startup behavior
        test2_success = await test_node_startup_with_invalid_certificate()

        if test1_success and test2_success:
            print("\n🎉 ALL TESTS PASSED!")
            print("\n📋 Summary:")
            print("   ✅ Certificate trust validation works correctly")
            print("   ✅ Valid certificates are accepted")
            print("   ✅ Invalid certificates are rejected")
            print("   ✅ Missing trust store is handled correctly")
            print("   ✅ Node startup fails with untrusted certificates")
            print("\n🔒 Security Guarantees:")
            print("   • Nodes will only start with certificates rooted in trusted CAs")
            print("   • FAME_CA_CERTS is the single source of truth for trust anchors")
            print("   • Certificate validation happens at node startup")
            print("   • Trust anchor mismatches are prevented at the source")
            return True
        else:
            print("\n❌ Some tests failed!")
            return False

    except Exception as e:
        print(f"\n❌ Test error: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)

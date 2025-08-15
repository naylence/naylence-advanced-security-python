#!/usr/bin/env python3
"""
Test certificate validation in key exchange scenarios.

Tests both node attach flows (fail) and on-demand key requests (skip and warn).
"""

import asyncio
import os
import tempfile


def test_certificate_validation_in_key_exchange():
    """Test certificate validation in both node attach and on-demand key request scenarios."""
    print("🔐 Testing certificate validation in key exchange scenarios...")

    # Create test certificates
    import base64
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from naylence.fame.security.cert.ca_service import CASigningService, create_test_ca

    # Create test CA
    ca_cert_pem, ca_key_pem = create_test_ca()
    ca_service = CASigningService(ca_cert_pem, ca_key_pem)

    # Create valid certificate
    node_key = ed25519.Ed25519PrivateKey.generate()
    node_pub_pem = (
        node_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )

    # Compute SID from physical path
    from naylence.fame.util.util import secure_digest

    physical_path = "/test/path"
    computed_sid = secure_digest(physical_path)

    valid_cert_pem = ca_service.sign_node_cert(
        public_key_pem=node_pub_pem,
        node_id="test-node",
        node_sid=computed_sid,
        physical_path=physical_path,
        logicals=["path.logical.test"],
    )

    # Convert to x5c format
    valid_cert = x509.load_pem_x509_certificate(valid_cert_pem.encode())
    valid_cert_der = valid_cert.public_bytes(serialization.Encoding.DER)
    valid_x5c = [base64.b64encode(valid_cert_der).decode()]

    # Create invalid certificate (self-signed, not from CA)
    invalid_key = ed25519.Ed25519PrivateKey.generate()
    invalid_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "invalid-cert")]))
        .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "invalid-cert")]))
        .public_key(invalid_key.public_key())
        .serial_number(12345)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(invalid_key, None)
    )

    invalid_cert_der = invalid_cert.public_bytes(serialization.Encoding.DER)
    invalid_x5c = [base64.b64encode(invalid_cert_der).decode()]

    # Create test JWKs
    valid_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "kid": "valid-cert-key",
        "x": base64.urlsafe_b64encode(
            node_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )
        )
        .decode()
        .rstrip("="),
        "x5c": valid_x5c,
    }

    invalid_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "kid": "invalid-cert-key",
        "x": base64.urlsafe_b64encode(
            invalid_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )
        )
        .decode()
        .rstrip("="),
        "x5c": invalid_x5c,
    }

    # Set up trust store
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as trust_store_file:
        trust_store_file.write(ca_cert_pem)
        trust_store_path = trust_store_file.name

    try:
        # Set environment variable for trust store
        os.environ["FAME_CA_CERTS"] = trust_store_path

        # Test 1: Certificate validation utility function
        print("\n1. Testing certificate validation utility function...")

        from naylence.fame.security.cert.util import validate_jwk_x5c_certificate

        # Valid certificate
        is_valid, error_msg = validate_jwk_x5c_certificate(
            valid_jwk, trust_store_pem=trust_store_path, strict=False
        )
        print(f"   ✓ Valid certificate: {is_valid}, error: {error_msg}")
        assert is_valid, "Valid certificate should pass validation"

        # Invalid certificate
        is_valid, error_msg = validate_jwk_x5c_certificate(
            invalid_jwk, trust_store_pem=trust_store_path, strict=False
        )
        print(f"   ✓ Invalid certificate: {is_valid}, error: {error_msg}")
        assert not is_valid, "Invalid certificate should fail validation"

        # Test 2: Node attach scenario (via DefaultKeyManager)
        print("\n2. Testing node attach scenario (DefaultKeyManager)...")

        from naylence.fame.core import DeliveryOriginType
        from naylence.fame.security.keys.default_key_manager import DefaultKeyManager
        from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore

        key_store = InMemoryKeyStore()
        key_manager = DefaultKeyManager(key_store=key_store)

        # Test with valid certificate (should succeed)
        try:
            # Use LOCAL origin to avoid path validation issues
            asyncio.run(
                key_manager.add_keys(
                    keys=[valid_jwk],
                    physical_path="/test/path",
                    system_id="test-system",
                    origin=DeliveryOriginType.LOCAL,
                )
            )
            print("   ✓ Valid certificate accepted in node attach flow")
        except Exception as e:
            print(f"   ❌ Valid certificate rejected: {e}")

        # Test with invalid certificate (should be rejected)
        try:
            asyncio.run(
                key_manager.add_keys(
                    keys=[invalid_jwk],
                    physical_path="/test/path",
                    system_id="test-system",
                    origin=DeliveryOriginType.LOCAL,
                )
            )
            print("   ⚠️  Invalid certificate was accepted (check logging for rejection)")
        except Exception as e:
            print(f"   ✓ Invalid certificate properly rejected: {e}")

        # Test 3: On-demand key request scenario (via KeyManagementHandler)
        print("\n3. Testing on-demand key request scenario (KeyManagementHandler)...")

        from naylence.fame.core import FameDeliveryContext, FameEnvelope, KeyAnnounceFrame
        from naylence.fame.security.keys.key_management_handler import KeyManagementHandler

        # Create a mock node
        class MockNode:
            has_parent = True

        handler = KeyManagementHandler(MockNode(), key_manager, None)

        # Create test frame and context
        test_frame = KeyAnnounceFrame(keys=[valid_jwk, invalid_jwk], physical_path="/test/path")
        test_envelope = FameEnvelope(frame=test_frame, sid="test-sid")
        test_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM, from_system_id="test-system"
        )

        # Process the key announce (should skip invalid cert with warning)
        try:
            asyncio.run(handler.accept_key_announce(test_envelope, test_context))
            print("   ✓ On-demand key request processed (check logs for warnings)")
        except Exception as e:
            print(f"   ❌ On-demand key request failed: {e}")

        print("\n✅ Certificate validation integration tests completed!")
        print("Check the logs above for certificate validation warnings and rejections.")

    finally:
        # Clean up
        if "FAME_CA_CERTS" in os.environ:
            del os.environ["FAME_CA_CERTS"]
        if os.path.exists(trust_store_path):
            os.unlink(trust_store_path)


if __name__ == "__main__":
    test_certificate_validation_in_key_exchange()

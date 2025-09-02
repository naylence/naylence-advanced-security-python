"""Test utilities for security testing."""

import pytest


def crypto_available():
    """Check if cryptography package is available."""
    try:
        import importlib.util

        return importlib.util.find_spec("cryptography") is not None
    except ImportError:
        return False


def requires_crypto(reason="Requires cryptography package"):
    """Decorator to skip tests when cryptography is not available."""
    return pytest.mark.skipif(not crypto_available(), reason=reason)


@pytest.fixture
def create_test_cert_and_key():
    """Create a test certificate and CA for testing."""
    import base64
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    # Create CA private key
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create CA certificate
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA Root"),
        ]
    )

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # Create leaf private key
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Create leaf certificate with SID and logicals
    leaf_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )

    # Add SAN with SID and logicals
    san_list = [
        x509.UniformResourceIdentifier("naylence:///logical/path1"),
        x509.UniformResourceIdentifier("naylence:///logical/path2"),
    ]

    # Add SID as OtherName extension (this would need the proper SID OID)
    try:
        # Try to add a SID OtherName extension
        from naylence.fame.security.cert.internal_ca_service import SID_OID

        sid_oid = x509.ObjectIdentifier(SID_OID)
        # Encode "test-node-123" as DER UTF8String
        import struct

        sid_value = "test-node-123"
        der_encoded = struct.pack("BB", 0x0C, len(sid_value)) + sid_value.encode("utf-8")
        sid_other_name = x509.OtherName(sid_oid, der_encoded)
        san_list.append(sid_other_name)  # type: ignore
    except (ImportError, Exception):
        # Just use URI format as fallback
        san_list.append(x509.UniformResourceIdentifier("naylence://sid/test-node-123"))

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # Create x5c chain
    x5c = [
        base64.b64encode(leaf_cert.public_bytes(serialization.Encoding.DER)).decode("ascii"),
        base64.b64encode(ca_cert.public_bytes(serialization.Encoding.DER)).decode("ascii"),
    ]

    # Create CA PEM
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    return x5c, ca_pem, leaf_cert

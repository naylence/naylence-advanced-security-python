"""Test certificate utility functions."""

import base64

import pytest

from naylence.fame.security.cert.certificate_cache import clear_cache
from naylence.fame.security.cert.util import public_key_from_x5c

# Import test utilities
try:
    import importlib.util

    CRYPTO_AVAILABLE = importlib.util.find_spec("cryptography") is not None
except ImportError:
    CRYPTO_AVAILABLE = False

requires_crypto = pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Requires cryptography package")


def requires_crypto_with_reason(reason="Requires cryptography package"):
    return pytest.mark.skipif(not CRYPTO_AVAILABLE, reason=reason)


class TestCertificateValidation:
    """Test certificate validation and public key extraction."""

    def setup_method(self):
        """Clear cache before each test."""
        clear_cache()

    def test_empty_chain_raises_error(self):
        """Test that empty certificate chain raises ValueError."""
        with pytest.raises(ValueError, match="Empty certificate chain"):
            public_key_from_x5c([])

    def test_invalid_base64_raises_error(self):
        """Test that invalid base64 certificates raise ValueError."""
        with pytest.raises(ValueError, match="Failed to decode certificate"):
            public_key_from_x5c(["invalid-base64"])

    @requires_crypto_with_reason("Requires cryptography package and test certificates")
    def test_valid_certificate_chain(self):
        """Test extracting public key from valid certificate chain."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from naylence.fame.security.cert.internal_ca_service import CASigningService, create_test_ca

        # Create test CA and node certificate
        root_cert_pem, root_key_pem = create_test_ca()
        ca_service = CASigningService(root_cert_pem, root_key_pem)

        # Generate node key
        node_key = ed25519.Ed25519PrivateKey.generate()
        node_pub_pem = (
            node_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )

        # Sign certificate
        from naylence.fame.util.util import secure_digest

        physical_path = "test/path"
        computed_sid = secure_digest(physical_path)

        cert_pem = ca_service.sign_node_cert(
            public_key_pem=node_pub_pem,
            node_id="test-node",
            node_sid=computed_sid,
            physical_path=physical_path,
            logicals=["path.logical.test"],
        )

        # Convert to x5c format
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        x5c = [base64.b64encode(cert_der).decode()]

        # Extract public key
        extracted_key = public_key_from_x5c(x5c)

        # Verify it matches the original
        original_bytes = node_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        extracted_bytes = extracted_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        assert original_bytes == extracted_bytes

    @requires_crypto_with_reason("Requires cryptography package and test certificates")
    def test_expired_certificate_raises_error(self):
        """Test that expired certificates raise ValueError."""
        # This would require generating expired test certificates
        pass

    @requires_crypto_with_reason("Requires cryptography package and test certificates")
    def test_name_constraints_validation(self):
        """Test that name constraints are properly validated."""
        # This would require generating certificates with name constraints
        pass

    @requires_crypto_with_reason("Requires cryptography package and test certificates")
    def test_trust_store_validation(self):
        """Test trust store validation."""
        # This would require generating a trust store
        pass


class TestCertificateCache:
    """Test certificate caching functionality."""

    def setup_method(self):
        """Clear cache before each test."""
        clear_cache()

    def test_cache_hit_performance(self):
        """Test that cached certificates are returned quickly."""
        # This test would require valid test certificates
        # For now, just verify cache structure works
        from naylence.fame.security.cert.certificate_cache import cache_stats

        stats = cache_stats()
        assert stats["size"] == 0
        assert stats["max_size"] == 512

    def test_cache_eviction(self):
        """Test that cache evicts old entries when full."""
        # This would require generating many test certificates
        pass

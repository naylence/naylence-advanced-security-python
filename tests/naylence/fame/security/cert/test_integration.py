"""Test certificate integration with envelope verification."""

import pytest

from naylence.fame.security.policy.security_policy import SigningConfig
from naylence.fame.security.signing.eddsa_envelope_verifier import (
    EdDSAEnvelopeVerifier,
    _load_public_key_from_jwk,
)

# Import test utilities
try:
    import importlib.util

    CRYPTO_AVAILABLE = importlib.util.find_spec("cryptography") is not None
except ImportError:
    CRYPTO_AVAILABLE = False

requires_crypto = pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Requires cryptography package")


class TestCertificateIntegration:
    """Test certificate support integration with existing systems."""

    def test_signing_config_certificate_fields(self):
        """Test that SigningConfig supports certificate-related fields."""
        from naylence.fame.security.policy.security_policy import SigningMaterial

        config = SigningConfig()

        # Test defaults
        assert config.signing_material == SigningMaterial.RAW_KEY
        assert config.validate_cert_name_constraints is True
        # trust_store_path removed - now uses FAME_CA_CERTS env var

        # Test setting values for X.509 chain mode
        config = SigningConfig(
            signing_material=SigningMaterial.X509_CHAIN,
            validate_cert_name_constraints=False,
        )

        assert config.signing_material == SigningMaterial.X509_CHAIN
        assert config.validate_cert_name_constraints is False
        # trust_store_path removed - now uses FAME_CA_CERTS env var

    def test_envelope_verifier_accepts_signing_config(self):
        """Test that EdDSAEnvelopeVerifier accepts SigningConfig."""
        from naylence.fame.security.keys.key_provider import get_key_provider
        from naylence.fame.security.policy.security_policy import SigningMaterial

        config = SigningConfig(signing_material=SigningMaterial.X509_CHAIN)
        verifier = EdDSAEnvelopeVerifier(key_provider=get_key_provider(), signing_config=config)

        assert verifier._signing_config.signing_material == SigningMaterial.X509_CHAIN

    def test_envelope_verifier_defaults_to_disabled_certificates(self):
        """Test that certificate support is disabled by default."""
        from naylence.fame.security.keys.key_provider import get_key_provider
        from naylence.fame.security.policy.security_policy import SigningMaterial

        verifier = EdDSAEnvelopeVerifier(key_provider=get_key_provider())

        assert verifier._signing_config.signing_material == SigningMaterial.RAW_KEY

    @requires_crypto
    def test_jwk_with_x5c_certificate_disabled(self):
        """Test that x5c JWKs are rejected when certificate support is disabled."""
        import base64

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from naylence.fame.security.cert.internal_ca_service import CASigningService, create_test_ca

        # Create test certificate
        root_cert_pem, root_key_pem = create_test_ca()
        ca_service = CASigningService(root_cert_pem, root_key_pem)

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

        physical_path = "test/path"
        computed_sid = secure_digest(physical_path)

        cert_pem = ca_service.sign_node_cert(
            public_key_pem=node_pub_pem,
            node_id="test-node",
            node_sid=computed_sid,
            physical_path=physical_path,
            logicals=["path.logical.test"],
        )

        # Create JWK with x5c
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        x5c = [base64.b64encode(cert_der).decode()]

        jwk = {"kty": "OKP", "crv": "Ed25519", "use": "sig", "kid": "test-node", "x5c": x5c}

        # Test with certificates disabled (default)
        config = SigningConfig()  # Default is RAW_KEY

        with pytest.raises(ValueError, match="Certificate keys disabled by node policy"):
            _load_public_key_from_jwk(jwk, config)

    @requires_crypto
    def test_jwk_with_x5c_certificate_enabled(self):
        """Test that x5c JWKs work when certificate support is enabled."""
        import base64
        import os
        import tempfile

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from naylence.fame.security.cert.internal_ca_service import CASigningService, create_test_ca

        # Create test certificate
        root_cert_pem, root_key_pem = create_test_ca()
        ca_service = CASigningService(root_cert_pem, root_key_pem)

        # Set up trust store with root CA
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as trust_store_file:
            trust_store_file.write(root_cert_pem)
            trust_store_path = trust_store_file.name

        # Set FAME_CA_CERTS environment variable
        old_ca_certs = os.environ.get("FAME_CA_CERTS")
        os.environ["FAME_CA_CERTS"] = trust_store_path

        try:
            node_key = ed25519.Ed25519PrivateKey.generate()
            node_pub_pem = (
                node_key.public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode()
            )

            # Compute SID from physical path
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

            # Create JWK with x5c
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            x5c = [base64.b64encode(cert_der).decode()]

            jwk = {"kty": "OKP", "crv": "Ed25519", "use": "sig", "kid": "test-node", "x5c": x5c}

            # Test with certificates enabled
            from naylence.fame.security.policy.security_policy import SigningMaterial

            config = SigningConfig(signing_material=SigningMaterial.X509_CHAIN)
            # Should successfully extract public key
            key_result = _load_public_key_from_jwk(jwk, config)

            # Since we're using x5c, we get a tuple (public_key, certificate)
            if isinstance(key_result, tuple):
                extracted_key, certificate = key_result
            else:
                extracted_key = key_result

            # Verify it matches the original
            original_bytes = node_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )
            extracted_bytes = extracted_key.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )

            assert original_bytes == extracted_bytes

        finally:
            # Restore original environment variable
            if old_ca_certs is not None:
                os.environ["FAME_CA_CERTS"] = old_ca_certs
            else:
                os.environ.pop("FAME_CA_CERTS", None)

            # Clean up temp file
            os.unlink(trust_store_path)

    @requires_crypto
    def test_name_constraints_validation_enabled(self):
        """Test name constraints validation when enabled."""
        # This would test:
        # 1. Create certificate with SANs that violate name constraints
        # 2. Use with EdDSAEnvelopeVerifier (name constraints enabled)
        # 3. Verify rejection
        pass

    @requires_crypto
    def test_name_constraints_validation_disabled(self):
        """Test name constraints validation when disabled."""
        # This would test:
        # 1. Create certificate with SANs that violate name constraints
        # 2. Use with EdDSAEnvelopeVerifier (name constraints disabled)
        # 3. Verify acceptance
        pass

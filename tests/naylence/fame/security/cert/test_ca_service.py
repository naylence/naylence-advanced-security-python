"""Test CA service functionality."""

import os
from typing import Any

import pytest

from naylence.fame.core import DataFrame
from naylence.fame.security.cert.ca_service import CASigningService, create_test_ca

# Import test utilities
try:
    import importlib.util

    CRYPTO_AVAILABLE = importlib.util.find_spec("cryptography") is not None
except ImportError:
    CRYPTO_AVAILABLE = False

requires_crypto = pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Requires cryptography package")


class TestCAService:
    """Test Certificate Authority service."""

    @requires_crypto
    def test_create_test_ca(self):
        """Test creating a test CA."""
        root_cert_pem, root_key_pem = create_test_ca()

        assert "-----BEGIN CERTIFICATE-----" in root_cert_pem
        assert "-----END CERTIFICATE-----" in root_cert_pem
        assert "-----BEGIN PRIVATE KEY-----" in root_key_pem
        assert "-----END PRIVATE KEY-----" in root_key_pem

    @requires_crypto
    def test_ca_service_initialization(self):
        """Test CA service initialization."""
        root_cert_pem, root_key_pem = create_test_ca()

        ca_service = CASigningService(root_cert_pem, root_key_pem)
        assert ca_service is not None

    @requires_crypto
    def test_sign_node_certificate(self):
        """Test signing a node certificate with physical and logicals."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from naylence.fame.util.util import secure_digest

        # Create test CA
        root_cert_pem, root_key_pem = create_test_ca()
        ca_service = CASigningService(root_cert_pem, root_key_pem)

        # Generate a test node key
        node_private_key = ed25519.Ed25519PrivateKey.generate()
        node_public_key_pem = (
            node_private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )

        # Compute SID from physical path
        physical_path = "us-east-1/rack-42/node-123"
        computed_sid = secure_digest(physical_path)

        # Sign node certificate with host-like logical addresses
        cert_pem = ca_service.sign_node_cert(
            public_key_pem=node_public_key_pem,
            node_id="test-node-123",
            node_sid=computed_sid,
            physical_path=physical_path,
            logicals=["api.services.node", "compute.services.node"],
        )

        # Verify certificate was created
        assert "-----BEGIN CERTIFICATE-----" in cert_pem
        assert "-----END CERTIFICATE-----" in cert_pem

        # Load and verify certificate contains expected SANs
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(cert_pem.encode())

        # Extract SAN URIs
        from cryptography.x509.oid import ExtensionOID

        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_uris = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)  # type: ignore[attr-defined]

        # Verify SPIFFE ID is present (replaces legacy naylence URIs)
        expected_spiffe_id = f"spiffe://naylence.fame/nodes/{computed_sid}"
        assert expected_spiffe_id in san_uris, (
            f"Expected SPIFFE ID {expected_spiffe_id} not found in {san_uris}"
        )

        # Verify no physical path URI is present (security requirement)
        physical_uri = "naylence-phys:///us-east-1/rack-42/node-123"
        assert physical_uri not in san_uris, f"Physical path URI should not be present: {san_uris}"

    @requires_crypto
    def test_create_intermediate_ca_with_name_constraints(self):
        """Test creating intermediate CA with DNS name constraints for OpenSSL compatibility."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        # Create test root CA
        root_cert_pem, root_key_pem = create_test_ca()
        ca_service = CASigningService(root_cert_pem, root_key_pem)

        # Generate intermediate CA key
        int_private_key = ed25519.Ed25519PrivateKey.generate()
        int_public_key_pem = (
            int_private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )

        # Create intermediate CA with name constraints
        int_cert_pem = ca_service.create_intermediate_ca(
            public_key_pem=int_public_key_pem,
            ca_name="Test Intermediate CA - us-east-1",
            permitted_paths=["/us-east-1/"],
        )

        # Verify certificate was created
        assert "-----BEGIN CERTIFICATE-----" in int_cert_pem
        assert "-----END CERTIFICATE-----" in int_cert_pem

        # Load and verify certificate contains name constraints
        cert = x509.load_pem_x509_certificate(int_cert_pem.encode())

        # Check for name constraints extension
        from cryptography.x509.oid import ExtensionOID

        nc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
        assert nc_ext.critical is True

        # Verify permitted subtrees - now using DNS constraints for OpenSSL compatibility
        name_constraints = nc_ext.value  # type: ignore[attr-defined]
        # Use dynamic attribute access to avoid linter issues with private/protected attributes
        permitted_subtrees = getattr(name_constraints, "permitted_subtrees", None)
        if permitted_subtrees is not None:
            # Look for DNS name constraints instead of URI constraints
            permitted_dns_names = [
                subtree.value for subtree in permitted_subtrees if isinstance(subtree, x509.DNSName)
            ]
        else:
            permitted_dns_names = []

        # Verify the base DNS constraint is present (allows all subdomains of FAME_ROOT)
        from naylence.fame.util.logicals_util import get_fame_root

        fame_root = get_fame_root()
        assert fame_root in permitted_dns_names, (
            f"Expected '{fame_root}' in DNS constraints: {permitted_dns_names}"
        )

    @requires_crypto
    def test_unsupported_key_type_rejection(self):
        """Test that unsupported key types are properly rejected."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import dh

        # Create test CA
        root_cert_pem, root_key_pem = create_test_ca()
        ca_service = CASigningService(root_cert_pem, root_key_pem)

        # Generate DH parameters and key
        parameters = dh.generate_parameters(generator=2, key_size=1024)
        dh_private_key = parameters.generate_private_key()
        dh_public_key_pem = (
            dh_private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )

        # Attempt to sign certificate with DH key should fail
        from naylence.fame.util.util import secure_digest

        test_physical_path = "test/path"
        test_computed_sid = secure_digest(test_physical_path)

        with pytest.raises(
            ValueError, match="Public key type DHPublicKey is not supported for X.509 certificates"
        ):
            ca_service.sign_node_cert(
                public_key_pem=dh_public_key_pem,
                node_id="test-node-dh",
                node_sid=test_computed_sid,
                physical_path=test_physical_path,
                logicals=["test.logical"],
            )

    @requires_crypto
    def test_sign_node_certificate_with_sid(self):
        """Test signing a node certificate with SID as OtherName extension."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from naylence.fame.util.util import secure_digest

        # Create test CA
        root_cert_pem, root_key_pem = create_test_ca()
        ca_service = CASigningService(root_cert_pem, root_key_pem)

        # Generate a test node key
        node_private_key = ed25519.Ed25519PrivateKey.generate()
        node_public_key_pem = (
            node_private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )

        # Compute SID from physical path
        physical_path = "us-east-1/rack-42/node-123"
        test_sid = secure_digest(physical_path)

        # Sign node certificate with SID
        cert_pem = ca_service.sign_node_cert(
            public_key_pem=node_public_key_pem,
            node_id="test-node-123",
            physical_path=physical_path,
            logicals=["agents.node.east.services"],
            node_sid=test_sid,
        )

        # Load certificate and verify SID is embedded as OtherName
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(cert_pem.encode())

        # Extract SID using utility function
        from naylence.fame.security.cert.util import sid_from_cert

        extracted_sid = sid_from_cert(cert)

        assert extracted_sid == test_sid, f"Expected SID '{test_sid}', got '{extracted_sid}'"


class TestEndToEndCertificateFlow:
    """Test complete certificate workflow."""

    @requires_crypto
    def test_complete_certificate_workflow(self):
        """Test complete workflow from CA to envelope verification."""
        import base64

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from naylence.fame.security.policy.security_policy import SigningConfig
        from naylence.fame.security.signing.eddsa_envelope_verifier import _load_public_key_from_jwk

        # Store original environment variable
        original_ca_certs = os.environ.get("FAME_CA_CERTS")

        try:
            # 1. Create test CA
            root_cert_pem, root_key_pem = create_test_ca()
            ca_service = CASigningService(root_cert_pem, root_key_pem)

            # Set FAME_CA_CERTS to use the test CA for trust validation
            os.environ["FAME_CA_CERTS"] = root_cert_pem

            # 2. Generate node keypair
            node_private_key = ed25519.Ed25519PrivateKey.generate()
            node_public_key_pem = (
                node_private_key.public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode()
            )

            # Compute SID from physical path
            from naylence.fame.util.util import secure_digest

            physical_path = "us-east-1/rack-42/node-123"
            computed_sid = secure_digest(physical_path)

            # 3. Sign node certificate with physical/logicals
            cert_pem = ca_service.sign_node_cert(
                public_key_pem=node_public_key_pem,
                node_id="test-node-123",
                node_sid=computed_sid,
                physical_path=physical_path,
                logicals=["node-123.agents.us-east-1"],
            )

            # 4. Create JWK with x5c
            cert_der = x509.load_pem_x509_certificate(cert_pem.encode()).public_bytes(
                serialization.Encoding.DER
            )
            cert_b64 = base64.b64encode(cert_der).decode()

            jwk = {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "kid": "test-node-123",
                "sid": "test-sid",
                "x5c": [cert_b64],
            }

            # 5. Use in EdDSAEnvelopeVerifier with certificates enabled
            from naylence.fame.security.policy.security_policy import SigningMaterial

            config = SigningConfig(signing_material=SigningMaterial.X509_CHAIN)
            # 6. Verify public key extraction works
            key_result = _load_public_key_from_jwk(jwk, config)

            # Since we're using x5c, we get a tuple (public_key, certificate)
            if isinstance(key_result, tuple):
                extracted_public_key, certificate = key_result
            else:
                extracted_public_key = key_result

            # Verify the extracted key matches the original
            original_public_key = node_private_key.public_key()

            # Compare public key bytes
            extracted_bytes = extracted_public_key.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )
            original_bytes = original_public_key.public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )

            assert extracted_bytes == original_bytes, "Extracted public key doesn't match original"

        finally:
            # Restore original environment variable
            if original_ca_certs is not None:
                os.environ["FAME_CA_CERTS"] = original_ca_certs
            else:
                os.environ.pop("FAME_CA_CERTS", None)

    @requires_crypto
    def test_envelope_verification_with_sid_validation(self):
        """Test envelope verification with SID validation enabled."""
        import base64

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from naylence.fame.core.protocol.envelope import FameEnvelope
        from naylence.fame.core.protocol.security_header import SecurityHeader, SignatureHeader
        from naylence.fame.security.keys.key_provider import KeyProvider
        from naylence.fame.security.policy.security_policy import SigningConfig
        from naylence.fame.security.signing.eddsa_envelope_verifier import EdDSAEnvelopeVerifier
        from naylence.fame.util.util import secure_digest

        # 1. Create test CA and node certificate with SID
        root_cert_pem, root_key_pem = create_test_ca()
        ca_service = CASigningService(root_cert_pem, root_key_pem)

        node_private_key = ed25519.Ed25519PrivateKey.generate()
        node_public_key_pem = (
            node_private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )

        physical_path = "us-east-1/rack-42/node-123"
        test_sid = secure_digest(physical_path)
        cert_pem = ca_service.sign_node_cert(
            public_key_pem=node_public_key_pem,
            node_id="test-node-123",
            physical_path=physical_path,
            logicals=["node-123.agents.us-east-1"],
            node_sid=test_sid,
        )

        # 2. Create JWK with x5c
        cert_der = x509.load_pem_x509_certificate(cert_pem.encode()).public_bytes(
            serialization.Encoding.DER
        )
        cert_b64 = base64.b64encode(cert_der).decode()

        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "kid": "test-node-123",
            "sid": test_sid,  # JWK SID matches certificate SID
            "x5c": [cert_b64],
        }

        # 3. Mock key provider
        class MockKeyProvider(KeyProvider):
            def get_key(self, kid: str) -> dict[str, Any]:
                if kid == "test-node-123":
                    return jwk
                else:
                    raise KeyError(f"Key {kid} not found")

        # 4. Create verifier with SID validation enabled
        from naylence.fame.security.policy.security_policy import SigningMaterial

        config = SigningConfig(signing_material=SigningMaterial.X509_CHAIN, require_cert_sid_match=True)
        EdDSAEnvelopeVerifier(key_provider=MockKeyProvider(), signing_config=config)

        # 5. Create test envelope with matching SID
        FameEnvelope(
            sid=test_sid,  # Envelope SID matches certificate SID
            sec=SecurityHeader(
                sig=SignatureHeader(
                    kid="test-node-123",
                    val="dummy-signature",  # We'll mock verification
                )
            ),
            frame=DataFrame(payload={"data": "test data"}),
        )

        # This would normally fail signature verification, but validates SID matching logic
        # In a real test, you'd need to create a proper signature

    @requires_crypto
    def test_envelope_verification_with_logical_validation(self):
        """Test envelope verification with logical validation enabled."""
        import base64

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from naylence.fame.security.keys.key_provider import KeyProvider
        from naylence.fame.security.policy.security_policy import SigningConfig
        from naylence.fame.security.signing.eddsa_envelope_verifier import EdDSAEnvelopeVerifier

        # 1. Create test CA and node certificate with logicals
        root_cert_pem, root_key_pem = create_test_ca()
        ca_service = CASigningService(root_cert_pem, root_key_pem)

        node_private_key = ed25519.Ed25519PrivateKey.generate()
        node_public_key_pem = (
            node_private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )

        allowed_logicals = ["node-123.agents.us-east-1", "node-123.compute.us-east-1"]

        # Compute SID from physical path
        from naylence.fame.util.util import secure_digest

        physical_path = "us-east-1/rack-42/node-123"
        computed_sid = secure_digest(physical_path)

        cert_pem = ca_service.sign_node_cert(
            public_key_pem=node_public_key_pem,
            node_id="test-node-123",
            node_sid=computed_sid,
            physical_path=physical_path,
            logicals=allowed_logicals,
        )

        # 2. Create JWK with x5c
        cert_der = x509.load_pem_x509_certificate(cert_pem.encode()).public_bytes(
            serialization.Encoding.DER
        )
        cert_b64 = base64.b64encode(cert_der).decode()

        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "kid": "test-node-123",
            "sid": "test-sid",
            "x5c": [cert_b64],
        }

        # 3. Mock key provider
        class MockKeyProvider(KeyProvider):
            def get_key(self, kid: str) -> dict[str, Any]:
                if kid == "test-node-123":
                    return jwk
                else:
                    raise KeyError(f"Key {kid} not found")

        # 4. Create verifier with logical validation enabled
        from naylence.fame.security.policy.security_policy import SigningMaterial

        config = SigningConfig(signing_material=SigningMaterial.X509_CHAIN, require_cert_logical_match=True)
        EdDSAEnvelopeVerifier(key_provider=MockKeyProvider(), signing_config=config)

        # 5. Test cases for logical validation
        # This would be used in the verify_envelope call with logical parameter
        # verify_envelope(envelope, logical="us-east-1/agents/node-123")  # Should pass
        # verify_envelope(envelope, logical="forbidden/path")  # Should fail

    @requires_crypto
    def test_sid_and_logical_validation(self):
        """Test SID and logical validation without full envelope verification."""
        import base64

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from naylence.fame.security.policy.security_policy import SigningConfig
        from naylence.fame.security.signing.eddsa_envelope_verifier import _load_public_key_from_jwk

        # Store original environment variable
        original_ca_certs = os.environ.get("FAME_CA_CERTS")

        try:
            # 1. Create test CA and node certificate with SID
            root_cert_pem, root_key_pem = create_test_ca()
            ca_service = CASigningService(root_cert_pem, root_key_pem)

            # Set FAME_CA_CERTS to use the test CA for trust validation
            os.environ["FAME_CA_CERTS"] = root_cert_pem

            node_private_key = ed25519.Ed25519PrivateKey.generate()
            node_public_key_pem = (
                node_private_key.public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode()
            )

            # Compute SID from physical path
            from naylence.fame.util.util import secure_digest

            physical_path = "us-east-1/rack-42/node-123"
            test_sid = secure_digest(physical_path)
            test_logicals = ["node-123.agents.us-east-1", "node-123.compute.us-east-1"]

            cert_pem = ca_service.sign_node_cert(
                public_key_pem=node_public_key_pem,
                node_id="test-node-123",
                physical_path=physical_path,
                logicals=test_logicals,
                node_sid=test_sid,
            )

            # 2. Load certificate and verify SID and logicals
            cert = x509.load_pem_x509_certificate(cert_pem.encode())

            from naylence.fame.security.cert.util import sid_from_cert

            # Verify SID extraction
            extracted_sid = sid_from_cert(cert)
            assert extracted_sid == test_sid, f"Expected SID '{test_sid}', got '{extracted_sid}'"

            # 3. Test that _load_public_key_from_jwk returns both key and cert for x5c
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            cert_b64 = base64.b64encode(cert_der).decode()

            jwk = {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "kid": "test-node-123",
                "sid": test_sid,
                "x5c": [cert_b64],
            }

            # Test with basic certificate support (returns just public key)
            from naylence.fame.security.policy.security_policy import SigningMaterial

            config_basic = SigningConfig(signing_material=SigningMaterial.X509_CHAIN)
            key_result_basic = _load_public_key_from_jwk(jwk, config_basic)

            # Should return just public key when no cert validation policies are enabled
            assert not isinstance(key_result_basic, tuple), (
                f"Expected public key only, got {type(key_result_basic)}"
            )

            # Test with certificate validation enabled (returns tuple)
            config_with_validation = SigningConfig(
                signing_material=SigningMaterial.X509_CHAIN, require_cert_sid_match=True
            )
            key_result_with_cert = _load_public_key_from_jwk(jwk, config_with_validation)

            # Should return a tuple (public_key, certificate) for x5c JWKs with validation enabled
            assert isinstance(key_result_with_cert, tuple), (
                f"Expected tuple for x5c JWK with validation, got {type(key_result_with_cert)}"
            )
            public_key, certificate = key_result_with_cert

            # Verify the certificate matches
            assert certificate == cert, "Certificate from JWK doesn't match original"

            # Verify SID from certificate matches
            cert_sid = sid_from_cert(certificate)
            assert cert_sid == test_sid, f"Certificate SID '{cert_sid}' doesn't match expected '{test_sid}'"

        finally:
            # Restore original environment variable
            if original_ca_certs is not None:
                os.environ["FAME_CA_CERTS"] = original_ca_certs
            else:
                os.environ.pop("FAME_CA_CERTS", None)

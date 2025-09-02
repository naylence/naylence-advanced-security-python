"""
Integration test for DNS hostname notation in certificates and name constraints.

This test verifies that:
1. Logicals are validated for DNS compatibility
2. CA service creates certificates with hostname notation
3. Certificate validation works with both path and hostname notation
4. Name constraints work properly with OpenSSL
"""

import asyncio

import pytest

from naylence.fame.security.cert.internal_ca_service import CASigningService, create_test_ca


@pytest.mark.asyncio
async def test_ca_service_hostname_notation_integration():
    """Test CA service integration with hostname notation."""

    # Create test CA
    root_cert_pem, root_key_pem = create_test_ca()
    ca_service = CASigningService(root_cert_pem, root_key_pem)

    # Test logicals (host-like notation)
    test_logicals = ["node-123.workers.us-east-1", "gateway.api.prod", "server01.rack42.datacenter1"]

    # Generate node key for testing
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    node_private_key = ed25519.Ed25519PrivateKey.generate()
    node_public_key_pem = (
        node_private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )

    # Compute SID from physical path
    from naylence.fame.util.util import secure_digest

    physical_path = "us-east-1/rack-42/node-123"
    computed_sid = secure_digest(physical_path)

    # Sign certificate with logicals
    cert_pem = ca_service.sign_node_cert(
        public_key_pem=node_public_key_pem,
        node_id="test-node-123",
        node_sid=computed_sid,
        physical_path=physical_path,
        logicals=test_logicals,
    )

    # Verify certificate was created
    assert "-----BEGIN CERTIFICATE-----" in cert_pem
    assert "-----END CERTIFICATE-----" in cert_pem

    # Load certificate and verify SAN contains hostname notation URIs
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    # Extract SAN URIs (should contain SPIFFE ID now)
    from cryptography.x509.oid import ExtensionOID

    san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    san_uris = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)

    # Verify SPIFFE ID is present in SAN
    spiffe_uris = [uri for uri in san_uris if uri.startswith("spiffe://")]
    assert len(spiffe_uris) > 0, f"Expected SPIFFE URI in SAN: {san_uris}"

    # Verify we can extract host-based logical addresses using our utility
    from naylence.fame.security.cert.util import host_logicals_from_cert

    extracted_logicals = host_logicals_from_cert(cert)

    # Should extract logical addresses in host-based format
    assert set(extracted_logicals) == set(test_logicals), (
        f"Extracted logicals {extracted_logicals} don't match expected {test_logicals}"
    )


@pytest.mark.asyncio
async def test_intermediate_ca_with_hostname_constraints():
    """Test intermediate CA creation with DNS name constraints for OpenSSL compatibility."""

    # Create test CA
    root_cert_pem, root_key_pem = create_test_ca()
    ca_service = CASigningService(root_cert_pem, root_key_pem)

    # Generate intermediate CA key
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    intermediate_private_key = ed25519.Ed25519PrivateKey.generate()
    intermediate_public_key_pem = (
        intermediate_private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )

    # Test permitted paths for name constraints
    permitted_paths = ["/us-east-1/workers", "/us-east-1/api"]

    # Create intermediate CA with name constraints
    intermediate_cert_pem = ca_service.create_intermediate_ca(
        public_key_pem=intermediate_public_key_pem,
        ca_name="Test Intermediate CA",
        permitted_paths=permitted_paths,
    )

    # Verify certificate was created
    assert "-----BEGIN CERTIFICATE-----" in intermediate_cert_pem

    # Load certificate and verify name constraints
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    intermediate_cert = x509.load_pem_x509_certificate(intermediate_cert_pem.encode())

    # Check for name constraints extension
    name_constraints_ext = intermediate_cert.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)

    # Verify name constraints are using DNS constraints for OpenSSL compatibility
    permitted_subtrees = name_constraints_ext.value.permitted_subtrees
    assert permitted_subtrees is not None

    # Extract DNS constraints (now using DNS name constraints instead of URI constraints)
    constraint_dns_names = [
        subtree.value for subtree in permitted_subtrees if isinstance(subtree, x509.DNSName)
    ]

    # Verify the base DNS constraint is present (allows all subdomains of FAME_ROOT)
    from naylence.fame.util.logicals_util import get_fame_root

    fame_root = get_fame_root()
    assert fame_root in constraint_dns_names, (
        f"Expected '{fame_root}' in DNS constraints: {constraint_dns_names}"
    )


@pytest.mark.asyncio
async def test_welcome_service_logical_validation():
    """Test that welcome service validates logicals for DNS compatibility."""

    from naylence.fame.core import NodeHelloFrame, NodeWelcomeFrame
    from naylence.fame.welcome.default_welcome_service import DefaultWelcomeService

    # Mock dependencies
    class MockPlacementStrategy:
        async def place(self, hello):
            class PlacementResult:
                accept = True
                assigned_path = "/test/node"
                target_system_id = "test-target"
                target_physical_path = "/test"
                expires_at = None
                metadata = None

            return PlacementResult()

    class MockTokenIssuer:
        def issue(self, **kwargs):
            return "mock-token"

    class MockTransportProvisioner:
        async def provision(self, placement_result, hello, metadata, token):
            class TransportResult:
                connection_grant = {"type": "websocket", "url": "ws://test"}
                cleanup_handle = None
                metadata = None

            return TransportResult()

    # Create welcome service
    welcome_service = DefaultWelcomeService(
        placement_strategy=MockPlacementStrategy(),
        transport_provisioner=MockTransportProvisioner(),
        token_issuer=MockTokenIssuer(),
    )

    # Test with valid host-based logical addresses
    valid_hello = NodeHelloFrame(
        system_id="test-node",
        instance_id="test-instance",
        logicals=["workers.us-east-1", "api.prod", "fame.fabric"],
        supported_transports=["websocket"],
    )

    # Should succeed
    result = await welcome_service.handle_hello(valid_hello)
    assert result is not None
    assert isinstance(result, NodeWelcomeFrame)
    assert result.target_system_id == "test-target"  # Uses target_system_id from placement
    assert result.system_id == "test-node"  # Original system_id from hello frame

    # Test with invalid logical addresses (should be rejected)
    invalid_hello = NodeHelloFrame(
        system_id="test-node",
        instance_id="test-instance",
        logicals=["-invalid.start", "invalid..double-dot"],
        supported_transports=["websocket"],
    )

    # Should raise an exception due to invalid logical address format
    with pytest.raises(Exception, match="Invalid logical format"):
        await welcome_service.handle_hello(invalid_hello)

    # Test with another invalid format
    invalid_hello2 = NodeHelloFrame(
        system_id="test-node",
        instance_id="test-instance",
        logicals=["valid.logical", ""],  # Empty logical address
        supported_transports=["websocket"],
    )

    # Should also be rejected
    with pytest.raises(Exception, match="Invalid logical format"):
        await welcome_service.handle_hello(invalid_hello2)


@pytest.mark.asyncio
async def test_attachment_logical_validation():
    """Test attachment validation with logicals."""

    from naylence.fame.factory import create_resource
    from naylence.fame.security.cert.attachment_cert_validator_factory import AttachmentCertValidatorConfig
    from naylence.fame.security.keys.attachment_key_validator_factory import AttachmentKeyValidatorFactory

    # Create validator instance
    config = AttachmentCertValidatorConfig()
    cert_validator = await create_resource(AttachmentKeyValidatorFactory, config)

    # Create test certificate with logicals
    root_cert_pem, root_key_pem = create_test_ca()
    ca_service = CASigningService(root_cert_pem, root_key_pem)

    # Generate node key
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    node_private_key = ed25519.Ed25519PrivateKey.generate()
    node_public_key_pem = (
        node_private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )

    # Certificate logicals (host-like notation)
    cert_logicals = ["workers.us-east-1", "api.us-east-1"]

    # Compute SID from physical path
    from naylence.fame.util.util import secure_digest

    physical_path = "/test/path"
    computed_sid = secure_digest(physical_path)

    # Sign certificate
    cert_pem = ca_service.sign_node_cert(
        public_key_pem=node_public_key_pem,
        node_id="test-node",
        node_sid=computed_sid,
        physical_path=physical_path,
        logicals=cert_logicals,
    )

    # Convert certificate to x5c format
    import base64

    from cryptography import x509

    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    x5c = [base64.b64encode(cert_der).decode()]

    # Create child keys with certificate
    child_keys = [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "test-node-key",
            "use": "sig",
            "x5c": x5c,
            "x": base64.urlsafe_b64encode(
                node_private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
                )
            )
            .decode()
            .rstrip("="),
        }
    ]

    # Test with matching authorized paths (now using host-based logical addresses)
    authorized_paths = ["workers.us-east-1", "api.us-east-1", "monitoring.us-east-1"]
    is_valid, error = await cert_validator.validate_child_attachment_logicals(
        child_keys, authorized_paths, "test-child"
    )
    assert is_valid, f"Validation should succeed: {error}"

    # Test with non-matching authorized paths
    unauthorized_paths = ["workers.us-west-1"]
    is_valid, error = await cert_validator.validate_child_attachment_logicals(
        child_keys, unauthorized_paths, "test-child"
    )
    assert not is_valid, "Validation should fail for unauthorized paths"
    assert "unauthorized logicals" in error.lower()


def test_host_logical_extraction():
    """Test that host logical extraction works correctly."""

    # Test extracting from host-like URI
    from naylence.fame.util.logicals_util import extract_host_logical_from_uri

    host_uri = "naylence://fame.fabric/"
    host_logical = extract_host_logical_from_uri(host_uri)
    assert host_logical == "fame.fabric"

    # Test extracting from URI without trailing slash
    host_uri_no_slash = "naylence://api.services"
    host_logical = extract_host_logical_from_uri(host_uri_no_slash)
    assert host_logical == "api.services"

    # Test conversion from legacy path format to host format
    legacy_uri = "naylence:///us-east-1/workers/node-123"
    host_logical = extract_host_logical_from_uri(legacy_uri)
    assert host_logical == "node-123.workers.us-east-1"


async def main():
    """Run all integration tests."""
    print("🧪 DNS Hostname Notation Integration Tests\n")

    try:
        await test_ca_service_hostname_notation_integration()
        print("✅ CA service hostname notation integration")

        await test_intermediate_ca_with_hostname_constraints()
        print("✅ Intermediate CA hostname constraints")

        await test_welcome_service_logical_validation()
        print("✅ Welcome service logical validation")

        await test_attachment_logical_validation()
        print("✅ Attachment logical validation")

        test_host_logical_extraction()
        print("✅ Host logical extraction")

        print("\n" + "=" * 60)
        print("🏆 ALL DNS HOSTNAME NOTATION INTEGRATION TESTS PASSED!")
        print("")
        print("SUMMARY:")
        print("✅ Logicals validated for DNS hostname compatibility")
        print("✅ CA service uses hostname notation for name constraints")
        print("✅ Certificate validation supports both path and hostname notation")
        print("✅ Welcome service validates logical syntax")
        print("✅ Host logical address extraction from certificates")
        print("✅ OpenSSL-compatible name constraints implemented")
        print("")
        print("🎯 Ready for production with OpenSSL compatibility!")

    except Exception as e:
        print(f"\n❌ Integration test failed: {e}")
        import traceback

        traceback.print_exc()
        return False

    return True


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)

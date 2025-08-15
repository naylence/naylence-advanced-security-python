"""
Test FAME_ROOT configuration and root logical handling.
"""

import os
from unittest.mock import patch

from naylence.fame.util.logicals_util import (
    get_fame_root,
    hostname_to_logical,
    logical_to_hostname,
)


class TestFameRootConfiguration:
    """Test FAME_ROOT environment variable configuration."""

    def test_default_fame_root(self):
        """Test that FAME_ROOT defaults to 'fame.fabric'."""
        # Ensure FAME_ROOT is not set
        with patch.dict(os.environ, {}, clear=True):
            assert get_fame_root() == "fame.fabric"

    def test_custom_fame_root(self):
        """Test that FAME_ROOT can be customized via environment variable."""
        with patch.dict(os.environ, {"FAME_ROOT": "custom.domain"}):
            assert get_fame_root() == "custom.domain"

    def test_root_path_conversion_default(self):
        """Test root path conversion with default FAME_ROOT."""
        with patch.dict(os.environ, {}, clear=True):
            # Root path "/" should convert to "fame.fabric"
            assert logical_to_hostname("/") == "fame.fabric"
            # And back
            assert hostname_to_logical("fame.fabric") == "/"

    def test_regular_path_conversion(self):
        """Test that regular paths work correctly with custom FAME_ROOT."""
        with patch.dict(os.environ, {"FAME_ROOT": "test.domain"}):
            # Regular path should still work normally
            assert logical_to_hostname("/org/api") == "api.org"
            assert hostname_to_logical("api.org") == "/org/api"

    def test_roundtrip_conversion_with_custom_root(self):
        """Test roundtrip conversion works with custom FAME_ROOT."""
        with patch.dict(os.environ, {"FAME_ROOT": "example.com"}):
            test_paths = [
                "/",  # Root path
                "/org",  # Single segment
                "/org/api",  # Two segments
                "/datacenter/rack/node",  # Three segments
            ]

            for path in test_paths:
                hostname = logical_to_hostname(path)
                converted_back = hostname_to_logical(hostname)
                assert converted_back == path, (
                    f"Roundtrip failed for {path}: {hostname} -> {converted_back}"
                )


class TestRootLogicalAddressScenarios:
    """Test scenarios with root logical addresses like 'alice@/'."""

    def test_intermediate_ca_with_custom_fame_root(self):
        """Test intermediate CA creation with custom FAME_ROOT."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.x509.oid import ExtensionOID

        from naylence.fame.security.cert.ca_service import CASigningService, create_test_ca

        with patch.dict(os.environ, {"FAME_ROOT": "company.internal"}):
            # Create test CA
            root_cert_pem, root_key_pem = create_test_ca()
            ca_service = CASigningService(root_cert_pem, root_key_pem)

            # Generate intermediate CA key
            intermediate_private_key = ed25519.Ed25519PrivateKey.generate()
            intermediate_public_key_pem = (
                intermediate_private_key.public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode()
            )

            # Create intermediate CA with logicals
            intermediate_cert_pem = ca_service.create_intermediate_ca(
                public_key_pem=intermediate_public_key_pem,
                ca_name="Test Intermediate CA",
                permitted_paths=["/org", "/"],  # Include root path
            )

            # Load certificate and verify name constraints
            intermediate_cert = x509.load_pem_x509_certificate(intermediate_cert_pem.encode())

            # Check for name constraints extension
            name_constraints_ext = intermediate_cert.extensions.get_extension_for_oid(
                ExtensionOID.NAME_CONSTRAINTS
            )

            # Extract DNS constraints
            permitted_subtrees = name_constraints_ext.value.permitted_subtrees
            assert permitted_subtrees is not None

            constraint_dns_names = [
                subtree.value for subtree in permitted_subtrees if isinstance(subtree, x509.DNSName)
            ]

            # Should contain the custom FAME_ROOT
            assert "company.internal" in constraint_dns_names, (
                f"Expected 'company.internal' in DNS constraints: {constraint_dns_names}"
            )

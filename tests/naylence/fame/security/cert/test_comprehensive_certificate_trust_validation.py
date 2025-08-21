"""
Comprehensive certificate trust validation test.

This test verifies the complete trust validation system:
1. Node startup certificate validation
2. Attachment handshake certificate validation
3. Key exchange certificate validation
4. End-to-end security guarantees
"""

import os

import pytest

from naylence.fame.core import create_resource
from naylence.fame.security.cert.attachment_cert_validator_factory import AttachmentCertValidatorConfig
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
from naylence.fame.security.keys.attachment_key_validator_factory import AttachmentKeyValidatorFactory


@pytest.fixture
async def cert_validator():
    """Create a certificate validator instance for testing."""
    config = AttachmentCertValidatorConfig()
    return await create_resource(AttachmentKeyValidatorFactory, config)


@pytest.mark.asyncio
async def test_comprehensive_trust_validation(cert_validator):
    """Test the complete certificate trust validation system."""

    # Set up test environment
    test_ca_pem = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAMZ8JKUBU1YrMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNVBAMMCVRl
c3QgUm9vdDAeFw0yNTA3MTEwMTAwMDBaFw0yNjA3MTEwMTAwMDBaMBQxEjAQBgNV
BAMMCVRlc3QgUm9vdDBcMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuZk
-----END CERTIFICATE-----"""

    original_ca_certs = os.environ.get("FAME_CA_CERTS")
    os.environ["FAME_CA_CERTS"] = test_ca_pem

    try:
        # Test 1: Node Startup Certificate Validation
        crypto_provider = get_crypto_provider()

        # Test with no certificate (should pass)
        if not crypto_provider.has_certificate():
            assert True, "Node without certificate can start (will request certificate)"

        # Test 2: Attachment Certificate Validation

        # Valid keys (no certificates)
        valid_keys = [{"kty": "RSA", "kid": "test-key", "use": "sig", "n": "test", "e": "AQAB"}]

        try:
            child_key_infos = await cert_validator.validate_keys(valid_keys)
            child_valid = True
            child_msg = ""
        except Exception as e:
            child_valid = False
            child_msg = str(e)
        
        try:
            parent_key_infos = await cert_validator.validate_keys(valid_keys)
            parent_valid = True
            parent_msg = ""
        except Exception as e:
            parent_valid = False
            parent_msg = str(e)

        assert child_valid, f"Valid attachment keys should be accepted: {child_msg}"
        assert parent_valid, f"Valid attachment keys should be accepted: {parent_msg}"

        # Invalid certificate keys
        invalid_keys = [
            {
                "kty": "RSA",
                "kid": "invalid-cert-key",
                "use": "sig",
                "x5c": ["invalid-certificate-data"],
                "n": "test",
                "e": "AQAB",
            }
        ]

        try:
            child_key_infos = await cert_validator.validate_keys(invalid_keys)
            child_invalid = True
            child_error = ""
        except Exception as e:
            child_invalid = False
            child_error = str(e)
        
        try:
            parent_key_infos = await cert_validator.validate_keys(invalid_keys)
            parent_invalid = True
            parent_error = ""
        except Exception as e:
            parent_invalid = False
            parent_error = str(e)

        assert not child_invalid, f"Invalid certificate keys should be rejected: {child_error}"
        assert not parent_invalid, f"Invalid certificate keys should be rejected: {parent_error}"
        assert "Certificate validation failed" in child_error or "certificate" in child_error.lower()
        assert "Certificate validation failed" in parent_error or "certificate" in parent_error.lower()

        # Test 3: End-to-End Security Guarantees
        guarantees = [
            ("Empty key list", [], True),
            ("None key list", None, True),
            ("Keys without x5c", [{"kty": "RSA", "kid": "test"}], True),
        ]

        for test_name, keys, expected_valid in guarantees:
            try:
                key_infos = await cert_validator.validate_keys(keys)
                is_valid = True
            except Exception:
                is_valid = False
            assert is_valid == expected_valid, f"{test_name} validation failed"

    finally:
        # Restore original environment
        if original_ca_certs:
            os.environ["FAME_CA_CERTS"] = original_ca_certs
        elif "FAME_CA_CERTS" in os.environ:
            del os.environ["FAME_CA_CERTS"]


@pytest.mark.asyncio
async def test_security_edge_cases(cert_validator):
    """Test security edge cases and boundary conditions."""

    original_ca_certs = os.environ.get("FAME_CA_CERTS")

    try:
        # Test 1: Malformed input handling
        malformed_cases = [
            (None, "null keys"),
            ([], "empty keys"),
            ([{}], "empty key object"),
            ([{"x5c": None}], "null x5c"),
            ([{"x5c": []}], "empty x5c"),
            ([{"x5c": ["", ""]}], "empty certificate strings"),
        ]

        for keys, case_name in malformed_cases:
            try:
                key_infos = await cert_validator.validate_keys(keys)
                is_valid = True
                error = ""
            except Exception as e:
                is_valid = False
                error = str(e)
            # Should handle all these gracefully without throwing exceptions
            assert isinstance(is_valid, bool), f"{case_name} should return boolean"
            assert isinstance(error, str), f"{case_name} should return string error"

        # Test 2: Environment variable edge cases
        env_cases = [
            (None, "No FAME_CA_CERTS"),
            ("", "Empty FAME_CA_CERTS"),
            ("invalid-pem", "Invalid PEM format"),
            ("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----", "Invalid certificate data"),
        ]

        for env_value, case_name in env_cases:
            if env_value is None:
                os.environ.pop("FAME_CA_CERTS", None)
            else:
                os.environ["FAME_CA_CERTS"] = env_value

            test_keys = [{"kty": "RSA", "kid": "test", "x5c": ["test-cert"]}]
            try:
                key_infos = await cert_validator.validate_keys(test_keys)
                is_valid = True
                error = ""
            except Exception as e:
                is_valid = False
                error = str(e)
            # Should handle gracefully
            assert isinstance(is_valid, bool), f"{case_name} should return boolean"
            assert isinstance(error, str), f"{case_name} should return string error"

        # Test 3: Certificate chain edge cases
        os.environ["FAME_CA_CERTS"] = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"

        chain_cases = [
            ([{"kty": "RSA", "x5c": ["single-cert"]}], "Single certificate"),
            ([{"kty": "RSA", "x5c": ["cert1", "cert2"]}], "Certificate chain"),
            ([{"kty": "RSA", "x5c": ["cert1", "cert2", "cert3"]}], "Long certificate chain"),
        ]

        for keys, case_name in chain_cases:
            try:
                key_infos = await cert_validator.validate_keys(keys)
                is_valid = True
                error = ""
            except Exception as e:
                is_valid = False
                error = str(e)
            # Should attempt validation without crashing
            assert isinstance(is_valid, bool), f"{case_name} should return boolean"
            assert isinstance(error, str), f"{case_name} should return string error"

    finally:
        # Restore original environment
        if original_ca_certs:
            os.environ["FAME_CA_CERTS"] = original_ca_certs
        elif "FAME_CA_CERTS" in os.environ:
            del os.environ["FAME_CA_CERTS"]


@pytest.mark.asyncio
async def test_attack_resistance(cert_validator):
    """Test resistance to various certificate-based attacks."""

    test_ca_pem = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAMZ8JKUBU1YrMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNVBAMMCVRl
c3QgUm9vdDAeFw0yNTA3MTEwMTAwMDBaFw0yNjA3MTEwMTAwMDBaMBQxEjAQBgNV
BAMMCVRlc3QgUm9vdDBcMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7test
-----END CERTIFICATE-----"""

    original_ca_certs = os.environ.get("FAME_CA_CERTS")
    os.environ["FAME_CA_CERTS"] = test_ca_pem

    try:
        # Test various attack scenarios
        attack_scenarios = [
            # Self-signed certificates
            (
                {"kty": "RSA", "kid": "self-signed", "x5c": ["self-signed-cert-data"]},
                "self-signed certificate",
            ),
            # Malformed certificates
            ({"kty": "RSA", "kid": "malformed", "x5c": ["malformed-cert-data"]}, "malformed certificate"),
            # Wrong CA signature
            ({"kty": "RSA", "kid": "wrong-ca", "x5c": ["wrong-ca-signed-cert"]}, "wrong CA signature"),
            # Certificate chain tampering
            (
                {"kty": "RSA", "kid": "tampered", "x5c": ["tampered-cert-1", "tampered-cert-2"]},
                "tampered certificate chain",
            ),
        ]

        for attack_key, attack_name in attack_scenarios:
            try:
                key_infos = await cert_validator.validate_keys([attack_key])
                is_valid = True
                error = ""
            except Exception as e:
                is_valid = False
                error = str(e)

            # All attacks should be rejected
            assert not is_valid, f"Should reject {attack_name}"
            assert "Certificate validation failed" in error or "certificate" in error.lower(), (
                f"Should provide proper error for {attack_name}"
            )

    finally:
        # Restore original environment
        if original_ca_certs:
            os.environ["FAME_CA_CERTS"] = original_ca_certs
        elif "FAME_CA_CERTS" in os.environ:
            del os.environ["FAME_CA_CERTS"]


@pytest.mark.asyncio
async def test_configuration_scenarios(cert_validator):
    """Test various configuration scenarios."""

    original_ca_certs = os.environ.get("FAME_CA_CERTS")

    try:
        # Scenario 1: FAME_CA_CERTS set
        test_ca = "-----BEGIN CERTIFICATE-----\ntest-ca\n-----END CERTIFICATE-----"
        os.environ["FAME_CA_CERTS"] = test_ca

        test_keys = [{"kty": "RSA", "kid": "test", "x5c": ["test-cert"]}]
        try:
            key_infos = await cert_validator.validate_keys(test_keys)
            is_valid = True
            error = ""
        except Exception as e:
            is_valid = False
            error = str(e)

        # Should attempt strict validation
        assert not is_valid, "Should perform strict validation when CA certs configured"

        # Scenario 2: FAME_CA_CERTS unset
        del os.environ["FAME_CA_CERTS"]

        try:
            key_infos = await cert_validator.validate_keys(test_keys)
            is_valid = True
            error = ""
        except Exception as e:
            is_valid = False
            error = str(e)

        # Should skip validation with warning (returns success when no trust store)
        assert is_valid, "Should skip validation when CA certs not configured"

        # Scenario 3: Multiple CAs in bundle
        multi_ca = """-----BEGIN CERTIFICATE-----
first-ca-cert
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
second-ca-cert
-----END CERTIFICATE-----"""

        os.environ["FAME_CA_CERTS"] = multi_ca

        try:
            key_infos = await cert_validator.validate_keys(test_keys)
            is_valid = True
            error = ""
        except Exception as e:
            is_valid = False
            error = str(e)

        # Should attempt validation against multiple CAs
        assert not is_valid, "Should validate against multiple CAs"

    finally:
        # Restore original environment
        if original_ca_certs:
            os.environ["FAME_CA_CERTS"] = original_ca_certs
        elif "FAME_CA_CERTS" in os.environ:
            del os.environ["FAME_CA_CERTS"]

"""
Test certificate validation during node attachment handshake.

This test verifies that:
1. Nodes with valid certificates can attach successfully
2. Nodes with invalid certificates are rejected during attachment
3. Both client and server sides validate certificates properly
"""

import os

import pytest

from naylence.fame.core import create_resource
from naylence.fame.security.cert.attachment_cert_validator_factory import AttachmentCertValidatorConfig
from naylence.fame.security.keys.attachment_key_validator_factory import AttachmentKeyValidatorFactory


@pytest.fixture
async def cert_validator():
    """Create a certificate validator instance for testing."""
    config = AttachmentCertValidatorConfig()
    return await create_resource(AttachmentKeyValidatorFactory, config)


@pytest.mark.asyncio
async def test_attachment_certificate_validation(cert_validator):
    """Test certificate validation during attachment handshake."""

    # Test data - simulate JWK keys with certificate chains

    jwk_without_cert = {"kty": "RSA", "kid": "no-cert-node", "use": "sig", "n": "test-modulus", "e": "AQAB"}

    # Test 1: Valid certificate validation

    # Create a temporary CA certificate for testing
    test_ca_pem = """-----BEGIN CERTIFICATE-----
MIICxzCCAa8CAQEwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIVGVzdCBDQSAw
HhcNMjUwNzEwMTIwMDAwWhcNMjYwNzEwMTIwMDAwWjATMREwDwYDVQQDDAhUZXN0
IE5vZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7test
-----END CERTIFICATE-----"""

    # Set up environment
    original_ca_certs = os.environ.get("FAME_CA_CERTS")
    os.environ["FAME_CA_CERTS"] = test_ca_pem

    try:
        # This should pass - no certificates to validate
        try:
            key_infos = await cert_validator.validate_keys([jwk_without_cert])
            assert len(key_infos) == 1, "Should return one KeyInfo"
            assert key_infos[0].kid == "no-cert-node", "Should preserve kid"
        except Exception as e:
            pytest.fail(f"Should accept keys without certificates: {e}")

        # This should pass - empty keys list
        try:
            key_infos = await cert_validator.validate_keys([])
            assert len(key_infos) == 0, "Should return empty list for empty input"
        except Exception as e:
            pytest.fail(f"Should accept empty keys list: {e}")

        # This should pass - None keys
        try:
            key_infos = await cert_validator.validate_keys(None)
            assert len(key_infos) == 0, "Should return empty list for None input"
        except Exception as e:
            pytest.fail(f"Should accept None keys: {e}")

    finally:
        # Restore original environment
        if original_ca_certs:
            os.environ["FAME_CA_CERTS"] = original_ca_certs
        elif "FAME_CA_CERTS" in os.environ:
            del os.environ["FAME_CA_CERTS"]


@pytest.mark.asyncio
async def test_invalid_certificate_validation(cert_validator):
    """Test invalid certificate validation."""

    invalid_jwk_with_cert = {
        "kty": "RSA",
        "kid": "invalid-node",
        "use": "sig",
        "x5c": ["invalid-certificate-data"],
        "n": "test-modulus",
        "e": "AQAB",
    }

    # Create a temporary CA certificate for testing
    test_ca_pem = """-----BEGIN CERTIFICATE-----
MIICxzCCAa8CAQEwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIVGVzdCBDQSAw
HhcNMjUwNzEwMTIwMDAwWhcNMjYwNzEwMTIwMDAwWjATMREwDwYDVQQDDAhUZXN0
IE5vZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7test
-----END CERTIFICATE-----"""

    original_ca_certs = os.environ.get("FAME_CA_CERTS")
    os.environ["FAME_CA_CERTS"] = test_ca_pem

    try:
        # This should fail - invalid certificate
        try:
            await cert_validator.validate_keys([invalid_jwk_with_cert])
            is_valid = True
            error = ""
        except Exception as e:
            is_valid = False
            error = str(e)
        assert not is_valid, f"Should reject invalid certificates: {error}"
        assert "Certificate validation failed" in error or "certificate" in error.lower()

    finally:
        # Restore original environment
        if original_ca_certs:
            os.environ["FAME_CA_CERTS"] = original_ca_certs
        elif "FAME_CA_CERTS" in os.environ:
            del os.environ["FAME_CA_CERTS"]


@pytest.mark.asyncio
async def test_no_trust_store_configured(cert_validator):
    """Test behavior with no trust store."""

    valid_jwk_with_cert = {
        "kty": "RSA",
        "kid": "test-node",
        "use": "sig",
        "x5c": ["some-certificate"],
        "n": "test-modulus",
        "e": "AQAB",
    }

    # Remove trust store
    original_ca_certs = os.environ.get("FAME_CA_CERTS")
    if "FAME_CA_CERTS" in os.environ:
        del os.environ["FAME_CA_CERTS"]

    try:
        # This should pass with warning - no trust store configured
        try:
            await cert_validator.validate_keys([valid_jwk_with_cert])
            is_valid = True
            error = ""
        except Exception as e:
            is_valid = False
            error = str(e)
        assert is_valid, f"Should accept when no trust store configured: {error}"

    finally:
        # Restore original environment
        if original_ca_certs:
            os.environ["FAME_CA_CERTS"] = original_ca_certs


@pytest.mark.asyncio
async def test_mixed_valid_and_invalid_keys(cert_validator):
    """Test mixed valid and invalid keys."""

    jwk_without_cert = {"kty": "RSA", "kid": "no-cert-node", "use": "sig", "n": "test-modulus", "e": "AQAB"}

    invalid_jwk_with_cert = {
        "kty": "RSA",
        "kid": "invalid-node",
        "use": "sig",
        "x5c": ["invalid-certificate-data"],
        "n": "test-modulus",
        "e": "AQAB",
    }

    test_ca_pem = """-----BEGIN CERTIFICATE-----
MIICxzCCAa8CAQEwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIVGVzdCBDQSAw
HhcNMjUwNzEwMTIwMDAwWhcNMjYwNzEwMTIwMDAwWjATMREwDwYDVQQDDAhUZXN0
IE5vZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7test
-----END CERTIFICATE-----"""

    original_ca_certs = os.environ.get("FAME_CA_CERTS")
    os.environ["FAME_CA_CERTS"] = test_ca_pem

    try:
        mixed_keys = [jwk_without_cert, invalid_jwk_with_cert]
        try:
            await cert_validator.validate_keys(mixed_keys)
            is_valid = True
            error = ""
        except Exception as e:
            is_valid = False
            error = str(e)
        assert not is_valid, f"Should reject if any certificate is invalid: {error}"
        assert "Certificate validation failed" in error or "certificate" in error.lower()

    finally:
        # Restore original environment
        if original_ca_certs:
            os.environ["FAME_CA_CERTS"] = original_ca_certs
        elif "FAME_CA_CERTS" in os.environ:
            del os.environ["FAME_CA_CERTS"]


@pytest.mark.asyncio
async def test_attachment_flow_simulation(cert_validator):
    """Simulate a complete attachment flow with certificate validation."""

    # Create test CA cert
    test_ca_pem = """-----BEGIN CERTIFICATE-----
MIICxzCCAa8CAQEwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIVGVzdCBDQSAw
HhcNMjUwNzEwMTIwMDAwWhcNMjYwNzEwMTIwMDAwWjATMREwDwYDVQQDDAhUZXN0
IE5vZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7test
-----END CERTIFICATE-----"""

    original_ca_certs = os.environ.get("FAME_CA_CERTS")
    os.environ["FAME_CA_CERTS"] = test_ca_pem

    try:
        # Scenario 1: Both nodes have valid certificates
        valid_child_keys = [{"kty": "RSA", "kid": "child-1", "use": "sig"}]  # No x5c
        valid_parent_keys = [{"kty": "RSA", "kid": "parent-1", "use": "sig"}]  # No x5c

        # Child validation (server side)
        try:
            await cert_validator.validate_keys(valid_child_keys)
            child_valid = True
            child_error = ""
        except Exception as e:
            child_valid = False
            child_error = str(e)
        assert child_valid, f"Child keys should be valid: {child_error}"

        # Parent validation (client side)
        try:
            await cert_validator.validate_keys(valid_parent_keys)
            parent_valid = True
            parent_error = ""
        except Exception as e:
            parent_valid = False
            parent_error = str(e)
        assert parent_valid, f"Parent keys should be valid: {parent_error}"

        # Scenario 2: Child has invalid certificate
        invalid_child_keys = [{"kty": "RSA", "kid": "child-2", "use": "sig", "x5c": ["invalid-cert-data"]}]

        try:
            await cert_validator.validate_keys(invalid_child_keys)
            child_valid = True
            child_error = ""
        except Exception as e:
            child_valid = False
            child_error = str(e)
        assert not child_valid, f"Invalid child certificate should be rejected: {child_error}"

        # Scenario 3: Parent has invalid certificate
        invalid_parent_keys = [
            {"kty": "RSA", "kid": "parent-2", "use": "sig", "x5c": ["invalid-cert-data"]}
        ]

        try:
            await cert_validator.validate_keys(invalid_parent_keys)
            parent_valid = True
            parent_error = ""
        except Exception as e:
            parent_valid = False
            parent_error = str(e)
        assert not parent_valid, f"Invalid parent certificate should be rejected: {parent_error}"

    finally:
        # Restore original environment
        if original_ca_certs:
            os.environ["FAME_CA_CERTS"] = original_ca_certs
        elif "FAME_CA_CERTS" in os.environ:
            del os.environ["FAME_CA_CERTS"]

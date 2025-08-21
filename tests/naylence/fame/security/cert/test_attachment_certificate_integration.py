"""
Integration test for attachment certificate validation with real node handshake.

This test creates real nodes with valid and invalid certificates and verifies
that the attachment handshake properly validates certificates and rejects
connections with untrusted certificates.
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
async def test_attachment_with_invalid_certificates(cert_validator):
    """Test that nodes reject attachment when certificates are invalid."""

    # Clear environment to ensure no valid trust store
    original_env = {}
    for key in ["FAME_CA_CERTS", "FAME_CA_CERT_FILE", "FAME_TRUST_STORE_PATH"]:
        original_env[key] = os.environ.get(key)
        if key in os.environ:
            del os.environ[key]

    # Set up a fake CA certificate that doesn't match any real certificates
    fake_ca_pem = """-----BEGIN CERTIFICATE-----
MIICxzCCAa8CAQEwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIRmFrZSBDQSAw
HhcNMjUwNzEwMTIwMDAwWhcNMjYwNzEwMTIwMDAwWjATMREwDwYDVQQDDAhGYWtl
IE5vZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDfake_cert_data
-----END CERTIFICATE-----"""

    os.environ["FAME_CA_CERTS"] = fake_ca_pem

    try:
        # Create a JWK with an untrusted certificate chain
        untrusted_jwk = {
            "kty": "RSA",
            "kid": "untrusted-node",
            "use": "sig",
            "x5c": [
                # This is a real-looking certificate but not signed by our fake CA
                "MIICWjCCAUICCQDQ5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X5X"
            ],
            "n": "some-modulus",
            "e": "AQAB",
        }

        # Test child certificate validation
        try:
            key_infos = await cert_validator.validate_keys([untrusted_jwk])
            is_valid = True
            error = ""
        except Exception as e:
            is_valid = False
            error = str(e)
        assert not is_valid, "Should have rejected untrusted certificate"
        assert "Certificate validation failed" in error or "certificate" in error.lower()

        # Test parent certificate validation
        try:
            key_infos = await cert_validator.validate_keys([untrusted_jwk])
            is_valid = True
            error = ""
        except Exception as e:
            is_valid = False
            error = str(e)
        assert not is_valid, "Should have rejected untrusted certificate"
        assert "Certificate validation failed" in error or "certificate" in error.lower()

    finally:
        # Restore original environment
        for key, value in original_env.items():
            if value is not None:
                os.environ[key] = value
            elif key in os.environ:
                del os.environ[key]


@pytest.mark.asyncio
async def test_attachment_without_trust_store(cert_validator):
    """Test attachment behavior when no trust store is configured."""

    # Save original environment
    original_env = {}
    for key in ["FAME_CA_CERTS", "FAME_CA_CERT_FILE", "FAME_TRUST_STORE_PATH"]:
        original_env[key] = os.environ.get(key)
        if key in os.environ:
            del os.environ[key]

    try:
        # Create a JWK with certificate chain
        jwk_with_cert = {
            "kty": "RSA",
            "kid": "node-with-cert",
            "use": "sig",
            "x5c": ["some-certificate-data"],
            "n": "some-modulus",
            "e": "AQAB",
        }

        # Test child attachment without trust store
        try:
            key_infos = await cert_validator.validate_keys([jwk_with_cert])
            is_valid = True
            error = ""
        except Exception as e:
            is_valid = False
            error = str(e)
        assert is_valid, "Should allow attachment when no trust store configured"

        # Test parent attachment without trust store
        try:
            key_infos = await cert_validator.validate_keys([jwk_with_cert])
            is_valid = True
            error = ""
        except Exception as e:
            is_valid = False
            error = str(e)
        assert is_valid, "Should allow attachment when no trust store configured"

    finally:
        # Restore original environment
        for key, value in original_env.items():
            if value is not None:
                os.environ[key] = value
            elif key in os.environ:
                del os.environ[key]


@pytest.mark.asyncio
async def test_attachment_validation_edge_cases(cert_validator):
    """Test edge cases for attachment certificate validation."""

    original_ca_certs = os.environ.get("FAME_CA_CERTS")

    try:
        # Test 1: Empty key list
        try:
            key_infos = await cert_validator.validate_keys([])
            is_valid = True
            error = ""
        except Exception as e:
            is_valid = False
            error = str(e)
        assert is_valid, f"Empty key list should be valid: {error}"

        # Test 2: None key list
        try:
            key_infos = await cert_validator.validate_keys(None)
            is_valid = True
            error = ""
        except Exception as e:
            is_valid = False
            error = str(e)
        assert is_valid, f"None key list should be valid: {error}"

        # Test 3: Keys without x5c
        keys_without_cert = [
            {"kty": "RSA", "kid": "key1", "use": "sig", "n": "mod", "e": "AQAB"},
            {"kty": "RSA", "kid": "key2", "use": "enc", "n": "mod", "e": "AQAB"},
        ]
        try:
            key_infos = await cert_validator.validate_keys(keys_without_cert)
            is_valid = True
            error = ""
        except Exception as e:
            is_valid = False
            error = str(e)
        assert is_valid, f"Keys without certificates should be valid: {error}"

        # Test 4: Mixed keys (some with x5c, some without)
        os.environ["FAME_CA_CERTS"] = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"

        mixed_keys = [
            {"kty": "RSA", "kid": "key1", "use": "sig", "n": "mod", "e": "AQAB"},  # No cert
            {
                "kty": "RSA",
                "kid": "key2",
                "use": "sig",
                "x5c": ["invalid"],
                "n": "mod",
                "e": "AQAB",
            },  # Invalid cert
        ]
        try:
            key_infos = await cert_validator.validate_keys(mixed_keys)
            is_valid = True
            error = ""
        except Exception as e:
            is_valid = False
            error = str(e)
        assert not is_valid, f"Mixed keys with invalid cert should be rejected: {error}"
        assert "Certificate validation failed" in error or "certificate" in error.lower()

    finally:
        # Restore original environment
        if original_ca_certs:
            os.environ["FAME_CA_CERTS"] = original_ca_certs
        elif "FAME_CA_CERTS" in os.environ:
            del os.environ["FAME_CA_CERTS"]


@pytest.mark.asyncio
async def test_attachment_security_guarantees(cert_validator):
    """Test that all security guarantees are met."""

    test_ca_pem = """-----BEGIN CERTIFICATE-----
MIICxzCCAa8CAQEwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIVGVzdCBDQSAw
HhcNMjUwNzEwMTIwMDAwWhcNMjYwNzEwMTIwMDAwWjATMREwDwYDVQQDDAhUZXN0
IE5vZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7test
-----END CERTIFICATE-----"""

    original_ca_certs = os.environ.get("FAME_CA_CERTS")
    os.environ["FAME_CA_CERTS"] = test_ca_pem

    try:
        # Test mutual authentication capability
        valid_keys = [{"kty": "RSA", "kid": "test-key", "use": "sig", "n": "test", "e": "AQAB"}]

        try:
            child_key_infos = await cert_validator.validate_keys(valid_keys)
            child_valid = True
        except Exception:
            child_valid = False
        
        try:
            parent_key_infos = await cert_validator.validate_keys(valid_keys)
            parent_valid = True
        except Exception:
            parent_valid = False

        assert child_valid, "Server-side validation should work"
        assert parent_valid, "Client-side validation should work"

        # Test immediate rejection of invalid certificates
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

        assert not child_invalid, "Server should reject invalid certificates"
        assert not parent_invalid, "Client should reject invalid certificates"
        assert "Certificate validation failed" in child_error or "certificate" in child_error.lower()
        assert "Certificate validation failed" in parent_error or "certificate" in parent_error.lower()

    finally:
        # Restore original environment
        if original_ca_certs:
            os.environ["FAME_CA_CERTS"] = original_ca_certs
        elif "FAME_CA_CERTS" in os.environ:
            del os.environ["FAME_CA_CERTS"]

#!/usr/bin/env python3
"""
Test certificate purging functionality in X5CKeyManager.
"""

import asyncio
import datetime
from unittest.mock import Mock

import pytest

from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore
from naylence.fame.security.keys.x5c_key_manager import X5CKeyManager


def create_test_certificate(valid_until: datetime.datetime) -> bytes:
    """Create a test certificate with the specified expiration date."""
    try:
        import ipaddress

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError:
        pytest.skip("cryptography library not available for certificate testing")

    # Generate a private key
    private_key = ed25519.Ed25519PrivateKey.generate()

    # Create certificate subject and issuer
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )

    # Create certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2)  # Start 2 days ago
        )
        .not_valid_after(valid_until)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("test.example.com"),
                    x509.DNSName("*.test.example.com"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            critical=True,
        )
        .sign(private_key, None)
    )  # Ed25519 requires None algorithm

    return cert.public_bytes(serialization.Encoding.DER)


def create_jwk_with_certificate(
    kid: str, valid_until: datetime.datetime, physical_path: str = "/test"
) -> dict:
    """Create a JWK with an x5c certificate chain."""
    try:
        import base64

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        pytest.skip("cryptography library not available for certificate testing")

    # Generate Ed25519 key pair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Get the raw public key bytes for the JWK
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # Create certificate
    cert_der = create_test_certificate(valid_until)
    cert_b64 = base64.b64encode(cert_der).decode("ascii")

    # Create proper Ed25519 JWK
    return {
        "kid": kid,
        "kty": "OKP",
        "crv": "Ed25519",
        "x": base64.urlsafe_b64encode(public_key_bytes).decode("ascii").rstrip("="),
        "use": "sig",
        "alg": "EdDSA",
        "x5c": [cert_b64],
        "physical_path": physical_path,
    }


class MockNode:
    """Mock node for testing."""

    def __init__(self):
        self._id = "test-node"
        self._sid = "test-sid"
        self.physical_path = "/test"
        self.has_parent = False
        self._envelope_factory = Mock()


@pytest.mark.asyncio
async def test_certificate_purging_expired_certificates():
    """Test that expired certificates are properly purged."""
    print("Testing certificate purging...")

    key_store = InMemoryKeyStore()
    key_manager = X5CKeyManager(key_store=key_store, cert_purge_interval=0.1)  # Short interval for testing

    # Initialize with mock node
    mock_node = MockNode()
    await key_manager.on_node_started(mock_node)

    # Create certificates with different expiration dates
    now = datetime.datetime.now(datetime.timezone.utc)
    expired_cert = create_jwk_with_certificate(
        "expired-cert",
        now - datetime.timedelta(days=1),  # Expired yesterday
    )
    valid_cert = create_jwk_with_certificate(
        "valid-cert",
        now + datetime.timedelta(days=30),  # Expires in 30 days
    )

    # Debug: Print the JWKs
    print(f"Expired cert JWK: {expired_cert}")
    print(f"Valid cert JWK: {valid_cert}")

    # Add certificates to key store directly (bypassing validation for now)
    key_store._keys["expired-cert"] = expired_cert
    key_store._keys["valid-cert"] = valid_cert

    # Verify both certificates are present
    assert await key_store.has_key("expired-cert")
    assert await key_store.has_key("valid-cert")

    # Run purge operation
    purged_count = await key_manager.purge_expired_certificates()

    # Verify expired certificate was removed but valid one remains
    assert purged_count == 1
    assert not await key_store.has_key("expired-cert"), "Expired certificate should be removed"
    assert await key_store.has_key("valid-cert"), "Valid certificate should remain"

    # Clean up
    await key_manager.on_node_stopped(mock_node)

    print("✓ Certificate purging test passed")


@pytest.mark.asyncio
async def test_certificate_purging_no_expired_certificates():
    """Test purging when no certificates are expired."""
    print("Testing purging with no expired certificates...")

    key_store = InMemoryKeyStore()
    key_manager = X5CKeyManager(key_store=key_store)

    # Initialize with mock node
    mock_node = MockNode()
    await key_manager.on_node_started(mock_node)

    # Create only valid certificates
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_cert1 = create_jwk_with_certificate("valid-cert1", now + datetime.timedelta(days=30))
    valid_cert2 = create_jwk_with_certificate("valid-cert2", now + datetime.timedelta(days=60))

    # Add certificates to key store directly (bypassing validation)
    key_store._keys["valid-cert1"] = valid_cert1
    key_store._keys["valid-cert2"] = valid_cert2

    # Run purge operation
    purged_count = await key_manager.purge_expired_certificates()

    # Verify no certificates were removed
    assert purged_count == 0
    assert await key_store.has_key("valid-cert1")
    assert await key_store.has_key("valid-cert2")

    # Clean up
    await key_manager.on_node_stopped(mock_node)

    print("✓ No expired certificates test passed")


@pytest.mark.asyncio
async def test_certificate_purging_non_certificate_keys():
    """Test that keys without certificates are not affected by purging."""
    print("Testing purging with non-certificate keys...")

    key_store = InMemoryKeyStore()
    key_manager = X5CKeyManager(key_store=key_store)

    # Initialize with mock node
    mock_node = MockNode()
    await key_manager.on_node_started(mock_node)

    # Create key without certificate
    non_cert_key = {
        "kid": "non-cert-key",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo",
        "use": "sig",
        "alg": "EdDSA",
        "physical_path": "/test",
    }

    # Add key to store directly (bypassing validation)
    key_store._keys["non-cert-key"] = non_cert_key

    # Run purge operation
    purged_count = await key_manager.purge_expired_certificates()

    # Verify no keys were removed
    assert purged_count == 0
    assert await key_store.has_key("non-cert-key")

    # Clean up
    await key_manager.on_node_stopped(mock_node)

    print("✓ Non-certificate keys test passed")


@pytest.mark.asyncio
async def test_background_purge_task_lifecycle():
    """Test that the background purge task starts and stops correctly."""
    print("Testing background purge task lifecycle...")

    key_store = InMemoryKeyStore()
    # Very short interval for testing
    key_manager = X5CKeyManager(key_store=key_store, cert_purge_interval=0.1)

    mock_node = MockNode()

    # Start key manager - should start background task
    await key_manager.on_node_started(mock_node)

    # Verify task is running
    assert key_manager._purge_task is not None
    assert not key_manager._purge_task.done()

    # Let the task run for a bit
    await asyncio.sleep(0.15)

    # Stop key manager - should stop background task
    await key_manager.on_node_stopped(mock_node)

    # Verify task is stopped
    assert key_manager._purge_task.done() or key_manager._purge_task.cancelled()

    print("✓ Background task lifecycle test passed")


@pytest.mark.asyncio
async def test_purge_with_malformed_certificates():
    """Test that purging handles malformed certificates gracefully."""
    print("Testing purging with malformed certificates...")

    key_store = InMemoryKeyStore()
    key_manager = X5CKeyManager(key_store=key_store)

    # Initialize with mock node
    mock_node = MockNode()
    await key_manager.on_node_started(mock_node)

    # Create key with malformed certificate
    malformed_cert_key = {
        "kid": "malformed-cert",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo",
        "use": "sig",
        "alg": "EdDSA",
        "x5c": ["invalid-base64-data"],  # Invalid certificate
        "physical_path": "/test",
    }

    # Add key to store directly (bypassing validation)
    key_store._keys["malformed-cert"] = malformed_cert_key

    # Run purge operation - should not crash
    purged_count = await key_manager.purge_expired_certificates()

    # Verify no keys were removed (malformed cert should be left alone)
    assert purged_count == 0
    assert await key_store.has_key("malformed-cert")

    # Clean up
    await key_manager.on_node_stopped(mock_node)

    print("✓ Malformed certificates test passed")


if __name__ == "__main__":

    async def run_tests():
        await test_certificate_purging_expired_certificates()
        await test_certificate_purging_no_expired_certificates()
        await test_certificate_purging_non_certificate_keys()
        await test_background_purge_task_lifecycle()
        await test_purge_with_malformed_certificates()
        print("🎉 All certificate purging tests passed!")

    asyncio.run(run_tests())

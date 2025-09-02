"""
Test helpers for CA-related functionality.

This module provides helper functions and classes to support testing
when the crypto provider's deprecated CA methods are not available
or when we need to work around compatibility issues.
"""

import os
import tempfile
from typing import Tuple

from naylence.fame.security.cert.internal_ca_service import CASigningService, create_test_ca


class TestCryptoProviderHelper:
    """Helper class to provide CA functionality for testing."""

    @staticmethod
    def create_crypto_provider_with_ca_pems(ca_cert_pem: str, ca_key_pem: str, **kwargs):
        """
        Create a crypto provider with CA credentials and ensure it can generate certificates.

        Args:
            ca_cert_pem: CA certificate as PEM string
            ca_key_pem: CA private key as PEM string
            **kwargs: Additional arguments for DefaultCryptoProvider

        Returns:
            Configured crypto provider instance
        """
        from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider

        # Create provider
        provider = DefaultCryptoProvider(**kwargs)

        # Store CA credentials for later use (use setattr to avoid type checker issues)
        setattr(provider, "_test_ca_cert_pem", ca_cert_pem)
        setattr(provider, "_test_ca_key_pem", ca_key_pem)

        # Monkey patch the deprecated methods if they exist
        if hasattr(provider, "_get_ca_credentials"):
            provider._get_ca_credentials = lambda: (ca_cert_pem, ca_key_pem)  # type: ignore

        return provider

    @staticmethod
    def create_crypto_provider_with_ca_files(ca_cert_file: str, ca_key_file: str, **kwargs):
        """
        Create a crypto provider with CA files and ensure it can generate certificates.

        Args:
            ca_cert_file: Path to CA certificate file
            ca_key_file: Path to CA private key file
            **kwargs: Additional arguments for DefaultCryptoProvider

        Returns:
            Configured crypto provider instance
        """
        # Read the files
        with open(ca_cert_file) as f:
            ca_cert_pem = f.read()
        with open(ca_key_file) as f:
            ca_key_pem = f.read()

        return TestCryptoProviderHelper.create_crypto_provider_with_ca_pems(
            ca_cert_pem, ca_key_pem, **kwargs
        )

    @staticmethod
    def ensure_test_certificate(provider, force_regenerate: bool = False):
        """
        Ensure the provider has a valid certificate for testing.

        Args:
            provider: The crypto provider instance
            force_regenerate: Whether to force regeneration even if cert exists

        Returns:
            Generated certificate PEM string or None
        """
        # Check if certificate already exists
        if not force_regenerate and hasattr(provider, "node_certificate_pem"):
            existing_cert = provider.node_certificate_pem()
            if existing_cert:
                return existing_cert

        # Check if we have test CA credentials
        ca_cert_pem = getattr(provider, "_test_ca_cert_pem", None)
        ca_key_pem = getattr(provider, "_test_ca_key_pem", None)

        # If no CA credentials, create test CA
        if not ca_cert_pem or not ca_key_pem:
            ca_cert_pem, ca_key_pem = create_test_ca()
            setattr(provider, "_test_ca_cert_pem", ca_cert_pem)
            setattr(provider, "_test_ca_key_pem", ca_key_pem)

        # Get certificate context
        if not hasattr(provider, "_cert_context") or not provider._cert_context:
            raise ValueError("Provider must have node context set before generating certificate")

        # Generate certificate using CA service
        ca_service = CASigningService(ca_cert_pem, ca_key_pem)

        cert_pem = ca_service.sign_node_cert(
            public_key_pem=provider._signature_public_pem,
            node_id=provider._cert_context["node_id"],
            node_sid=provider._cert_context["node_sid"],
            physical_path=provider._cert_context["physical_path"],
            logicals=provider._cert_context["logicals"],
        )

        # Store the certificate
        if hasattr(provider, "store_signed_certificate"):
            provider.store_signed_certificate(cert_pem)
        else:
            # Fallback: store directly
            setattr(provider, "_node_cert_pem", cert_pem)

        return cert_pem

    @staticmethod
    def create_crypto_provider_with_env_ca(**kwargs):
        """
        Create a crypto provider using CA from environment variables.

        Args:
            **kwargs: Additional arguments for DefaultCryptoProvider

        Returns:
            Configured crypto provider instance
        """
        ca_cert_file = os.environ.get("FAME_CA_CERT_FILE")
        ca_key_file = os.environ.get("FAME_CA_KEY_FILE")

        if ca_cert_file and ca_key_file and os.path.exists(ca_cert_file) and os.path.exists(ca_key_file):
            try:
                return TestCryptoProviderHelper.create_crypto_provider_with_ca_files(
                    ca_cert_file, ca_key_file, **kwargs
                )
            except Exception:
                # Fall back to test CA if files can't be read
                pass

        # Fall back to test CA
        ca_cert_pem, ca_key_pem = create_test_ca()
        return TestCryptoProviderHelper.create_crypto_provider_with_ca_pems(
            ca_cert_pem, ca_key_pem, **kwargs
        )


def create_temp_ca_files() -> Tuple[str, str, str, str]:
    """
    Create temporary CA files for testing.

    Returns:
        Tuple of (ca_cert_pem, ca_key_pem, cert_file_path, key_file_path)
    """
    ca_cert_pem, ca_key_pem = create_test_ca()

    # Create temporary files
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as cert_file:
        cert_file.write(ca_cert_pem)
        cert_file_path = cert_file.name

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as key_file:
        key_file.write(ca_key_pem)
        key_file_path = key_file.name

    return ca_cert_pem, ca_key_pem, cert_file_path, key_file_path


def cleanup_temp_files(*file_paths: str) -> None:
    """
    Clean up temporary files.

    Args:
        *file_paths: Paths to files to delete
    """
    for file_path in file_paths:
        try:
            if file_path and os.path.exists(file_path):
                os.unlink(file_path)
        except Exception:
            pass  # Ignore cleanup errors


# Compatibility function to replace deprecated methods
def get_ca_credentials() -> Tuple[str, str]:
    """
    Get CA credentials for testing.

    Returns:
        Tuple of (ca_cert_pem, ca_key_pem)
    """
    return create_test_ca()


# Helper to create working crypto provider
def create_working_crypto_provider(**kwargs):
    """
    Create a crypto provider that will work for certificate generation in tests.

    Args:
        **kwargs: Additional arguments for DefaultCryptoProvider

    Returns:
        Working crypto provider instance
    """
    ca_cert_pem, ca_key_pem = create_test_ca()
    return TestCryptoProviderHelper.create_crypto_provider_with_ca_pems(ca_cert_pem, ca_key_pem, **kwargs)

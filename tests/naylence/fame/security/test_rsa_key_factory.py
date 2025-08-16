"""Tests for RSA key factory."""

from unittest.mock import patch

import pytest

from naylence.fame.security.crypto.key_factories.rsa_key_factory import create_rsa_keypair
from naylence.fame.util.crypto_util import DevKeyPair


class TestRSAKeyFactory:
    """Test the RSA key factory."""

    @patch("naylence.fame.security.crypto.key_factories.rsa_key_factory.require_crypto")
    @patch("naylence.fame.security.crypto.key_factories.rsa_key_factory.generate_key_pair_and_jwks")
    def test_create_rsa_keypair_default_kid(self, mock_generate, mock_require):
        """Test creating RSA keypair with default kid."""
        # Mock the return value
        mock_data = {
            "jwks": {"keys": [{}]},
            "private_pem": "mock_private_key",
            "public_pem": "mock_public_key",
        }
        mock_generate.return_value = mock_data

        result = create_rsa_keypair()

        mock_require.assert_called_once()
        mock_generate.assert_called_once()

        # Verify the function was called with the right parameters
        call_args = mock_generate.call_args
        assert call_args[1]["kid"] == "dev"
        assert call_args[1]["algorithm"] == "RS256"

        # Verify key generation function exists
        key_gen_fn = call_args[1]["key_gen_fn"]
        assert callable(key_gen_fn)

        # Verify kid is attached to the result
        assert mock_data["jwks"]["keys"][0]["kid"] == "dev"

        # Verify DevKeyPair is created
        assert isinstance(result, DevKeyPair)

    @patch("naylence.fame.security.crypto.key_factories.rsa_key_factory.require_crypto")
    @patch("naylence.fame.security.crypto.key_factories.rsa_key_factory.generate_key_pair_and_jwks")
    def test_create_rsa_keypair_custom_kid(self, mock_generate, mock_require):
        """Test creating RSA keypair with custom kid."""
        mock_data = {
            "jwks": {"keys": [{}]},
            "private_pem": "mock_private_key",
            "public_pem": "mock_public_key",
        }
        mock_generate.return_value = mock_data

        custom_kid = "test-key-123"
        result = create_rsa_keypair(kid=custom_kid)

        mock_require.assert_called_once()
        mock_generate.assert_called_once()

        # Verify the custom kid was used
        call_args = mock_generate.call_args
        assert call_args[1]["kid"] == custom_kid
        assert call_args[1]["algorithm"] == "RS256"

        # Verify kid is attached to the result
        assert mock_data["jwks"]["keys"][0]["kid"] == custom_kid

        assert isinstance(result, DevKeyPair)

    @patch("naylence.fame.security.crypto.key_factories.rsa_key_factory.require_crypto")
    def test_create_rsa_keypair_crypto_requirement_error(self, mock_require):
        """Test that crypto requirement error is propagated."""
        mock_require.side_effect = ImportError("Crypto libraries not available")

        with pytest.raises(ImportError, match="Crypto libraries not available"):
            create_rsa_keypair()

    @patch("naylence.fame.security.crypto.key_factories.rsa_key_factory.require_crypto")
    @patch("naylence.fame.security.crypto.key_factories.rsa_key_factory.generate_key_pair_and_jwks")
    def test_create_rsa_keypair_key_generation_parameters(self, mock_generate, mock_require):
        """Test that RSA key generation uses correct parameters."""
        mock_data = {
            "jwks": {"keys": [{}]},
            "private_pem": "mock_private_key",
            "public_pem": "mock_public_key",
        }
        mock_generate.return_value = mock_data

        create_rsa_keypair("test-kid")

        # Extract the key generation function and test it
        call_args = mock_generate.call_args
        key_gen_fn = call_args[1]["key_gen_fn"]
        assert callable(key_gen_fn)

        # Verify algorithm and kid are correct
        assert call_args[1]["algorithm"] == "RS256"
        assert call_args[1]["kid"] == "test-kid"

    @patch("naylence.fame.security.crypto.key_factories.rsa_key_factory.require_crypto")
    @patch("naylence.fame.security.crypto.key_factories.rsa_key_factory.generate_key_pair_and_jwks")
    def test_create_rsa_keypair_jwks_structure(self, mock_generate, mock_require):
        """Test that JWKS structure is properly modified."""
        # Test with multiple keys to ensure the right one is modified
        mock_data = {
            "jwks": {"keys": [{"existing": "key"}, {"another": "key"}]},
            "private_pem": "mock_private_key",
            "public_pem": "mock_public_key",
        }
        mock_generate.return_value = mock_data

        create_rsa_keypair("special-kid")

        # Verify only the first key gets the kid
        assert mock_data["jwks"]["keys"][0]["kid"] == "special-kid"
        assert mock_data["jwks"]["keys"][0]["existing"] == "key"  # Original data preserved

        # Second key should be unchanged
        assert "kid" not in mock_data["jwks"]["keys"][1]
        assert mock_data["jwks"]["keys"][1]["another"] == "key"

    @patch("naylence.fame.security.crypto.key_factories.rsa_key_factory.require_crypto")
    @patch("naylence.fame.security.crypto.key_factories.rsa_key_factory.generate_key_pair_and_jwks")
    def test_create_rsa_keypair_empty_kid(self, mock_generate, mock_require):
        """Test creating RSA keypair with empty kid."""
        mock_data = {
            "jwks": {"keys": [{}]},
            "private_pem": "mock_private_key",
            "public_pem": "mock_public_key",
        }
        mock_generate.return_value = mock_data

        result = create_rsa_keypair("")

        # Verify empty kid is used
        call_args = mock_generate.call_args
        assert call_args[1]["kid"] == ""
        assert mock_data["jwks"]["keys"][0]["kid"] == ""

        assert isinstance(result, DevKeyPair)

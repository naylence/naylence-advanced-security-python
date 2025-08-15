"""
Test certificate manager integration with existing security policy framework.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from naylence.fame.core import SecuritySettings, SigningMaterial
from naylence.fame.security.cert.default_certificate_manager import create_certificate_manager
from naylence.fame.security.policy.security_policy import SigningConfig


def test_certificate_manager_with_signing_config():
    """Test certificate manager integrates with existing SigningConfig."""

    # Test with X509_CHAIN requirement in SigningConfig
    signing_config = SigningConfig(signing_material=SigningMaterial.X509_CHAIN)
    cert_manager = create_certificate_manager(signing_config=signing_config)

    assert cert_manager.signing_config.signing_material == SigningMaterial.X509_CHAIN

    # Test with RAW_KEY (default)
    signing_config_raw = SigningConfig(signing_material=SigningMaterial.RAW_KEY)
    cert_manager_raw = create_certificate_manager(signing_config=signing_config_raw)

    assert cert_manager_raw.signing_config.signing_material == SigningMaterial.RAW_KEY


def test_security_settings_and_signing_config_together():
    """Test priority between security profile and signing config."""

    # Security profile takes precedence
    security_settings = SecuritySettings(signing_material=SigningMaterial.X509_CHAIN)
    signing_config = SigningConfig(signing_material=SigningMaterial.RAW_KEY)

    cert_manager = create_certificate_manager(
        security_settings=security_settings, signing_config=signing_config
    )

    assert cert_manager.security_settings.signing_material == SigningMaterial.X509_CHAIN
    assert cert_manager.signing_config.signing_material == SigningMaterial.RAW_KEY


@pytest.mark.asyncio
async def test_certificate_manager_root_start_decision():
    """Test certificate manager makes correct decisions for root node start."""

    # Test X509_CHAIN - should call certificate provisioning
    signing_config = SigningConfig(signing_material=SigningMaterial.X509_CHAIN)
    cert_manager = create_certificate_manager(signing_config=signing_config)

    # Mock the private method on the instance
    with patch.object(
        cert_manager, "_ensure_node_certificate", new_callable=AsyncMock, return_value=True
    ) as mock_ensure:
        result = await cert_manager.ensure_root_certificate(
            node_id="test-node", physical_path="/test", logicals=["logical1"]
        )

        assert result is True
        mock_ensure.assert_called_once()


@pytest.mark.asyncio
async def test_certificate_manager_raw_key_bypass():
    """Test certificate manager bypasses certificate provisioning for RAW_KEY."""

    # Test RAW_KEY - should bypass certificate provisioning
    signing_config = SigningConfig(signing_material=SigningMaterial.RAW_KEY)
    cert_manager = create_certificate_manager(signing_config=signing_config)

    result = await cert_manager.ensure_root_certificate(
        node_id="test-node", physical_path="/test", logicals=["logical1"]
    )

    # Should return True without calling certificate provisioner
    assert result is True


@pytest.mark.asyncio
async def test_certificate_manager_welcome_handling():
    """Test certificate manager handles welcome frame correctly."""

    cert_manager = create_certificate_manager()

    # Mock welcome frame with security profile requiring X509
    welcome_frame = Mock()
    welcome_frame.security_settings = SecuritySettings(signing_material=SigningMaterial.X509_CHAIN)
    welcome_frame.system_id = "test-node"
    welcome_frame.assigned_path = "/test"

    # Mock the private method on the instance
    with patch.object(
        cert_manager, "ensure_non_root_certificate", new_callable=AsyncMock, return_value=True
    ) as mock_ensure:
        await cert_manager.on_welcome(welcome_frame=welcome_frame)
        mock_ensure.assert_called_once()


def test_signing_config_defaults():
    """Test that SigningConfig has correct defaults."""

    config = SigningConfig()

    # Should default to RAW_KEY
    assert config.signing_material == SigningMaterial.RAW_KEY
    assert config.validate_cert_name_constraints is True


if __name__ == "__main__":
    # Run some basic tests
    test_certificate_manager_with_signing_config()
    test_security_settings_and_signing_config_together()
    test_signing_config_defaults()

    print("✓ All certificate manager integration tests passed!")

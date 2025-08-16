"""
Test for CertificateManager factory and resource framework integration.
"""

import pytest

from naylence.fame.core import ExtensionManager, SecuritySettings, SigningMaterial, create_resource
from naylence.fame.security.cert.certificate_manager_factory import (
    CertificateManagerFactory,
)
from naylence.fame.security.cert.default_certificate_manager_factory import (
    DefaultCertificateManagerConfig,
    DefaultCertificateManagerFactory,
)
from naylence.fame.security.policy.security_policy import SigningConfig


@pytest.mark.asyncio
async def test_certificate_manager_factory_with_resource_factory(, SigningMaterial):
    """Test CertificateManagerFactory with create_resource."""
    print("Testing CertificateManagerFactory with resource framework...")

    # Initialize the extension manager for CertificateManagerFactory
    ExtensionManager.lazy_init(
        group="naylence.CertificateManagerFactory", base_type=CertificateManagerFactory
    )

    # Test with DefaultCertificateManager
    config = DefaultCertificateManagerConfig(
        security_settings=SecuritySettings(signing_material=SigningMaterial.X509_CHAIN),
        signing_config=SigningConfig(signing_material=SigningMaterial.X509_CHAIN),
    )

    certificate_manager = await create_resource(CertificateManagerFactory, config)

    assert certificate_manager is not None
    assert certificate_manager.security_settings is not None
    assert certificate_manager.security_settings.signing_material == SigningMaterial.X509_CHAIN
    assert certificate_manager.signing_config is not None
    assert certificate_manager.signing_config.signing_material == SigningMaterial.X509_CHAIN

    print("✓ CertificateManager created via resource framework")


@pytest.mark.asyncio
async def test_certificate_manager_factory_with_dict_config():
    """Test CertificateManagerFactory with dictionary config."""
    print("Testing CertificateManagerFactory with dict config...")

    # Initialize the extension manager for CertificateManagerFactory
    ExtensionManager.lazy_init(
        group="naylence.CertificateManagerFactory", base_type=CertificateManagerFactory
    )

    # Test with dictionary config
    config = {
        "type": "DefaultCertificateManager",
        "security_settings": {"signing_material": "x509-chain"},
        "signing_config": {"signing_material": "x509-chain"},
    }

    certificate_manager = await create_resource(CertificateManagerFactory, config)

    assert certificate_manager is not None
    assert certificate_manager.security_settings is not None
    assert certificate_manager.security_settings.signing_material == SigningMaterial.X509_CHAIN

    print("✓ CertificateManager created via dict config")


@pytest.mark.asyncio
async def test_certificate_manager_factory_defaults():
    """Test CertificateManagerFactory with minimal config."""
    print("Testing CertificateManagerFactory with defaults...")

    # Initialize the extension manager for CertificateManagerFactory
    ExtensionManager.lazy_init(
        group="naylence.CertificateManagerFactory", base_type=CertificateManagerFactory
    )

    # Test with minimal config
    config = DefaultCertificateManagerConfig()

    certificate_manager = await create_resource(CertificateManagerFactory, config)

    assert certificate_manager is not None
    # Should have default settings
    assert certificate_manager.security_settings is not None
    assert certificate_manager.signing_config is not None

    print("✓ CertificateManager created with defaults")


def test_default_certificate_manager_factory_direct():
    """Test DefaultCertificateManagerFactory directly."""
    print("Testing DefaultCertificateManagerFactory directly...")

    factory = DefaultCertificateManagerFactory()

    assert factory.type == "DefaultCertificateManager"
    print(f"✓ Factory type: {factory.type}")


if __name__ == "__main__":
    import asyncio

    async def run_tests():
        await test_certificate_manager_factory_with_resource_factory()
        await test_certificate_manager_factory_with_dict_config()
        await test_certificate_manager_factory_defaults()
        test_default_certificate_manager_factory_direct()
        print("\n✅ All CertificateManager factory tests passed!")

    asyncio.run(run_tests())

"""
Test the complete CertificateManager interface-based architecture with extension points.
"""

import pytest

from naylence.fame.core import SigningMaterial
from naylence.fame.factory import ExtensionManager, create_resource
from naylence.fame.security.cert.certificate_manager import CertificateManager
from naylence.fame.security.cert.certificate_manager_factory import CertificateManagerFactory


@pytest.mark.asyncio
async def test_certificate_manager_extension_point_discovery():
    """Test that CertificateManager extension points are properly discovered."""
    print("Testing CertificateManager extension point discovery...")

    # Initialize extension manager
    ExtensionManager.lazy_init(
        group="naylence.CertificateManagerFactory", base_type=CertificateManagerFactory
    )

    # Get all available implementations
    mgr = ExtensionManager.lazy_init(
        group="naylence.CertificateManagerFactory", base_type=CertificateManagerFactory
    )

    available_names = mgr.available_names()
    print(f"Available CertificateManager implementations: {available_names}")

    # Verify that DefaultCertificateManager is available
    assert "DefaultCertificateManager" in available_names
    print("✓ DefaultCertificateManager found in extension points")


@pytest.mark.asyncio
async def test_end_to_end_interface_based_certificate_manager():
    """Test the complete interface-based flow from config to implementation."""
    print("Testing end-to-end interface-based CertificateManager...")

    # 1. Create config using the interface
    config = {
        "type": "DefaultCertificateManager",
        "security_settings": {"signing_material": "x509-chain"},
        "signing": {"signing_material": "x509-chain"},
    }

    # 2. Create instance via resource framework
    cert_manager = await create_resource(CertificateManagerFactory, config)

    # 3. Verify it implements the interface
    assert isinstance(cert_manager, CertificateManager)
    print("✓ Created instance implements CertificateManager interface")

    # 4. Verify configuration was applied
    assert cert_manager.security_settings.signing_material == SigningMaterial.X509_CHAIN
    assert cert_manager._signing.signing_material == SigningMaterial.X509_CHAIN
    print("✓ Configuration properly applied")

    # 5. Test interface methods exist
    assert hasattr(cert_manager, "on_node_started")
    assert hasattr(cert_manager, "on_welcome")
    print("✓ All interface methods available")

    # 6. Test that methods are callable
    assert callable(getattr(cert_manager, "on_node_started"))
    assert callable(getattr(cert_manager, "on_welcome"))
    print("✓ Interface methods are callable")

    print("✅ End-to-end interface-based architecture working correctly!")


@pytest.mark.asyncio
async def test_certificate_manager_interface_abstraction():
    """Test that the interface properly abstracts from implementation details."""
    print("Testing CertificateManager interface abstraction...")

    # Create via interface
    config = {"type": "DefaultCertificateManager", "security_settings": {"signing_material": "raw-key"}}

    cert_manager = await create_resource(CertificateManagerFactory, config)

    # Should be able to use via interface without knowing implementation
    assert isinstance(cert_manager, CertificateManager)

    # Can call interface methods
    # (We won't actually call them since they need proper setup, but verify they exist)
    interface_methods = ["on_node_started", "on_welcome"]
    for method in interface_methods:
        assert hasattr(cert_manager, method)
        assert callable(getattr(cert_manager, method))

    print("✓ Interface abstraction working correctly")


if __name__ == "__main__":
    import asyncio

    async def run_tests():
        await test_certificate_manager_extension_point_discovery()
        await test_end_to_end_interface_based_certificate_manager()
        await test_certificate_manager_interface_abstraction()
        print("\n✅ All interface architecture tests passed!")

    asyncio.run(run_tests())

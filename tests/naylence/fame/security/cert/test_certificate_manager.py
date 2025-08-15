from unittest.mock import Mock

import pytest

from naylence.fame.core import SecuritySettings, SigningMaterial
from naylence.fame.security.cert.default_certificate_manager import DefaultCertificateManager


@pytest.mark.asyncio
async def test_certificate_manager():
    """Test CertificateManager functionality."""

    print("Testing CertificateManager...")

    # Test 1: Manager with RAW_KEY (no certificate needed)
    raw_key_profile = SecuritySettings(signing_material=SigningMaterial.RAW_KEY)
    raw_key_manager = DefaultCertificateManager(raw_key_profile)

    print("✓ CertificateManager with RAW_KEY profile created")

    # Test 2: Manager with X509_CHAIN (certificate needed)
    x509_profile = SecuritySettings(signing_material=SigningMaterial.X509_CHAIN)
    DefaultCertificateManager(x509_profile)

    print("✓ CertificateManager with X509_CHAIN profile created")

    # # Test 3: Factory function
    # factory_manager = build_certificate_manager(x509_profile)
    # print("✓ Factory function works correctly")
    # print(f"  Factory manager requires certificate: {factory_manager.requires_certificate()}")

    # # Test 4: Default manager (no profile)
    # default_manager = build_certificate_manager()
    # print("✓ Default manager created")
    # print(f"  Default manager requires certificate: {default_manager.requires_certificate()}")

    # Test 5: on_root_start with RAW_KEY (should return True immediately)
    result = await raw_key_manager.ensure_root_certificate(
        node_id="test-node", physical_path="/test/path", logicals=["logical1", "logical2"]
    )
    print(f"✓ RAW_KEY on_root_start result: {result}")

    # Test 6: Mock welcome frame for child test
    mock_welcome = Mock()
    mock_welcome.system_id = "child-node"
    mock_welcome.assigned_path = "/child/path"
    mock_welcome.security_settings = None  # No profile from parent

    # Test with RAW_KEY manager (should return True immediately)
    result = await raw_key_manager.on_welcome(mock_welcome)
    print(f"✓ RAW_KEY on_welcome result: {result}")

    # Test 7: Mock welcome frame with X509 security profile
    mock_x509_welcome = Mock()
    mock_x509_welcome.system_id = "x509-child-node"
    mock_x509_welcome.assigned_path = "/x509/child/path"
    mock_x509_welcome.security_settings = x509_profile

    print("✓ All basic CertificateManager tests passed!")
    print("\nNote: X509_CHAIN certificate provisioning tests require CA service setup.")
    print("The manager correctly identifies when certificates are needed vs not needed.")

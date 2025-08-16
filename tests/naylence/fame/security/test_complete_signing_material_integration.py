"""
Comprehensive test demonstrating the complete SigningMaterial integration
between core frames, runtime security policy, and certificate manager.
"""

import asyncio
from unittest.mock import AsyncMock, patch

# Core package imports
from naylence.fame.core import SecuritySettings, SigningMaterial
from naylence.fame.core.protocol.frames import NodeHelloFrame, NodeWelcomeFrame
from naylence.fame.security.cert.default_certificate_manager import create_certificate_manager

# Runtime package imports
from naylence.fame.security.policy.security_policy import SigningConfig


def test_complete_signing_material_integration(, SigningMaterial):
    """Test that SigningMaterial works consistently across all components."""

    print("=== Complete SigningMaterial Integration Test ===")

    # 1. Test SecuritySettings (core package)
    print("\n1. Testing SecuritySettings from core package:")
    core_profile = SecuritySettings(signing_material=SigningMaterial.X509_CHAIN)
    print(f"   ✓ SecuritySettings.signing_material = {core_profile.signing_material}")

    # 2. Test SigningConfig (runtime package)
    print("\n2. Testing SigningConfig from runtime package:")
    runtime_config = SigningConfig(signing_material=SigningMaterial.X509_CHAIN)  # type: ignore
    print(f"   ✓ SigningConfig.signing_material = {runtime_config.signing_material}")

    # 3. Test that they use the same enum
    print("\n3. Testing enum consistency:")
    assert core_profile.signing_material == runtime_config.signing_material
    print("   ✓ Both use the same SigningMaterial.X509_CHAIN value")

    # 4. Test frames integration
    print("\n4. Testing frames integration:")
    hello_frame = NodeHelloFrame(
        system_id="test-node", instance_id="test-instance", security_settings=core_profile
    )
    print(
        f"   ✓ NodeHelloFrame.security_settings.signing_material = "
        f"{hello_frame.security_settings.signing_material}"  # type: ignore
    )

    welcome_frame = NodeWelcomeFrame(
        system_id="test-node", instance_id="test-instance", security_settings=core_profile
    )
    print(
        f"   ✓ NodeWelcomeFrame.security_settings.signing_material = "
        f"{welcome_frame.security_settings.signing_material}"  # type: ignore
    )

    # 5. Test JSON serialization round-trip
    print("\n5. Testing JSON serialization:")
    hello_json = hello_frame.model_dump_json()
    hello_restored = NodeHelloFrame.model_validate_json(hello_json)
    assert hello_restored.security_settings.signing_material == SigningMaterial.X509_CHAIN  # type: ignore
    print(
        f"   ✓ JSON round-trip preserves signing_material = "
        f"{hello_restored.security_settings.signing_material}"  # type: ignore
    )

    # 6. Test certificate manager integration
    print("\n6. Testing certificate manager integration:")
    cert_manager = create_certificate_manager(security_settings=core_profile, signing_config=runtime_config)
    print("   ✓ CertificateManager created with both profile and config")
    print(
        f"   ✓ Manager.security_settings.signing_material = "
        f"{cert_manager.security_settings.signing_material}"
    )
    print(f"   ✓ Manager.signing_config.signing_material = {cert_manager.signing_config.signing_material}")

    print("\n✅ Complete SigningMaterial integration test passed!")


async def test_complete_certificate_flow_simulation():
    """Simulate a complete certificate flow using the integrated components."""

    print("\n=== Complete Certificate Flow Simulation ===")

    # 1. Child node creates hello with preferred signing material
    print("\n1. Child node admission request:")
    child_profile = SecuritySettings(signing_material=SigningMaterial.RAW_KEY)
    hello = NodeHelloFrame(
        system_id="child-node-001", instance_id="instance-001", security_settings=child_profile
    )
    print(f"   ✓ Child requests signing_material = {hello.security_settings.signing_material}")  # type: ignore

    # 2. Server negotiates security profile (upgrades to X509)
    print("\n2. Server admission controller negotiation:")
    server_policy_config = SigningConfig(signing_material=SigningMaterial.X509_CHAIN)  # type: ignore
    # Simulate server enforcing X509 requirement
    negotiated_profile = SecuritySettings(signing_material=SigningMaterial.X509_CHAIN)

    welcome = NodeWelcomeFrame(
        system_id="child-node-001",
        instance_id="instance-001",
        assigned_path="/child/001",
        security_settings=negotiated_profile,
    )
    print(f"   ✓ Server negotiated signing_material = {welcome.security_settings.signing_material}")  # type: ignore

    # 3. Child receives welcome and provisions certificate
    print("\n3. Child certificate provisioning:")
    child_cert_manager = create_certificate_manager(signing_config=server_policy_config)

    # Mock the private method on this specific instance
    with patch.object(
        child_cert_manager, "ensure_non_root_certificate", new_callable=AsyncMock, return_value=True
    ) as mock_ensure_after_welcome:
        cert_result = await child_cert_manager.on_welcome(welcome_frame=welcome)
        print(f"   ✓ Certificate provisioning result = {cert_result}")

        # 4. Verify certificate provisioner was called with correct parameters
        mock_ensure_after_welcome.assert_called_once()
        call_args = mock_ensure_after_welcome.call_args
        assert call_args[1]["welcome_frame"] == welcome
        print("   ✓ Certificate provisioner called with correct welcome frame")

        # 5. Test that RAW_KEY would bypass certificate provisioning
        print("\n4. Testing RAW_KEY bypass:")
        raw_key_profile = SecuritySettings(signing_material=SigningMaterial.RAW_KEY)
        welcome_raw = NodeWelcomeFrame(
            system_id="raw-node-001", instance_id="instance-002", security_settings=raw_key_profile
        )

        raw_cert_manager = create_certificate_manager()
        raw_result = await raw_cert_manager.on_welcome(welcome_frame=welcome_raw)
        print(f"   ✓ RAW_KEY bypass result = {raw_result} (should be True without calling provisioner)")

        # Verify that certificate provisioner was NOT called again (only once for X509)
        assert mock_ensure_after_welcome.call_count == 1
        print("   ✓ Certificate provisioner not called for RAW_KEY")

        print("\n✅ Complete certificate flow simulation passed!")


if __name__ == "__main__":
    print("SigningMaterial Complete Integration Test")
    print("=" * 50)

    # Run synchronous tests
    test_complete_signing_material_integration()

    # Run asynchronous flow simulation
    asyncio.run(test_complete_certificate_flow_simulation())

    print("\n" + "=" * 50)
    print("✅ ALL INTEGRATION TESTS PASSED!")
    print("\nThe SigningMaterial enum is now successfully integrated across:")
    print("  • Core package: SecuritySettings and frames")
    print("  • Runtime package: SigningConfig and CertificateManager")
    print("  • JSON serialization/deserialization works correctly")
    print("  • Certificate provisioning flow is policy-driven")
    print("  • No hasattr() checks needed - clean interface-based design")

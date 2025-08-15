"""
Comprehensive test demonstrating the enhanced SecurityManager algorithm preference system.
"""

import pytest

from naylence.fame.security.encryption.composite_encryption_manager import CompositeEncryptionManager
from naylence.fame.security.encryption.sealed.x25519_encryption_manager import X25519EncryptionManager
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.security_manager_factory import SecurityManagerFactory
from naylence.fame.security.signing.eddsa_envelope_signer import EdDSAEnvelopeSigner
from naylence.fame.security.signing.eddsa_envelope_verifier import EdDSAEnvelopeVerifier

# Import test utilities for algorithm preference testing
from . import test_utils  # type: ignore


class MockSecureChannelManager:
    """Mock channel manager for testing."""

    def __init__(self):
        self._channels = {}


@pytest.mark.asyncio
async def test_complete_algorithm_preference_system():
    """Test the complete algorithm preference system end-to-end."""
    print("Testing complete algorithm preference system...")

    # Test 1: Backward compatibility - single preferred algorithms still work
    print("\n1. Testing backward compatibility with single preferred algorithms...")

    # Create a mock SecurityRequirements with old-style single algorithm preferences
    class MockOldRequirements:
        def __init__(self):
            self.preferred_signing_algorithm = "EdDSA"
            self.preferred_encryption_algorithm = "X25519"
            self.signing_required = True
            self.verification_required = True
            self.encryption_required = True
            self.decryption_required = True

    old_req = MockOldRequirements()

    # Test that the helper methods handle backward compatibility
    signing_algs = test_utils.get_preferred_signing_algorithms(old_req)
    encryption_algs = test_utils.get_preferred_encryption_algorithms(old_req)

    assert signing_algs == ["EdDSA"]
    assert encryption_algs == ["X25519"]
    print("✓ Backward compatibility with single algorithms works")

    # Test 2: New list-based algorithm preferences
    print("\n2. Testing new list-based algorithm preferences...")

    class MockNewRequirements:
        def __init__(self):
            self.preferred_signing_algorithms = ["EdDSA"]
            self.preferred_encryption_algorithms = [
                "X25519",
                "ECDH-ES+A256GCM",
                "chacha20-poly1305-channel",
            ]
            self.signing_required = True
            self.verification_required = True
            self.encryption_required = True
            self.decryption_required = True

    new_req = MockNewRequirements()

    signing_algs_new = test_utils.get_preferred_signing_algorithms(new_req)
    encryption_algs_new = test_utils.get_preferred_encryption_algorithms(new_req)

    assert signing_algs_new == ["EdDSA"]
    assert encryption_algs_new == ["X25519", "ECDH-ES+A256GCM", "chacha20-poly1305-channel"]
    print("✓ New list-based algorithm preferences work")

    # Test 3: Component creation with algorithm preferences
    print("\n3. Testing component creation with algorithm preferences...")

    # Import SigningConfig for component creation
    from naylence.fame.security.policy.security_policy import SigningConfig

    default_signing_config = SigningConfig()

    # Test signer creation
    signer = test_utils.create_default_signer(["EdDSA"], default_signing_config)
    assert isinstance(signer, EdDSAEnvelopeSigner)
    print("✓ Signer creation with algorithm preference works")

    # Test verifier creation
    verifier = test_utils.create_default_verifier(["EdDSA"], default_signing_config)
    assert isinstance(verifier, EdDSAEnvelopeVerifier)
    print("✓ Verifier creation with algorithm preference works")

    # Test encryption manager creation with single algorithm
    mock_secure_channel_manager = MockSecureChannelManager()
    enc_mgr_single = test_utils.create_default_encryption_manager(
        ["X25519"], get_secure_channel_manager=lambda: mock_secure_channel_manager
    )
    assert isinstance(enc_mgr_single, X25519EncryptionManager)
    print("✓ Specialized encryption manager creation works")

    # Test encryption manager creation with multiple algorithms
    enc_mgr_multi = test_utils.create_default_encryption_manager(
        ["X25519", "aes-256-gcm", "chacha20-poly1305-channel"],
        get_secure_channel_manager=lambda: mock_secure_channel_manager,
    )
    assert isinstance(enc_mgr_multi, CompositeEncryptionManager)
    print("✓ Composite encryption manager creation with multiple algorithms works")

    # Test 4: CompositeEncryptionManager algorithm configuration
    print("\n4. Testing CompositeEncryptionManager algorithm configuration...")

    if isinstance(enc_mgr_multi, CompositeEncryptionManager):
        # Check that it properly separated sealed vs channel algorithms
        assert (
            "aes-256-gcm" in enc_mgr_multi._supported_sealed_algorithms
            or len(enc_mgr_multi._supported_sealed_algorithms) > 0
        )
        assert "chacha20-poly1305-channel" in enc_mgr_multi._supported_channel_algorithms
        print("✓ Algorithm separation and configuration works")

    # Test 5: Edge cases and fallbacks
    print("\n5. Testing edge cases and fallbacks...")

    # Test with empty requirements object
    class EmptyRequirements:
        pass

    empty_req = EmptyRequirements()
    empty_signing = test_utils.get_preferred_signing_algorithms(empty_req)
    assert empty_signing == ["EdDSA"]  # Should fall back to default
    print("✓ Empty requirements object fallback works")

    # Test with unknown algorithms
    unknown_enc_mgr = test_utils.create_default_encryption_manager(
        ["unknown-algorithm"], get_secure_channel_manager=lambda: mock_secure_channel_manager
    )
    assert isinstance(unknown_enc_mgr, CompositeEncryptionManager)
    print("✓ Unknown algorithm fallback works")

    # Test 6: Real-world scenario with DefaultSecurityPolicy
    print("\n6. Testing real-world scenario with DefaultSecurityPolicy...")

    policy = DefaultSecurityPolicy()
    policy.requirements()
    node_security = await SecurityManagerFactory.create_security_manager(policy)

    # Verify all auto-created components are created
    assert node_security.policy is not None
    assert node_security.envelope_signer is not None
    assert node_security.envelope_verifier is not None
    # Encryption managers ARE auto-created when policy requires encryption and dependencies are available
    assert node_security.encryption is not None
    assert node_security.key_manager is not None
    assert node_security.authorizer is not None  # Should be auto-created now

    print("✓ Real-world DefaultSecurityPolicy integration works")
    print(f"  - Policy: {type(node_security.policy).__name__}")
    print(f"  - Signer: {type(node_security.envelope_signer).__name__}")
    print(f"  - Verifier: {type(node_security.envelope_verifier).__name__}")
    print(
        f"  - Encryption: {type(node_security.encryption).__name__ if node_security.encryption else 'None'}"
    )
    print(f"  - Key Manager: {type(node_security.key_manager).__name__}")
    print(f"  - Authorizer: {type(node_security.authorizer).__name__}")

    # Test that we can still create encryption managers manually when needed
    mock_secure_channel_manager = MockSecureChannelManager()
    manual_encryption = test_utils.create_default_encryption_manager(
        ["X25519", "aes-256-gcm"], get_secure_channel_manager=lambda: mock_secure_channel_manager
    )
    assert isinstance(manual_encryption, CompositeEncryptionManager)
    print("✓ Manual encryption manager creation still works")

    print("\n🎉 All algorithm preference system tests passed!")


def test_algorithm_priority_and_selection():
    """Test that algorithm priority and selection work correctly."""
    print("\nTesting algorithm priority and selection...")

    # Create mock channel manager for testing
    mock_secure_channel_manager = MockSecureChannelManager()

    # Test 1: Single X25519 should create specialized manager
    print("\n1. Testing single X25519 creates specialized manager...")

    # Only X25519 should create specialized manager
    x25519_only = test_utils.create_default_encryption_manager(
        ["X25519"], get_secure_channel_manager=lambda: mock_secure_channel_manager
    )
    assert isinstance(x25519_only, X25519EncryptionManager)
    print("✓ Single X25519 creates specialized manager")

    # Multiple algorithms (including X25519) should create composite manager
    x25519_with_others = test_utils.create_default_encryption_manager(
        ["X25519", "aes-256-gcm"], get_secure_channel_manager=lambda: mock_secure_channel_manager
    )
    assert isinstance(x25519_with_others, CompositeEncryptionManager)
    print("✓ X25519 with other algorithms creates composite manager")

    # Test 2: Non-X25519 algorithms should create composite manager
    print("\n2. Testing non-X25519 algorithms create composite manager...")

    non_x25519 = test_utils.create_default_encryption_manager(
        ["aes-256-gcm", "chacha20-poly1305"], get_secure_channel_manager=lambda: mock_secure_channel_manager
    )
    assert isinstance(non_x25519, CompositeEncryptionManager)
    print("✓ Non-X25519 algorithms create composite manager")

    # Test 3: Algorithm filtering and categorization
    print("\n3. Testing algorithm filtering and categorization...")

    mixed_algorithms = ["X25519", "unknown-alg", "chacha20-poly1305-channel", "aes-256-gcm"]
    enc_mgr = test_utils.create_default_encryption_manager(
        mixed_algorithms, get_secure_channel_manager=lambda: mock_secure_channel_manager
    )

    # Should create composite manager due to multiple algorithms
    assert isinstance(enc_mgr, CompositeEncryptionManager)

    # Should have filtered out unknown algorithms
    all_supported = enc_mgr._supported_sealed_algorithms + enc_mgr._supported_channel_algorithms
    assert "unknown-alg" not in all_supported
    assert "X25519" in enc_mgr._supported_sealed_algorithms
    assert "aes-256-gcm" in enc_mgr._supported_sealed_algorithms
    assert "chacha20-poly1305-channel" in enc_mgr._supported_channel_algorithms
    print("✓ Unknown algorithms are filtered out and known algorithms are properly categorized")

    print("\n🎉 All algorithm priority and selection tests passed!")

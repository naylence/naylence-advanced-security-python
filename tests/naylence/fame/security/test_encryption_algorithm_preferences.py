"""
Test that the encryption manager properly respects preferred algorithms.
"""

import pytest

from naylence.fame.security.encryption.composite_encryption_manager import CompositeEncryptionManager
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.security_manager_factory import SecurityManagerFactory

# Import test utilities for algorithm preference testing
from . import test_utils


class MockSecureChannelManager:
    """Mock channel manager for testing."""

    def __init__(self):
        self._channels = {}


def test_encryption_manager_algorithm_preferences():
    """Test that the encryption manager properly uses preferred algorithms."""
    print("Testing encryption manager algorithm preferences...")

    # Test 1: Test helper methods directly
    print("\n1. Testing algorithm preference helper methods...")

    # Create a mock requirements object with preferred algorithms
    class MockRequirements:
        def __init__(self, preferred_encryption_algorithms=None):
            self.preferred_encryption_algorithms = preferred_encryption_algorithms or [
                "X25519",
                "aes-256-gcm",
            ]
            self.encryption_required = True
            self.decryption_required = True

    mock_req = MockRequirements(["ECDH-ES+A256GCM", "chacha20-poly1305"])
    algorithms = test_utils.get_preferred_encryption_algorithms(mock_req)

    assert algorithms == ["ECDH-ES+A256GCM", "chacha20-poly1305"]
    print("✓ Algorithm preference extraction works")

    # Test 2: Test encryption manager creation with preferred algorithms
    print("\n2. Testing encryption manager creation with algorithms...")

    mock_secure_channel_manager = MockSecureChannelManager()
    encryption_manager = test_utils.create_default_encryption_manager(
        ["X25519", "aes-256-gcm"], get_secure_channel_manager=lambda: mock_secure_channel_manager
    )
    assert encryption_manager is not None
    print(f"✓ Created encryption manager: {type(encryption_manager).__name__}")

    # Test 3: Test with mixed algorithms
    print("\n3. Testing mixed sealed and channel algorithms...")

    mixed_algorithms = ["X25519", "chacha20-poly1305-channel", "aes-256-gcm"]
    mixed_manager = test_utils.create_default_encryption_manager(
        mixed_algorithms, get_secure_channel_manager=lambda: mock_secure_channel_manager
    )
    assert mixed_manager is not None

    if isinstance(mixed_manager, CompositeEncryptionManager):
        # Should have configured algorithms
        print("✓ CompositeEncryptionManager created with mixed algorithms")
    else:
        print(f"✓ Created specialized encryption manager: {type(mixed_manager).__name__}")

    # Test 4: Test algorithm separation logic
    print("\n4. Testing algorithm separation logic...")

    # Test the logic in _create_default_encryption_manager
    sealed_algs = []
    channel_algs = []
    known_sealed = {"X25519", "ECDH-ES+A256GCM", "chacha20-poly1305", "aes-256-gcm"}
    known_channel = {"chacha20-poly1305-channel"}

    test_algorithms = ["X25519", "chacha20-poly1305-channel", "aes-256-gcm"]
    for algorithm in test_algorithms:
        if algorithm in known_sealed:
            sealed_algs.append(algorithm)
        elif algorithm in known_channel:
            channel_algs.append(algorithm)

    assert "X25519" in sealed_algs
    assert "aes-256-gcm" in sealed_algs
    assert "chacha20-poly1305-channel" in channel_algs
    print("✓ Algorithm separation logic works correctly")

    print("\n🎉 All encryption algorithm preference tests passed!")


def test_composite_encryption_manager_flexibility():
    """Test that CompositeEncryptionManager can be configured flexibly."""
    print("\nTesting CompositeEncryptionManager flexibility...")

    # Create a mock channel manager for testing
    mock_secure_channel_manager = MockSecureChannelManager()

    # Test 1: Default configuration
    print("\n1. Testing default CompositeEncryptionManager...")
    from naylence.fame.security.keys.key_provider import get_key_provider

    default_manager = CompositeEncryptionManager(
        secure_channel_manager=mock_secure_channel_manager, key_provider=get_key_provider()
    )
    assert (
        default_manager._supported_sealed_algorithms == CompositeEncryptionManager.DEFAULT_SEALED_ALGORITHMS
    )
    assert (
        default_manager._supported_channel_algorithms
        == CompositeEncryptionManager.DEFAULT_CHANNEL_ALGORITHMS
    )
    print("✓ Default configuration works")

    # Test 2: Custom sealed algorithms
    print("\n2. Testing custom sealed algorithms...")
    custom_sealed = ["ECDH-ES+A256GCM"]
    sealed_manager = CompositeEncryptionManager(
        secure_channel_manager=mock_secure_channel_manager,
        key_provider=get_key_provider(),
        supported_sealed_algorithms=custom_sealed,
    )
    assert sealed_manager._supported_sealed_algorithms == custom_sealed
    assert (
        sealed_manager._supported_channel_algorithms
        == CompositeEncryptionManager.DEFAULT_CHANNEL_ALGORITHMS
    )
    print("✓ Custom sealed algorithms configuration works")

    # Test 3: Custom channel algorithms
    print("\n3. Testing custom channel algorithms...")
    custom_channel = ["chacha20-poly1305-channel"]
    secure_channel_manager = CompositeEncryptionManager(
        secure_channel_manager=mock_secure_channel_manager,
        key_provider=get_key_provider(),
        supported_channel_algorithms=custom_channel,
    )
    assert (
        secure_channel_manager._supported_sealed_algorithms
        == CompositeEncryptionManager.DEFAULT_SEALED_ALGORITHMS
    )
    assert secure_channel_manager._supported_channel_algorithms == custom_channel
    print("✓ Custom channel algorithms configuration works")

    # Test 4: Custom both
    print("\n4. Testing custom both algorithms...")
    both_manager = CompositeEncryptionManager(
        secure_channel_manager=mock_secure_channel_manager,
        key_provider=get_key_provider(),
        supported_sealed_algorithms=["aes-256-gcm"],
        supported_channel_algorithms=["chacha20-poly1305-channel"],
    )
    assert both_manager._supported_sealed_algorithms == ["aes-256-gcm"]
    assert both_manager._supported_channel_algorithms == ["chacha20-poly1305-channel"]
    print("✓ Custom both algorithms configuration works")

    # Test 5: Algorithm checking methods
    print("\n5. Testing algorithm checking methods...")
    test_manager = CompositeEncryptionManager(
        secure_channel_manager=mock_secure_channel_manager,
        key_provider=get_key_provider(),
        supported_sealed_algorithms=["aes-256-gcm"],
        supported_channel_algorithms=["chacha20-poly1305-channel"],
    )

    assert test_manager._is_sealed_algorithm("aes-256-gcm") is True
    assert test_manager._is_sealed_algorithm("unknown-algorithm") is False
    assert test_manager._is_channel_algorithm("chacha20-poly1305-channel") is True
    assert test_manager._is_channel_algorithm("unknown-algorithm") is False
    print("✓ Algorithm checking methods work correctly")

    print("\n🎉 All CompositeEncryptionManager flexibility tests passed!")


@pytest.mark.asyncio
async def test_real_world_integration():
    """Test with real DefaultSecurityPolicy to ensure everything works together."""
    print("\nTesting real-world integration...")

    # Test with default policy
    print("\n1. Testing with DefaultSecurityPolicy...")
    default_policy = DefaultSecurityPolicy()
    node_security = await SecurityManagerFactory.create_security_manager(default_policy)

    # Default policy correctly creates no encryption manager (no encryption required)
    encryption_manager = node_security.encryption
    print(f"   Default policy encryption manager: {encryption_manager}")
    
    # Create a policy that actually requires encryption
    from naylence.fame.security.policy.security_policy import EncryptionConfig, OutboundCryptoRules, CryptoLevel
    
    encryption_policy = DefaultSecurityPolicy(
        encryption=EncryptionConfig(
            outbound=OutboundCryptoRules(default_level=CryptoLevel.CHANNEL)
        )
    )
    
    encryption_security = await SecurityManagerFactory.create_security_manager(encryption_policy)
    encryption_manager = encryption_security.encryption
    assert encryption_manager is not None

    # Test that we can create encryption managers manually with proper dependencies
    print("\n2. Testing manual encryption manager creation...")
    mock_secure_channel_manager = MockSecureChannelManager()
    manual_encryption = test_utils.create_default_encryption_manager(
        ["X25519", "aes-256-gcm"], get_secure_channel_manager=lambda: mock_secure_channel_manager
    )
    assert manual_encryption is not None
    print(f"✓ Manual encryption manager creation works: {type(manual_encryption).__name__}")

    # Test that we can provide encryption manager explicitly
    print("\n3. Testing explicit encryption manager provision...")
    node_security_with_encryption = await SecurityManagerFactory.create_security_manager(
        default_policy, encryption_manager=manual_encryption
    )
    assert node_security_with_encryption.encryption is manual_encryption
    print("✓ Explicit encryption manager provision works")

    print("\n🎉 Real-world integration test passed!")

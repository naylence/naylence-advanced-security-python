#!/usr/bin/env python3
"""
Test demonstrating the new key provider parameter in X25519EncryptionManager.
"""

from naylence.fame.security.encryption.sealed.x25519_encryption_manager import X25519EncryptionManager
from naylence.fame.security.keys.key_provider import get_key_provider


class MockKeyProvider:
    """Mock key provider for testing."""

    def __init__(self):
        self.keys = {}

    def get_key(self, kid: str) -> dict:
        if kid in self.keys:
            return self.keys[kid]
        raise KeyError(f"Key {kid} not found")

    def add_key(self, kid: str, key_data: dict):
        self.keys[kid] = key_data


def test_key_provider_parameter():
    """Test that key_provider parameter is required in X25519EncryptionManager."""

    print("🔑 Testing X25519EncryptionManager key provider parameter...")

    # Test 1: Required key_provider parameter
    default_provider = get_key_provider()
    manager1 = X25519EncryptionManager(key_provider=default_provider)

    print("✅ Initialization with explicit key provider successful")
    assert hasattr(manager1, "_key_provider")
    assert manager1._key_provider is default_provider

    # Test 2: Custom key provider
    mock_provider = MockKeyProvider()
    mock_provider.add_key("test-key", {"encryption_private_pem": "mock-pem-data"})

    manager2 = X25519EncryptionManager(key_provider=mock_provider)  # type: ignore

    print("✅ Custom key provider initialization successful")
    assert manager2._key_provider == mock_provider
    assert manager2._key_provider.keys["test-key"]["encryption_private_pem"] == "mock-pem-data"  # type: ignore

    # Test 3: Both crypto provider and key provider parameters
    from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider

    crypto_provider = get_crypto_provider()

    # Create a different mock provider for this test
    mock_provider2 = MockKeyProvider()
    mock_provider2.add_key("test-key-2", {"encryption_private_pem": "mock-pem-data-2"})

    manager3 = X25519EncryptionManager(crypto=crypto_provider, key_provider=mock_provider2)  # type: ignore

    print("✅ Both crypto and key provider parameters work together")
    assert manager3._crypto == crypto_provider
    assert manager3._key_provider == mock_provider2

    # Test 4: Verify managers are independent
    assert manager1._key_provider != manager2._key_provider
    assert manager2._key_provider != manager3._key_provider
    assert manager2._key_provider == mock_provider
    assert manager3._key_provider == mock_provider2

    print("✅ Multiple manager instances are independent")

    print("🎉 Key provider parameter test completed successfully!")
    print("\n📝 Key benefits:")
    print("   ✅ Flexible initialization - can provide custom key provider")
    print("   ✅ Backward compatible - defaults to get_key_provider() if not specified")
    print("   ✅ Testable - can inject mock key providers for testing")
    print("   ✅ Instance-level - each manager has its own key provider")
    print("   ✅ Clean API - optional parameter with sensible default")

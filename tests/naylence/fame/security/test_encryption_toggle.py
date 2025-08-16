"""
Test the encrypted storage provider with encryption toggle functionality.
"""

import hashlib
from typing import Optional, Type, TypeVar

import pytest
from pydantic import BaseModel

from naylence.fame.security.credential.credential_provider import CredentialProvider
from naylence.fame.storage.encrypted_storage_provider_base import EncryptedStorageProviderBase
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
from naylence.fame.storage.key_value_store import KeyValueStore

V = TypeVar("V", bound=BaseModel)


class StaticCredentialProvider(CredentialProvider):
    """Simple credential provider that returns a static key."""

    def __init__(self, key: bytes, key_id: str = "static-key"):
        self._key = key
        self._key_id = key_id

    async def get(self) -> bytes:
        return self._key

    def get_key_id(self) -> str:
        return self._key_id


class EncryptedInMemoryStorageProvider(EncryptedStorageProviderBase):
    """
    Test encrypted storage provider using in-memory storage as the backend.
    """

    def __init__(self, master_password: Optional[str] = None, is_encrypted: bool = True):
        if is_encrypted:
            if master_password is None:
                raise ValueError("master_password is required when is_encrypted=True")
            # Derive a 32-byte key from the password using PBKDF2
            master_key = self._derive_key_from_password(master_password)
            master_key_provider = StaticCredentialProvider(master_key, "memory-key-v1")
        else:
            master_key_provider = None

        # Initialize the encrypted base
        super().__init__(is_encrypted=is_encrypted, master_key_provider=master_key_provider)

        # Create underlying storage
        self._underlying_provider = InMemoryStorageProvider()

    def _derive_key_from_password(self, password: str) -> bytes:
        """Derive a cryptographic key from a password."""
        # Use a fixed salt for simplicity (in production, use a random salt)
        salt = b"naylence-fame-encrypted-storage"
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)

    async def _get_underlying_kv_store(
        self, model_cls: Type[V], *, namespace: str | None = None
    ) -> KeyValueStore[V]:
        """Get the underlying storage for the encrypted wrapper."""
        return await self._underlying_provider.get_kv_store(model_cls, namespace=namespace)


class TestData(BaseModel):
    """Test model for storage."""

    id: str
    name: str
    secret: str
    count: int = 0


@pytest.mark.asyncio
async def test_encrypted_mode():
    """Test storage provider with encryption enabled."""
    # Create encrypted storage with encryption enabled
    provider = EncryptedInMemoryStorageProvider("my-secret-password-123", is_encrypted=True)

    # Get a key-value store for our test data
    kv_store = await provider.get_kv_store(TestData, namespace="test")

    # Test data
    test_item = TestData(id="test-1", name="Test Item", secret="This is sensitive data!", count=42)

    # Store and retrieve the data
    await kv_store.set("item1", test_item)
    retrieved = await kv_store.get("item1")

    assert retrieved is not None, "Should retrieve stored item"
    assert retrieved.id == "test-1", "ID should match"
    assert retrieved.secret == "This is sensitive data!", "Secret should be decrypted correctly"
    assert retrieved.count == 42, "Count should match"


@pytest.mark.asyncio
async def test_unencrypted_mode():
    """Test storage provider with encryption disabled."""
    # Create storage provider with encryption disabled
    provider = EncryptedInMemoryStorageProvider(is_encrypted=False)

    # Get a key-value store for our test data
    kv_store = await provider.get_kv_store(TestData, namespace="test")

    # Test data
    test_item = TestData(id="test-2", name="Unencrypted Item", secret="This is plain text data", count=100)

    # Store and retrieve the data
    await kv_store.set("item2", test_item)
    retrieved = await kv_store.get("item2")

    assert retrieved is not None, "Should retrieve stored item"
    assert retrieved.id == "test-2", "ID should match"
    assert retrieved.secret == "This is plain text data", "Secret should match"
    assert retrieved.count == 100, "Count should match"


@pytest.mark.asyncio
async def test_validation():
    """Test that proper validation happens."""
    # Should fail when encryption is enabled but no password provided
    with pytest.raises(ValueError, match="master_password is required"):
        EncryptedInMemoryStorageProvider(is_encrypted=True)  # No password

    # Should work when encryption is disabled and no password provided
    provider = EncryptedInMemoryStorageProvider(is_encrypted=False)
    assert provider is not None, "Should create provider without password when unencrypted"


@pytest.mark.asyncio
async def test_data_isolation():
    """Test that encrypted and unencrypted stores are isolated."""
    # Create both encrypted and unencrypted providers
    encrypted_provider = EncryptedInMemoryStorageProvider("password123", is_encrypted=True)
    unencrypted_provider = EncryptedInMemoryStorageProvider(is_encrypted=False)

    # Get stores for the same namespace
    encrypted_store = await encrypted_provider.get_kv_store(TestData, namespace="shared")
    unencrypted_store = await unencrypted_provider.get_kv_store(TestData, namespace="shared")

    # Store data in both
    test_data = TestData(id="shared", name="Shared Key", secret="Secret data")

    await encrypted_store.set("key1", test_data)
    await unencrypted_store.set("key1", test_data)

    # Retrieve from both
    encrypted_result = await encrypted_store.get("key1")
    unencrypted_result = await unencrypted_store.get("key1")

    # Both should work independently
    assert encrypted_result is not None, "Encrypted store should return data"
    assert encrypted_result.secret == "Secret data", "Encrypted data should decrypt correctly"
    assert unencrypted_result is not None, "Unencrypted store should return data"
    assert unencrypted_result.secret == "Secret data", "Unencrypted data should match"


@pytest.mark.asyncio
async def test_performance_comparison():
    """Test that both encrypted and unencrypted modes work efficiently."""
    import time

    # Create both providers
    encrypted_provider = EncryptedInMemoryStorageProvider("password123", is_encrypted=True)
    unencrypted_provider = EncryptedInMemoryStorageProvider(is_encrypted=False)

    encrypted_store = await encrypted_provider.get_kv_store(TestData, namespace="perf")
    unencrypted_store = await unencrypted_provider.get_kv_store(TestData, namespace="perf")

    test_data = TestData(id="perf", name="Performance Test", secret="x" * 1000, count=1)  # Larger data

    # Test encrypted storage timing
    start = time.time()
    for i in range(10):
        await encrypted_store.set(f"key{i}", test_data)
        retrieved = await encrypted_store.get(f"key{i}")
        assert retrieved is not None, f"Should retrieve encrypted key{i}"
    encrypted_time = time.time() - start

    # Test unencrypted storage timing
    start = time.time()
    for i in range(10):
        await unencrypted_store.set(f"key{i}", test_data)
        retrieved = await unencrypted_store.get(f"key{i}")
        assert retrieved is not None, f"Should retrieve unencrypted key{i}"
    unencrypted_time = time.time() - start

    # Both should complete in reasonable time (not asserting relative performance as it can vary)
    assert encrypted_time < 5.0, "Encrypted operations should complete in reasonable time"
    assert unencrypted_time < 5.0, "Unencrypted operations should complete in reasonable time"


@pytest.mark.asyncio
async def test_multiple_namespaces():
    """Test that encryption works correctly across multiple namespaces."""
    provider = EncryptedInMemoryStorageProvider("test-password", is_encrypted=True)

    # Create stores for different namespaces
    store1 = await provider.get_kv_store(TestData, namespace="ns1")
    store2 = await provider.get_kv_store(TestData, namespace="ns2")

    # Store different data in each namespace
    data1 = TestData(id="1", name="Data One", secret="Secret One")
    data2 = TestData(id="2", name="Data Two", secret="Secret Two")

    await store1.set("key", data1)
    await store2.set("key", data2)

    # Retrieve and verify
    retrieved1 = await store1.get("key")
    retrieved2 = await store2.get("key")

    assert retrieved1 is not None and retrieved1.secret == "Secret One", (
        "Namespace 1 should have correct data"
    )
    assert retrieved2 is not None and retrieved2.secret == "Secret Two", (
        "Namespace 2 should have correct data"
    )
    assert retrieved1.id != retrieved2.id, "Different namespaces should have different data"

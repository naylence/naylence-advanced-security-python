"""Test EncryptionManagerFactory to ensure configs resolve to correct subtypes."""

import pytest

from naylence.fame.factory import create_resource
from naylence.fame.security.encryption.composite_encryption_manager import CompositeEncryptionManager
from naylence.fame.security.encryption.composite_encryption_manager_factory import (
    CompositeEncryptionManagerConfig,
)
from naylence.fame.security.encryption.encryption_manager import EncryptionManagerFactory
from naylence.fame.security.encryption.sealed.x25519_encryption_manager import X25519EncryptionManager
from naylence.fame.security.encryption.sealed.x25519_encryption_manager_factory import (
    X25519EncryptionManagerConfig,
)


class TestEncryptionManagerFactory:
    """Test EncryptionManagerFactory and its implementations."""

    @pytest.mark.asyncio
    async def test_composite_encryption_manager_factory(self):
        """Test CompositeEncryptionManager factory creates correct instance."""
        config = CompositeEncryptionManagerConfig()

        # Need to provide crypto provider for encryption manager
        from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
        from naylence.fame.security.keys.key_provider import get_key_provider

        crypto_provider = get_crypto_provider()

        # Create a mock channel manager for the composite encryption manager
        class MockSecureChannelManager:
            def __init__(self):
                self._channels = {}

        mock_secure_channel_manager = MockSecureChannelManager()

        manager = await create_resource(
            EncryptionManagerFactory,
            config,
            crypto=crypto_provider,
            key_provider=get_key_provider(),
            secure_channel_manager=mock_secure_channel_manager,
        )

        assert isinstance(manager, CompositeEncryptionManager)
        assert manager.__class__.__name__ == "CompositeEncryptionManager"

    @pytest.mark.asyncio
    async def test_x25519_encryption_manager_factory(self):
        """Test X25519EncryptionManager factory creates correct instance."""
        config = X25519EncryptionManagerConfig()

        from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
        from naylence.fame.security.keys.key_provider import get_key_provider

        crypto_provider = get_crypto_provider()

        manager = await create_resource(
            EncryptionManagerFactory, config, crypto=crypto_provider, key_provider=get_key_provider()
        )

        assert isinstance(manager, X25519EncryptionManager)
        assert manager.__class__.__name__ == "X25519EncryptionManager"

    @pytest.mark.asyncio
    async def test_encryption_manager_factory_from_dict(self):
        """Test factory with dictionary configuration."""
        config = {"type": "CompositeEncryptionManager"}

        from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
        from naylence.fame.security.keys.key_provider import get_key_provider

        crypto_provider = get_crypto_provider()

        # Create a mock channel manager for the composite encryption manager
        class MockSecureChannelManager:
            def __init__(self):
                self._channels = {}

        mock_secure_channel_manager = MockSecureChannelManager()

        manager = await create_resource(
            EncryptionManagerFactory,
            config,  # type: ignore
            crypto=crypto_provider,
            key_provider=get_key_provider(),
            secure_channel_manager=mock_secure_channel_manager,
        )

        assert isinstance(manager, CompositeEncryptionManager)

    @pytest.mark.asyncio
    async def test_x25519_encryption_manager_factory_from_dict(self):
        """Test X25519 factory with dictionary configuration."""
        config = {"type": "X25519EncryptionManager"}

        from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
        from naylence.fame.security.keys.key_provider import get_key_provider

        crypto_provider = get_crypto_provider()

        manager = await create_resource(
            EncryptionManagerFactory,
            config,  # type: ignore
            crypto=crypto_provider,
            key_provider=get_key_provider(),
        )

        assert isinstance(manager, X25519EncryptionManager)

    @pytest.mark.asyncio
    async def test_encryption_manager_factory_invalid_type(self):
        """Test factory with invalid type raises error."""
        config = {"type": "InvalidEncryptionManager"}

        from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider

        crypto_provider = get_crypto_provider()

        with pytest.raises(Exception):
            await create_resource(
                EncryptionManagerFactory,
                config,  # type: ignore
                crypto=crypto_provider,
            )

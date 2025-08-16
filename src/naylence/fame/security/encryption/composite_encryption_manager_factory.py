from typing import Any, List, Optional

from naylence.fame.security.crypto.providers.crypto_provider import CryptoProvider
from naylence.fame.security.encryption.encryption_manager import (
    EncryptionManager,
    EncryptionManagerConfig,
    EncryptionManagerFactory,
    EncryptionOptions,
)
from naylence.fame.security.encryption.secure_channel_manager import SecureChannelManager


class CompositeEncryptionManagerConfig(EncryptionManagerConfig):
    """
    Config for CompositeEncryptionManager.
    Optionally specify which delegate to use as default, or other policy fields.
    """

    type: str = "CompositeEncryptionManager"
    priority: int = 1000  # Highest priority - this is the main orchestrator

    default_algo: Optional[str] = None  # e.g. 'sealed' or 'channel'
    # Add more policy fields as needed

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Composite manager supports all algorithms from registered factories
        if self.supported_algorithms is None:
            self.supported_algorithms = []  # Will be populated dynamically
        if self.encryption_type is None:
            self.encryption_type = "composite"


class CompositeEncryptionManagerFactory(EncryptionManagerFactory):
    type: str = "CompositeEncryptionManagerFactory"

    is_default: bool = True

    def __init__(self, config: Optional[CompositeEncryptionManagerConfig] = None):
        self.config = config or CompositeEncryptionManagerConfig()

    def get_supported_algorithms(self) -> List[str]:
        """Return list of algorithms this factory can create managers for."""
        # The composite manager supports all algorithms from its registered factories
        # This will be populated dynamically at runtime
        return self.config.supported_algorithms or []

    def get_encryption_type(self) -> str:
        """Return the encryption type this factory handles."""
        return self.config.encryption_type or "composite"

    def get_priority(self) -> int:
        """Return priority for algorithm conflicts."""
        return self.config.priority

    def supports_options(self, opts: Optional[EncryptionOptions]) -> bool:
        """Check if this factory can handle the given encryption options."""
        # The composite manager can handle any encryption options by delegating
        # to appropriate registered factories, so it always returns True
        return True

    async def create(
        self,
        config: Optional[EncryptionManagerConfig | dict[str, Any]] = None,
        crypto_provider: Optional[CryptoProvider] = None,
        key_provider: Optional[Any] = None,
        node_like=None,  # Accept node reference for channel encryption
        secure_channel_manager: Optional[SecureChannelManager] = None,  # Callable to get channel manager
        **kwargs: Any,
    ) -> EncryptionManager:
        # Lazy import to avoid import-time dependency
        from .composite_encryption_manager import CompositeEncryptionManager

        if secure_channel_manager is None:
            raise ValueError(
                "CompositeEncryptionManager requires secure_channel_manager parameter. "
                "Please provide an instance of SecureChannelManager."
            )

        # Strongly encourage explicit key_provider injection but allow fallback
        if key_provider is None:
            raise ValueError(
                "CompositeEncryptionManager requires a key_provider. "
                "Please provide an instance of KeyProvider."
            )

        return CompositeEncryptionManager(
            secure_channel_manager=secure_channel_manager,
            crypto=crypto_provider,
            key_provider=key_provider,
            node_like=node_like,
        )

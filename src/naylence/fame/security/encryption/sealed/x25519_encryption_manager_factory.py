from typing import Any, List, Optional

from naylence.fame.security.crypto.providers.crypto_provider import CryptoProvider
from naylence.fame.security.encryption.encryption_manager import (
    EncryptionManager,
    EncryptionManagerConfig,
    EncryptionManagerFactory,
    EncryptionOptions,
)


class X25519EncryptionManagerConfig(EncryptionManagerConfig):
    """Config for the X25519 encryption manager."""

    type: str = "X25519EncryptionManager"
    priority: int = 100  # Higher priority than channel encryption

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Set X25519-specific defaults
        if self.supported_algorithms is None:
            self.supported_algorithms = ["X25519", "ECDH-ES+A256GCM", "chacha20-poly1305", "aes-256-gcm"]
        if self.encryption_type is None:
            self.encryption_type = "sealed"


class X25519EncryptionManagerFactory(EncryptionManagerFactory):
    type: str = "X25519EncryptionManager"

    def __init__(self, config: Optional[X25519EncryptionManagerConfig] = None):
        self.config = config or X25519EncryptionManagerConfig()

    def get_supported_algorithms(self) -> List[str]:
        """Return list of algorithms this factory can create managers for."""
        return self.config.supported_algorithms or [
            "X25519",
            "ECDH-ES+A256GCM",
            "chacha20-poly1305",
            "aes-256-gcm",
        ]

    def get_encryption_type(self) -> str:
        """Return the encryption type this factory handles."""
        return self.config.encryption_type or "sealed"

    def get_priority(self) -> int:
        """Return priority for algorithm conflicts (higher = preferred)."""
        return self.config.priority

    def supports_options(self, opts: Optional[EncryptionOptions]) -> bool:
        """Check if this factory can handle the given encryption options."""
        if not opts:
            return False

        # Sealed encryption is indicated by recipient public key, key ID, or address request
        return bool("recip_pub" in opts or "recip_kid" in opts or "request_address" in opts)

    async def create(
        self,
        config: Optional[EncryptionManagerConfig | dict[str, Any]] = None,
        key_provider: Optional[Any] = None,
        crypto: Optional[CryptoProvider] = None,
        **kwargs: Any,
    ) -> EncryptionManager:
        from .x25519_encryption_manager import X25519EncryptionManager

        # Require explicit key_provider - no fallback to singleton
        if key_provider is None:
            raise ValueError("key_provider is required for X25519EncryptionManager creation via factory")

        # Get node_like from kwargs
        node_like = kwargs.get("node_like")

        return X25519EncryptionManager(key_provider=key_provider, crypto=crypto, node_like=node_like)

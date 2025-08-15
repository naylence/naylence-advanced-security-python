"""
Factory for creating ChannelEncryptionManager instances.

This factory provides pluggable channel encryption capabilities through the
ResourceFactory extension system.
"""

from typing import Any, List, Optional

from naylence.fame.security.encryption.channel.channel_encryption_manager import ChannelEncryptionManager
from naylence.fame.security.encryption.encryption_manager import (
    EncryptionManagerConfig,
    EncryptionManagerFactory,
    EncryptionOptions,
)
from naylence.fame.security.encryption.secure_channel_manager import SecureChannelManager
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class ChannelEncryptionManagerConfig(EncryptionManagerConfig):
    """Configuration for ChannelEncryptionManager."""

    type: str = "ChannelEncryptionManager"
    priority: int = 90  # Lower priority than sealed encryption

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Set channel-specific defaults
        if self.supported_algorithms is None:
            self.supported_algorithms = ["chacha20-poly1305-channel"]
        if self.encryption_type is None:
            self.encryption_type = "channel"


class ChannelEncryptionManagerFactory(EncryptionManagerFactory):
    """Factory for creating ChannelEncryptionManager instances."""

    type: str = "ChannelEncryptionManager"

    def __init__(self, config: Optional[ChannelEncryptionManagerConfig] = None):
        self.config = config or ChannelEncryptionManagerConfig()

    def get_supported_algorithms(self) -> List[str]:
        """Return list of algorithms this factory can create managers for."""
        return self.config.supported_algorithms or ["chacha20-poly1305-channel"]

    def get_encryption_type(self) -> str:
        """Return the encryption type this factory handles."""
        return self.config.encryption_type or "channel"

    def get_priority(self) -> int:
        """Return priority for algorithm conflicts (higher = preferred)."""
        return self.config.priority

    def supports_options(self, opts: Optional[EncryptionOptions]) -> bool:
        """Check if this factory can handle the given encryption options."""
        if not opts:
            return False

        # Channel encryption is indicated by encryption_type = "channel"
        return opts.get("encryption_type") == "channel"

    async def create(
        self,
        config: Optional[EncryptionManagerConfig | dict[str, Any]] = None,
        secure_channel_manager: Optional[SecureChannelManager] = None,
        **kwargs: Any,
    ) -> ChannelEncryptionManager:
        """Create a ChannelEncryptionManager instance."""

        # Use provided config or default
        if config is None:
            config = self.config
        elif isinstance(config, dict):
            config = ChannelEncryptionManagerConfig(**config)
        elif not isinstance(config, ChannelEncryptionManagerConfig):
            # Convert base config to channel-specific config
            config = ChannelEncryptionManagerConfig(
                type=getattr(config, "type", "ChannelEncryptionManager"),
                supported_algorithms=getattr(config, "supported_algorithms", None),
                encryption_type=getattr(config, "encryption_type", None),
                priority=getattr(config, "priority", 90),
            )

        # Extract dependencies from kwargs
        node_like = kwargs.get("node_like")

        logger.debug(
            "creating_channel_encryption_manager",
            config_type=config.type,
            has_secure_channel_manager=secure_channel_manager is not None,
            has_node_like=node_like is not None,
        )

        return ChannelEncryptionManager(secure_channel_manager=secure_channel_manager, node_like=node_like)

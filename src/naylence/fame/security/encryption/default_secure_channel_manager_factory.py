"""
Configuration and factory for DefaultSecureChannelManager.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.security.encryption.secure_channel_manager import SecureChannelManager
from naylence.fame.security.encryption.secure_channel_manager_factory import (
    SecureChannelManagerConfig,
    SecureChannelManagerFactory,
)


class DefaultSecureChannelManagerConfig(SecureChannelManagerConfig):
    """Configuration for DefaultSecureChannelManager."""

    type: str = "DefaultSecureChannelManager"

    channel_ttl: float = Field(
        default=3600.0, description="Default channel time-to-live in seconds (default: 1 hour)"
    )


class DefaultSecureChannelManagerFactory(SecureChannelManagerFactory):
    """Factory for creating DefaultSecureChannelManager instances."""

    type: str = "DefaultSecureChannelManager"
    is_default: bool = True  # Mark as default implementation

    async def create(
        self, config: Optional[DefaultSecureChannelManagerConfig | dict[str, Any]] = None, **kwargs: Any
    ) -> SecureChannelManager:
        """Create a DefaultSecureChannelManager instance.

        Args:
            config: Configuration for the secure channel manager
            **kwargs: Additional keyword arguments

        Returns:
            DefaultSecureChannelManager instance
        """
        from .default_secure_channel_manager import DefaultSecureChannelManager

        # Handle dict config or convert to DefaultSecureChannelManagerConfig
        if isinstance(config, dict):
            effective_config = DefaultSecureChannelManagerConfig(**config)
        elif config is None:
            effective_config = DefaultSecureChannelManagerConfig()
        else:
            effective_config = config

        # Create the manager with custom TTL if specified
        manager = DefaultSecureChannelManager()
        if (
            effective_config.channel_ttl
            != DefaultSecureChannelManagerConfig.model_fields["channel_ttl"].default
        ):
            manager.DEFAULT_CHANNEL_TTL = effective_config.channel_ttl

        return manager

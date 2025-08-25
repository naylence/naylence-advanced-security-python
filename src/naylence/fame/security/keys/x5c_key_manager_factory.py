"""
Factory for creating DefaultKeyManager instances.
"""

from __future__ import annotations

from typing import Any, Optional

from naylence.fame.security.keys.key_manager import KeyManager
from naylence.fame.security.keys.key_manager_factory import KeyManagerConfig, KeyManagerFactory
from naylence.fame.security.keys.key_store import KeyStore
from naylence.fame.security.keys.key_store_factory import KeyStoreConfig


class X5CKeyManagerConfig(KeyManagerConfig):
    """Configuration for X5CKeyManager."""

    type: str = "X5CKeyManager"

    # Node context configuration
    has_upstream: bool = False
    node_id: Optional[str] = None

    # Optional overrides for advanced use cases
    key_store: Optional[KeyStoreConfig] = None

    model_config = {"arbitrary_types_allowed": True}


class X5CKeyManagerFactory(KeyManagerFactory):
    """Factory for creating X5CKeyManager instances."""

    is_default: bool = True
    priority: int = 100

    async def create(
        self,
        config: Optional[X5CKeyManagerConfig | dict[str, Any]] = None,
        key_store: Optional[KeyStore] = None,
        **kwargs: Any,
    ) -> KeyManager:
        """Create a DefaultKeyManager instance."""
        # Lazy import to avoid circular dependencies
        from .x5c_key_manager import X5CKeyManager

        # Use provided key_store or fall back to global singleton
        if key_store is None:
            from naylence.fame.security.keys.key_store import get_key_store

            key_store = get_key_store()

        # Use config or defaults
        if config is None:
            config = X5CKeyManagerConfig()
        elif isinstance(config, dict):
            config = X5CKeyManagerConfig(**config)

        return X5CKeyManager(key_store=key_store)

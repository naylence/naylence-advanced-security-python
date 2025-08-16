from typing import TYPE_CHECKING, Any, Dict, List, Optional

from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.security.crypto.providers.crypto_provider import CryptoProvider, get_crypto_provider
from naylence.fame.security.encryption.encryption_manager import (
    EncryptionManager,
    EncryptionOptions,
    EncryptionResult,
)
from naylence.fame.security.encryption.encryption_manager_registry import (
    get_encryption_manager_factory_registry,
)
from naylence.fame.security.encryption.secure_channel_manager import SecureChannelManager
from naylence.fame.security.keys.key_provider import KeyProvider
from naylence.fame.util.logging import getLogger

if TYPE_CHECKING:
    from naylence.fame.node.node_like import NodeLike

logger = getLogger(__name__)


class CompositeEncryptionManager(EncryptionManager, NodeEventListener):
    """
    Delegates to pluggable encryption managers based on registered factories.
    Uses the ResourceFactory extension system for pluggability.
    """

    # Default algorithm sets for backward compatibility
    DEFAULT_SEALED_ALGORITHMS = ["X25519", "ECDH-ES+A256GCM", "chacha20-poly1305", "aes-256-gcm"]
    DEFAULT_CHANNEL_ALGORITHMS = ["chacha20-poly1305-channel"]

    def __init__(
        self,
        secure_channel_manager: Optional[SecureChannelManager],
        key_provider: KeyProvider,
        crypto: Optional[CryptoProvider] = None,
        node_like=None,
        supported_sealed_algorithms: Optional[List[str]] = None,
        supported_channel_algorithms: Optional[List[str]] = None,
    ):
        self._secure_channel_manager = secure_channel_manager
        self._crypto = crypto or get_crypto_provider()
        self._key_provider = key_provider
        self._node_like = node_like

        # Store algorithm preferences for backward compatibility
        self._supported_sealed_algorithms = supported_sealed_algorithms or self.DEFAULT_SEALED_ALGORITHMS
        self._supported_channel_algorithms = supported_channel_algorithms or self.DEFAULT_CHANNEL_ALGORITHMS

        # Use factory registry for pluggable managers (auto-discovery enabled by default)
        self._factory_registry = get_encryption_manager_factory_registry()
        self._manager_instances: Dict[str, EncryptionManager] = {}

    def _is_sealed_algorithm(self, algorithm: str) -> bool:
        """Check if an algorithm is a sealed encryption algorithm."""
        return algorithm in self._supported_sealed_algorithms

    def _is_channel_algorithm(self, algorithm: str) -> bool:
        """Check if an algorithm is a channel encryption algorithm."""
        return algorithm in self._supported_channel_algorithms

    @property
    def _sealed(self) -> Optional[EncryptionManager]:
        """Backward compatibility: Get the sealed encryption manager instance."""
        # Look for any manager that handles sealed algorithms
        for factory_name, manager in self._manager_instances.items():
            factory = self._factory_registry.get_factory_for_algorithm(
                "X25519"
            )  # Try common sealed algorithm
            if factory and factory.__class__.__name__ == factory_name:
                if factory.get_encryption_type() == "sealed":
                    return manager
        return None

    @property
    def _channel(self) -> Optional[EncryptionManager]:
        """Backward compatibility: Get the channel encryption manager instance."""
        # Look for any manager that handles channel algorithms
        for factory_name, manager in self._manager_instances.items():
            factory = self._factory_registry.get_factory_for_algorithm(
                "chacha20-poly1305-channel"
            )  # Try common channel algorithm
            if factory and factory.__class__.__name__ == factory_name:
                if factory.get_encryption_type() == "channel":
                    return manager
        return None

    @property
    def _channel_with_handshake(self) -> Optional[EncryptionManager]:
        """Backward compatibility: Alias for _channel property."""
        return self._channel

    async def _ensure_default_managers(self) -> None:
        """Ensure default managers are created for backward compatibility."""
        # Create sealed manager if we have sealed algorithms
        if self._supported_sealed_algorithms and not self._sealed:
            await self._get_manager_for_algorithm(self._supported_sealed_algorithms[0])

        # Create channel manager if we have channel algorithms
        if self._supported_channel_algorithms and not self._channel:
            await self._get_manager_for_algorithm(self._supported_channel_algorithms[0])

    async def _get_manager_for_algorithm(self, algorithm: str) -> Optional[EncryptionManager]:
        """Get the encryption manager instance that handles the given algorithm."""
        factory = self._factory_registry.get_factory_for_algorithm(algorithm)
        if not factory:
            logger.debug("no_factory_found_for_algorithm", algorithm=algorithm)
            return None

        # Use factory class name as key for instance caching
        factory_key = factory.__class__.__name__

        # Lazy instantiation
        if factory_key not in self._manager_instances:
            try:
                # Create manager instance using factory
                manager = await factory.create(
                    crypto=self._crypto,
                    key_provider=self._key_provider,
                    node_like=self._node_like,
                    secure_channel_manager=self._secure_channel_manager,
                )
                self._manager_instances[factory_key] = manager
                logger.debug(
                    "created_manager_instance",
                    factory=factory_key,
                    manager_type=type(manager).__name__,
                    algorithm=algorithm,
                )
            except Exception as e:
                logger.error("failed_to_create_composite_encryption_manager", factory=factory_key, error=str(e))
                return None

        return self._manager_instances.get(factory_key)

    async def _get_manager_for_options(
        self, opts: Optional[EncryptionOptions]
    ) -> Optional[EncryptionManager]:
        """Get the encryption manager that can handle the given options."""
        factory = self._factory_registry.get_factory_for_options(opts)
        if not factory:
            logger.debug("no_factory_found_for_options", opts=opts)
            return None

        factory_key = factory.__class__.__name__

        if factory_key not in self._manager_instances:
            try:
                manager = await factory.create(
                    crypto=self._crypto,
                    key_provider=self._key_provider,
                    node_like=self._node_like,
                    secure_channel_manager=self._secure_channel_manager,
                )
                self._manager_instances[factory_key] = manager
                logger.debug(
                    "created_manager_instance_for_options",
                    factory=factory_key,
                    manager_type=type(manager).__name__,
                )
            except Exception as e:
                logger.error(
                    "failed_to_create_composite_encryption_manager", factory=factory_key, error=str(e),
                )
                return None

        return self._manager_instances[factory_key]

    async def encrypt_envelope(self, env, *, opts: Optional[EncryptionOptions] = None) -> EncryptionResult:
        """Encrypt envelope using appropriate factory-created manager."""
        manager = await self._get_manager_for_options(opts)
        if manager:
            return await manager.encrypt_envelope(env, opts=opts)
        return EncryptionResult.skipped(env)

    async def decrypt_envelope(self, env, *, opts: Optional[EncryptionOptions] = None):
        """Decrypt envelope using appropriate factory-created manager."""
        if env.sec and env.sec.enc and env.sec.enc.alg:
            manager = await self._get_manager_for_algorithm(env.sec.enc.alg)
            if manager:
                return await manager.decrypt_envelope(env, opts=opts)
        return env

    async def notify_channel_established(self, channel_id: str) -> None:
        """Notify all managers that support channel operations about channel establishment."""
        logger.debug("notifying_managers_of_channel_establishment", channel_id=channel_id)

        # Find managers that handle channel encryption
        channel_factories = self._factory_registry.get_factories_by_type("channel")
        for factory in channel_factories:
            factory_key = factory.__class__.__name__
            if factory_key in self._manager_instances:
                manager = self._manager_instances[factory_key]
                if hasattr(manager, "notify_channel_established"):
                    await manager.notify_channel_established(channel_id)
                    logger.debug(
                        "notified_manager_of_channel_establishment",
                        manager=factory_key,
                        channel_id=channel_id,
                    )

    async def notify_channel_failed(self, channel_id: str, reason: str = "handshake_failed") -> None:
        """Notify all managers that support channel operations about channel failure."""
        logger.debug("notifying_managers_of_channel_failure", channel_id=channel_id, reason=reason)

        # Find managers that handle channel encryption
        channel_factories = self._factory_registry.get_factories_by_type("channel")
        for factory in channel_factories:
            factory_key = factory.__class__.__name__
            if factory_key in self._manager_instances:
                manager = self._manager_instances[factory_key]
                if hasattr(manager, "notify_channel_failed"):
                    await manager.notify_channel_failed(channel_id, reason)  # type: ignore
                    logger.debug(
                        "notified_manager_of_channel_failure",
                        manager=factory_key,
                        channel_id=channel_id,
                        reason=reason,
                    )

    async def notify_key_available(self, key_id: str) -> None:
        """Notify all managers that support sealed encryption about key availability."""
        logger.debug("notifying_managers_of_key_availability", key_id=key_id)

        # Find managers that handle sealed encryption
        sealed_factories = self._factory_registry.get_factories_by_type("sealed")
        for factory in sealed_factories:
            factory_key = factory.__class__.__name__
            if factory_key in self._manager_instances:
                manager = self._manager_instances[factory_key]
                if hasattr(manager, "notify_key_available"):
                    await manager.notify_key_available(key_id)  # type: ignore
                    logger.debug("notified_manager_of_key_availability", manager=factory_key, key_id=key_id)

    # NodeEventListener methods
    async def on_node_started(self, node: "NodeLike") -> None:
        """Handle node initialization for all encryption managers."""
        self._node_like = node

        # Ensure default managers are created for backward compatibility
        await self._ensure_default_managers()

        # Notify all instantiated managers
        for manager in self._manager_instances.values():
            if isinstance(manager, NodeEventListener):
                await manager.on_node_started(node)

    async def on_node_attach_to_upstream(self, node: "NodeLike", attach_info: Any) -> None:
        """Handle upstream attachment for all encryption managers."""
        for manager in self._manager_instances.values():
            if isinstance(manager, NodeEventListener):
                await manager.on_node_attach_to_upstream(node, attach_info)

    async def on_node_stopped(self, node: "NodeLike") -> None:
        """Handle node shutdown for all encryption managers."""
        for manager in self._manager_instances.values():
            if isinstance(manager, NodeEventListener):
                await manager.on_node_stopped(node)

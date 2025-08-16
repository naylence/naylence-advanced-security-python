"""
Registry for encryption manager factories with algorithm-based routing.

This provides a central registry for pluggable encryption managers that can be
selected based on supported algorithms and encryption types.
"""

from typing import Dict, List, Optional

from naylence.fame.security.encryption.encryption_manager import EncryptionManagerFactory, EncryptionOptions
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class EncryptionManagerFactoryRegistry:
    """Registry for encryption manager factories with algorithm-based routing."""

    def __init__(self, auto_discover: bool = True):
        self._factories: List[EncryptionManagerFactory] = []
        self._algorithm_to_factory: Dict[str, EncryptionManagerFactory] = {}
        self._type_to_factories: Dict[str, List[EncryptionManagerFactory]] = {}
        self._auto_discovered: bool = False

        # Automatically discover and register factories from extension points
        if auto_discover:
            self._auto_discover_factories()

    def _auto_discover_factories(self) -> None:
        """Automatically discover and register factories from extension points."""
        if self._auto_discovered:
            return  # Avoid duplicate discovery

        try:
            from naylence.fame.core.util.extension_manager import ExtensionManager

            # First, ensure an ExtensionManager exists for our group
            # This will load and cache all EncryptionManagerFactory extensions
            ext_manager = ExtensionManager.lazy_init(
                group="naylence.EncryptionManagerFactory", base_type=EncryptionManagerFactory
            )

            # Now get all available extensions from the manager
            factory_names = ext_manager.available_names()

            registered_count = 0
            for factory_name in factory_names:
                # Skip the CompositeEncryptionManager factory to avoid circular dependency
                if factory_name == "CompositeEncryptionManager":
                    logger.debug(
                        "skipping_composite_factory_to_avoid_circular_dependency", factory_name=factory_name
                    )
                    continue

                try:
                    # Get the factory class and instantiate it
                    factory_class = ext_manager.get(factory_name)
                    factory_instance = factory_class()
                    self.register_factory(factory_instance)
                    registered_count += 1

                    logger.debug(
                        "auto_discovered_factory",
                        factory_name=factory_name,
                        factory_class=factory_class.__name__,
                        algorithms=factory_instance.get_supported_algorithms(),
                        encryption_type=factory_instance.get_encryption_type(),
                    )

                except Exception as e:
                    logger.warning(
                        "failed_to_auto_register_factory", factory_name=factory_name, error=str(e)
                    )

            self._auto_discovered = True
            logger.debug(
                "completed_auto_discovery",
                registered_factories=registered_count,
                total_discovered=len(factory_names),
                skipped_composite=True,
            )

        except Exception as e:
            logger.warning("failed_auto_discovery_of_factories", error=str(e))

    def register_factory(self, factory: EncryptionManagerFactory) -> None:
        """Register an encryption manager factory."""
        self._factories.append(factory)

        # Build algorithm mappings
        for algorithm in factory.get_supported_algorithms():
            # Handle algorithm conflicts with priority
            existing_factory = self._algorithm_to_factory.get(algorithm)
            if existing_factory is None or factory.get_priority() > existing_factory.get_priority():
                self._algorithm_to_factory[algorithm] = factory
                logger.debug(
                    "registered_algorithm_mapping",
                    algorithm=algorithm,
                    factory=factory.__class__.__name__,
                    priority=factory.get_priority(),
                )

        # Build type mappings
        encryption_type = factory.get_encryption_type()
        if encryption_type not in self._type_to_factories:
            self._type_to_factories[encryption_type] = []
        self._type_to_factories[encryption_type].append(factory)

        # Sort by priority (highest first)
        self._type_to_factories[encryption_type].sort(key=lambda f: f.get_priority(), reverse=True)

        logger.debug(
            "registered_encryption_manager_factory",
            factory=factory.__class__.__name__,
            encryption_type=encryption_type,
            algorithms=factory.get_supported_algorithms(),
            priority=factory.get_priority(),
        )

    def get_factory_for_algorithm(self, algorithm: str) -> Optional[EncryptionManagerFactory]:
        """Get the factory that handles a specific algorithm."""
        # Ensure auto-discovery is completed
        self._ensure_auto_discovery()
        return self._algorithm_to_factory.get(algorithm)

    def get_factory_for_options(
        self, opts: Optional[EncryptionOptions]
    ) -> Optional[EncryptionManagerFactory]:
        """Get the first factory that can handle the given options."""
        # Ensure auto-discovery is completed
        self._ensure_auto_discovery()

        for factory in self._factories:
            if factory.supports_options(opts):
                logger.debug(
                    "found_factory_for_options",
                    factory=factory.__class__.__name__,
                    encryption_type=factory.get_encryption_type(),
                )
                return factory

        logger.debug("no_factory_found_for_options", opts=opts)
        return None

    def get_factories_by_type(self, encryption_type: str) -> List[EncryptionManagerFactory]:
        """Get all factories that handle a specific encryption type."""
        # Ensure auto-discovery is completed
        self._ensure_auto_discovery()
        return self._type_to_factories.get(encryption_type, [])

    def get_all_supported_algorithms(self) -> List[str]:
        """Get all algorithms supported by registered factories."""
        # Ensure auto-discovery is completed
        self._ensure_auto_discovery()
        return list(self._algorithm_to_factory.keys())

    def _ensure_auto_discovery(self) -> None:
        """Ensure auto-discovery has been completed."""
        if not self._auto_discovered:
            self._auto_discover_factories()

    def get_registry_info(self) -> Dict:
        """Get registry information for debugging."""
        return {
            "total_factories": len(self._factories),
            "auto_discovered": self._auto_discovered,
            "algorithm_mappings": {
                alg: factory.__class__.__name__ for alg, factory in self._algorithm_to_factory.items()
            },
            "type_mappings": {
                enc_type: [f.__class__.__name__ for f in factories]
                for enc_type, factories in self._type_to_factories.items()
            },
        }

    def force_rediscovery(self) -> None:
        """Force re-discovery of extension point factories (useful for testing or dynamic loading)."""
        self._auto_discovered = False
        self._auto_discover_factories()

    def is_auto_discovered(self) -> bool:
        """Check if auto-discovery has been completed."""
        return self._auto_discovered


# Global registry instance with auto-discovery enabled
_factory_registry = EncryptionManagerFactoryRegistry(auto_discover=True)


def get_encryption_manager_factory_registry() -> EncryptionManagerFactoryRegistry:
    """Get the global encryption manager factory registry."""
    # Ensure auto-discovery is completed if not already done
    if not _factory_registry.is_auto_discovered():
        _factory_registry._auto_discover_factories()
    return _factory_registry


def register_encryption_manager_factory(factory: EncryptionManagerFactory) -> None:
    """Register an encryption manager factory with the global registry."""
    _factory_registry.register_factory(factory)

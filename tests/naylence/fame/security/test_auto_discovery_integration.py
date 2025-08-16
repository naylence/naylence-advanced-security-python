"""
Test the automatic discovery and registration of encryption manager factories.

This test validates that the EncryptionManagerFactoryRegistry correctly:
1. Auto-discovers factories from extension points
2. Registers them with proper algorithm and type mappings
3. Handles circular dependency avoidance (CompositeEncryptionManager)
4. Provides correct factory lookup functionality
"""

import pytest

from naylence.fame.security.encryption.encryption_manager_registry import (
    EncryptionManagerFactoryRegistry,
    get_encryption_manager_factory_registry,
)


class TestAutoDiscovery:
    """Test automatic discovery of encryption manager factories."""

    def test_auto_discovery_enabled_by_default(self):
        """Test that auto-discovery is enabled by default."""
        registry = EncryptionManagerFactoryRegistry()
        assert registry.is_auto_discovered(), "Auto-discovery should be enabled by default"

    def test_manual_discovery_control(self):
        """Test that auto-discovery can be disabled."""
        registry = EncryptionManagerFactoryRegistry(auto_discover=False)
        assert not registry.is_auto_discovered(), (
            "Auto-discovery should be disabled when explicitly set to False"
        )

    def test_global_registry_auto_discovery(self):
        """Test that the global registry has auto-discovery enabled."""
        registry = get_encryption_manager_factory_registry()
        assert registry.is_auto_discovered(), "Global registry should have auto-discovery enabled"

    def test_discovered_factory_types(self):
        """Test that expected factory types are discovered."""
        registry = get_encryption_manager_factory_registry()
        registry_info = registry.get_registry_info()

        # Should have at least sealed and channel types
        type_mappings = registry_info["type_mappings"]
        assert "sealed" in type_mappings, "Should discover sealed encryption factories"
        assert "channel" in type_mappings, "Should discover channel encryption factories"

        # Should have some algorithms
        algorithms = registry.get_all_supported_algorithms()
        assert len(algorithms) > 0, "Should discover some supported algorithms"

    def test_algorithm_lookup(self):
        """Test algorithm-based factory lookup."""
        registry = get_encryption_manager_factory_registry()

        # Should be able to find X25519 factory (note: uppercase X25519)
        x25519_factory = registry.get_factory_for_algorithm("X25519")
        assert x25519_factory is not None, "Should find factory for X25519 algorithm"
        assert "X25519" in x25519_factory.get_supported_algorithms(), "Factory should support X25519"

    def test_type_lookup(self):
        """Test encryption type-based factory lookup."""
        registry = get_encryption_manager_factory_registry()

        # Should find sealed encryption factories
        sealed_factories = registry.get_factories_by_type("sealed")
        assert len(sealed_factories) > 0, "Should find at least one sealed encryption factory"

        # Should find channel encryption factories
        channel_factories = registry.get_factories_by_type("channel")
        assert len(channel_factories) > 0, "Should find at least one channel encryption factory"

    def test_composite_factory_exclusion(self):
        """Test that CompositeEncryptionManager factory is excluded to avoid circular dependency."""
        registry = get_encryption_manager_factory_registry()
        registry_info = registry.get_registry_info()

        # CompositeEncryptionManager should not be in the regular factory mappings
        all_factory_names = []
        for factories in registry_info["type_mappings"].values():
            all_factory_names.extend(factories)

        assert "CompositeEncryptionManagerFactory" not in all_factory_names, (
            "CompositeEncryptionManagerFactory should be excluded to avoid circular dependency"
        )

    def test_force_rediscovery(self):
        """Test that force rediscovery works correctly."""
        registry = EncryptionManagerFactoryRegistry(auto_discover=False)
        assert not registry.is_auto_discovered(), "Should start with no auto-discovery"

        # Force rediscovery
        registry.force_rediscovery()
        assert registry.is_auto_discovered(), "Should be auto-discovered after force rediscovery"

        # Should have some factories now
        assert len(registry.get_all_supported_algorithms()) > 0, "Should have discovered algorithms"

    def test_registry_info_structure(self):
        """Test that registry info has expected structure."""
        registry = get_encryption_manager_factory_registry()
        registry_info = registry.get_registry_info()

        # Check expected keys
        expected_keys = {"total_factories", "auto_discovered", "algorithm_mappings", "type_mappings"}
        assert set(registry_info.keys()) == expected_keys, (
            f"Registry info should have keys: {expected_keys}"
        )

        # Check types
        assert isinstance(registry_info["total_factories"], int), "total_factories should be int"
        assert isinstance(registry_info["auto_discovered"], bool), "auto_discovered should be bool"
        assert isinstance(registry_info["algorithm_mappings"], dict), "algorithm_mappings should be dict"
        assert isinstance(registry_info["type_mappings"], dict), "type_mappings should be dict"

    def test_lazy_discovery(self):
        """Test that discovery happens lazily when accessing registry methods."""
        # Create registry with auto-discovery disabled
        registry = EncryptionManagerFactoryRegistry(auto_discover=False)
        assert not registry.is_auto_discovered(), "Should start without auto-discovery"

        # Accessing methods should trigger discovery
        algorithms = registry.get_all_supported_algorithms()
        assert registry.is_auto_discovered(), "Should trigger auto-discovery when accessing algorithms"
        assert len(algorithms) > 0, "Should have discovered algorithms"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

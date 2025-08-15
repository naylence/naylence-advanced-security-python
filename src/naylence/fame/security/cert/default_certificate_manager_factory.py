"""
Factory for creating DefaultCertificateManager instances.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from naylence.fame.security.cert.certificate_manager_factory import (
    CertificateManagerConfig,
    CertificateManagerFactory,
)

if TYPE_CHECKING:
    from naylence.fame.security.cert.default_certificate_manager import DefaultCertificateManager


class DefaultCertificateManagerConfig(CertificateManagerConfig):
    """Configuration for DefaultCertificateManager."""

    type: str = "DefaultCertificateManager"


class DefaultCertificateManagerFactory(CertificateManagerFactory):
    """Factory for creating DefaultCertificateManager instances with lazy loading."""

    type: str = "DefaultCertificateManager"
    is_default: bool = True  # Mark as default implementation

    async def create(
        self, config: Optional[DefaultCertificateManagerConfig | dict[str, Any]] = None, **kwargs: Any
    ) -> DefaultCertificateManager:
        """
        Create a DefaultCertificateManager instance with lazy loading.

        Args:
            config: Configuration for the certificate manager
            **kwargs: Additional keyword arguments

        Returns:
            Configured DefaultCertificateManager instance
        """
        # Lazy import to avoid circular dependencies
        from naylence.fame.security.cert.default_certificate_manager import DefaultCertificateManager

        # Handle dict config
        if isinstance(config, dict):
            config = DefaultCertificateManagerConfig(**config)
        elif config is None:
            config = DefaultCertificateManagerConfig()

        # Extract security settings and signing config
        security_settings = config.security_settings
        signing_config = config.signing_config

        return DefaultCertificateManager(security_settings=security_settings, signing_config=signing_config)

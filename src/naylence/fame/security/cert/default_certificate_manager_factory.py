"""
Factory for creating DefaultCertificateManager instances.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.security.auth.auth_injection_strategy_factory import (
    AuthInjectionStrategyConfig,
    AuthInjectionStrategyFactory,
)
from naylence.fame.security.auth.no_auth_injection_strategy_factory import NoAuthInjectionStrategyConfig
from naylence.fame.security.cert.certificate_manager import CertificateManager
from naylence.fame.security.cert.certificate_manager_factory import (
    CertificateManagerConfig,
    CertificateManagerFactory,
)


class DefaultCertificateManagerConfig(CertificateManagerConfig):
    """Configuration for DefaultCertificateManager."""

    type: str = "DefaultCertificateManager"
    ca_auth: AuthInjectionStrategyConfig = Field(
        default_factory=NoAuthInjectionStrategyConfig, description="Authentication configuration"
    )


class DefaultCertificateManagerFactory(CertificateManagerFactory):
    """Factory for creating DefaultCertificateManager instances with lazy loading."""

    type: str = "DefaultCertificateManager"
    is_default: bool = True  # Mark as default implementation

    async def create(
        self, config: Optional[DefaultCertificateManagerConfig | dict[str, Any]] = None, **kwargs: Any
    ) -> CertificateManager:
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
        security_settings = kwargs.get("security_settings", config.security_settings)
        signing = kwargs.get("signing", config.signing)

        auth_strategy = await AuthInjectionStrategyFactory.create_auth_strategy(config.ca_auth)

        return DefaultCertificateManager(
            security_settings=security_settings, signing=signing, auth_strategy=auth_strategy
        )

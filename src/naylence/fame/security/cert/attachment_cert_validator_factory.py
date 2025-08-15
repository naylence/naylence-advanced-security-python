"""
Factory and configuration for certificate-based attachment key validators.

This module provides the factory implementation and configuration for creating
certificate-based attachment key validators that validate certificates during node handshake.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional, Union

from naylence.fame.security.keys.attachment_key_validator import AttachmentKeyValidator
from naylence.fame.security.keys.attachment_key_validator_factory import (
    AttachmentKeyValidatorConfig,
    AttachmentKeyValidatorFactory,
)

if TYPE_CHECKING:
    pass


class AttachmentCertValidatorConfig(AttachmentKeyValidatorConfig):
    """Configuration for certificate-based attachment key validator."""

    type: str = "AttachmentCertValidator"
    trust_store: Optional[str] = None
    enforce_name_constraints: bool = True
    strict_validation: bool = True


class AttachmentCertValidatorFactory(AttachmentKeyValidatorFactory[AttachmentCertValidatorConfig]):
    """Factory for creating certificate-based attachment key validators."""

    type = "AttachmentCertValidator"

    async def create(
        self, config: Optional[Union[AttachmentCertValidatorConfig, Dict[str, Any]]] = None, **kwargs
    ) -> AttachmentKeyValidator:
        """Create an AttachmentCertValidator instance."""
        # Lazy import to avoid circular dependencies
        from naylence.fame.security.cert.attachment_cert_validator import AttachmentCertValidator

        if config is None:
            typed_config = AttachmentCertValidatorConfig()
        elif isinstance(config, dict):
            typed_config = AttachmentCertValidatorConfig.model_validate(config)
        else:
            typed_config = config

        # Pass individual properties instead of entire config
        return AttachmentCertValidator(
            trust_store=typed_config.trust_store,
            enforce_name_constraints=typed_config.enforce_name_constraints,
            strict_validation=typed_config.strict_validation,
        )

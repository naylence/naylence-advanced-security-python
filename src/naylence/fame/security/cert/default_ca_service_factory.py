from typing import Annotated, Any, Optional

from pydantic import Field

from naylence.fame.factory import create_resource
from naylence.fame.security.auth.authorizer_factory import AuthorizerConfig, AuthorizerFactory
from naylence.fame.security.cert.ca_service import CAService
from naylence.fame.security.cert.ca_service_factory import (
    CAServiceConfig,
    CAServiceFactory,
)
from naylence.fame.security.credential.credential_provider_factory import (
    CredentialProviderConfig,
    EnvCredentialProviderConfig,
)
from naylence.fame.security.credential.secret_source import SecretSource


class DefaultCAServiceConfig(CAServiceConfig):
    type: str = "DefaultCAService"

    ca_cert_pem: Annotated[CredentialProviderConfig, SecretSource] = Field(
        default=EnvCredentialProviderConfig(var_name="FAME_CA_CERT"),
        description="CA certificate from various sources (plain text, env://VAR, secret://name, "
        "or provider config)",
    )

    ca_key_pem: Annotated[CredentialProviderConfig, SecretSource] = Field(
        default=EnvCredentialProviderConfig(var_name="FAME_CA_KEY"),
        description="CA private key from various sources (plain text, env://VAR, secret://name, "
        "or provider config)",
    )

    intermediate_chain_pem: Annotated[CredentialProviderConfig, SecretSource] = Field(
        default=EnvCredentialProviderConfig(var_name="FAME_CA_INTERMEDIATE_CHAIN"),
        description="CA intermediate chain from various sources (plain text, env://VAR, secret://name, "
        "or provider config)",
    )

    signing_cert_pem: Annotated[CredentialProviderConfig, SecretSource] = Field(
        default=EnvCredentialProviderConfig(var_name="FAME_SIGNING_CERT"),
        description="Signing certificate from various sources (plain text, env://VAR, secret://name, "
        "or provider config)",
    )

    signing_key_pem: Annotated[CredentialProviderConfig, SecretSource] = Field(
        default=EnvCredentialProviderConfig(var_name="FAME_SIGNING_KEY"),
        description="Signing key from various sources (plain text, env://VAR, secret://name, "
        "or provider config)",
    )

    authorizer: Optional[AuthorizerConfig] = Field(
        default=None,
        description="Authorization configuration for the CA service",
    )


class DefaultCAServiceFactory(CAServiceFactory[DefaultCAServiceConfig]):
    """Factory for DefaultCAService."""

    is_default: bool = True

    async def create(
        self,
        config: Optional[DefaultCAServiceConfig | dict[str, Any]] = None,
        **kwargs: dict[str, Any],
    ) -> CAService:
        from naylence.fame.security.cert.default_ca_service import (
            DefaultCAService,
        )

        if isinstance(config, dict):
            config = DefaultCAServiceConfig.model_validate(config)
        elif config is None:
            config = DefaultCAServiceConfig()

        # ca_cert_provider = await create_resource(CredentialProviderFactory, config.ca_cert_pem)
        # ca_key_provider = await create_resource(CredentialProviderFactory, config.ca_key_pem)
        # intermediate_chain_provider = await create_resource(
        #     CredentialProviderFactory, config.intermediate_chain_pem
        # )
        # signing_cert_provider = await create_resource(CredentialProviderFactory, config.signing_cert_pem)
        # signing_key_provider = await create_resource(CredentialProviderFactory, config.signing_key_pem)

        authorizer = None
        if config.authorizer:
            authorizer = await create_resource(AuthorizerFactory, config.authorizer)

        return DefaultCAService(
            # ca_cert_pem=ca_cert_provider,
            # ca_key_pem=ca_key_provider,
            # intermediate_chain_pem=intermediate_chain_provider,
            # signing_cert_pem=signing_cert_provider,
            # signing_key_pem=signing_key_provider,
            authorizer=authorizer,
        )

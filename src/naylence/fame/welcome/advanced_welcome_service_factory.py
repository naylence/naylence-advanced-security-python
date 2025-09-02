from __future__ import annotations

from typing import Any, Optional

from pydantic import ConfigDict

from naylence.fame.security.auth.authorizer_factory import AuthorizerFactory
from naylence.fame.security.auth.token_issuer_factory import (
    TokenIssuerFactory,
)
from naylence.fame.transport.transport_provisioner import (
    TransportProvisionerFactory,
)
from naylence.fame.welcome.default_welcome_service_factory import DefaultWelcomeServiceConfig
from naylence.fame.welcome.welcome_service import (
    WelcomeService,
)
from naylence.fame.welcome.welcome_service_factory import WelcomeServiceFactory


class AdvancedWelcomeServiceConfig(DefaultWelcomeServiceConfig):
    type: str = "AdvancedWelcomeService"

    ca_service_url: str

    model_config = ConfigDict(extra="allow")


class AdvancedWelcomeServiceFactory(WelcomeServiceFactory):
    is_default: bool = True
    priority: int = 100

    async def create(
        self,
        config: Optional[AdvancedWelcomeServiceConfig | dict[str, Any]] = None,
        **kwargs: dict[str, Any],
    ) -> WelcomeService:
        from naylence.fame.placement.node_placement_strategy import (
            NodePlacementStrategyFactory,
        )
        from naylence.fame.welcome.advanced_welcome_service import AdvancedWelcomeService

        if config is None:
            raise RuntimeError("AdvancedWelcomeService requires configuration")

        if isinstance(config, dict):
            config = AdvancedWelcomeServiceConfig(**config)

        placement_strategy = await NodePlacementStrategyFactory.create_node_placement_strategy(
            config.placement if config else None, **kwargs
        )

        transport_provider = await TransportProvisionerFactory.create_transport_provisioner(
            config.transport if config else None, **kwargs
        )

        token_issuer = await TokenIssuerFactory.create_token_issuer(
            config.token_issuer if config else None, **kwargs
        )

        authorizer = None
        if config and config.authorizer:
            authorizer = await AuthorizerFactory.create_authorizer(config.authorizer)

        return AdvancedWelcomeService(
            placement_strategy=placement_strategy,
            transport_provisioner=transport_provider,
            token_issuer=token_issuer,
            authorizer=authorizer,
            ca_service_url=config.ca_service_url,
        )

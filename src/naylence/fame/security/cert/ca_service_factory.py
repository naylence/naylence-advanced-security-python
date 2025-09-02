from typing import Any, Optional, TypeVar

from pydantic import ConfigDict

from naylence.fame.factory import ResourceConfig, ResourceFactory, create_default_resource, create_resource
from naylence.fame.security.cert.ca_service import CAService


class CAServiceConfig(ResourceConfig):
    type: str = "CAService"

    model_config = ConfigDict(extra="allow")


C = TypeVar("C", bound=CAServiceConfig)


class CAServiceFactory(ResourceFactory[CAService, C]):
    @staticmethod
    async def create_ca_service(
        config: Optional[CAServiceConfig | dict[str, Any]] = None, **kwargs
    ) -> CAService:
        if not config:
            from naylence.fame.config.config import ExtendedFameConfig, get_fame_config

            fame_config = get_fame_config()
            assert isinstance(fame_config, ExtendedFameConfig)
            # Access 'ca' from extra attributes since it's not explicitly defined
            config = getattr(fame_config, "ca", None) or (
                fame_config.__pydantic_extra__.get("ca") if fame_config.__pydantic_extra__ else None
            )

        if config is None:
            service = await create_default_resource(CAServiceFactory, config, **kwargs)
            assert service is not None
            return service
        elif isinstance(config, dict):
            if "type" not in config:
                service = await create_default_resource(CAServiceFactory, config, **kwargs)
                assert service is not None
                return service
            else:
                config = CAServiceConfig(**config)
        elif not isinstance(config, CAServiceConfig):
            raise ValueError(f"Invalid config type: {type(config)}")

        return await create_resource(CAServiceFactory, config, **kwargs)

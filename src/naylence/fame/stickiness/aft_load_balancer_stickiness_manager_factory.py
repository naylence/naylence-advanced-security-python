from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.security.keys.key_provider import KeyProvider
from naylence.fame.stickiness.aft_verifier import AFTVerifier
from naylence.fame.stickiness.load_balancer_stickiness_manager import LoadBalancerStickinessManager
from naylence.fame.stickiness.load_balancer_stickiness_manager_factory import (
    LoadBalancerStickinessManagerConfig,
    LoadBalancerStickinessManagerFactory,
)
from naylence.fame.stickiness.stickiness_mode import StickinessMode


class AFTLoadBalancerStickinessManagerConfig(LoadBalancerStickinessManagerConfig):
    type: str = "AFTLoadBalancerStickinessManager"

    enabled: bool = Field(default=True, description="Master switch for entire feature")

    client_echo: bool = Field(default=False, description="Whether sentinel forwards `aft` to clients")

    default_ttl_sec: int = Field(default=30, description="Fallback TTL if replica omits `exp`")

    cache_max: int = Field(default=100_000, description="Max AFTs kept in memory (LRU)")

    security_level: StickinessMode = Field(
        default=StickinessMode.SIGNED_OPTIONAL,
        description="Security policy level for AFT verification",
    )

    max_ttl_sec: int = Field(default=7200, description="Maximum allowed TTL for AFTs (2 hours)")


class AFTLoadBalancerStickinessManagerFactory(LoadBalancerStickinessManagerFactory):
    is_default: bool = False

    async def create(
        self,
        config: Optional[AFTLoadBalancerStickinessManagerConfig | dict[str, Any]] = None,
        key_provider: Optional[KeyProvider] = None,
        verifier: Optional[AFTVerifier] = None,
        **kwargs: Any,
    ) -> LoadBalancerStickinessManager:
        # Lazy imports to avoid heavy deps until needed
        from naylence.fame.stickiness.aft_load_balancer_stickiness_manager import (
            AFTLoadBalancerStickinessManager,
        )
        from naylence.fame.stickiness.aft_verifier import create_aft_verifier

        cfg: Optional[AFTLoadBalancerStickinessManagerConfig] = None
        if isinstance(config, AFTLoadBalancerStickinessManagerConfig):
            cfg = config
        elif isinstance(config, dict):
            cfg = AFTLoadBalancerStickinessManagerConfig.model_validate(config)
        else:
            cfg = AFTLoadBalancerStickinessManagerConfig()

        # key_provider = kwargs.get("key_provider")
        if verifier is None and key_provider is not None:
            verifier = create_aft_verifier(
                cfg.security_level,
                key_provider,
                cfg.default_ttl_sec,
            )

        assert verifier is not None, "AFTVerifier must be provided or created"

        return AFTLoadBalancerStickinessManager(cfg, verifier)

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.stickiness.stickiness_mode import StickinessMode

from .replica_stickiness_manager import ReplicaStickinessManager
from .replica_stickiness_manager_factory import (
    ReplicaStickinessManagerConfig,
    ReplicaStickinessManagerFactory,
)


class AFTReplicaStickinessManagerConfig(ReplicaStickinessManagerConfig):
    type: str = "AFTReplicaStickinessManager"

    security_level: StickinessMode = Field(
        default=StickinessMode.SIGNED_OPTIONAL,
        description="Security policy level for AFT verification",
    )

    max_ttl_sec: int = Field(default=7200, description="Maximum allowed TTL for AFTs (2 hours)")


class AFTReplicaStickinessManagerFactory(ReplicaStickinessManagerFactory):
    is_default: bool = True

    async def create(
        self, config: Optional[AFTReplicaStickinessManagerConfig | dict[str, Any]] = None, **kwargs: Any
    ) -> ReplicaStickinessManager:
        # Lazy import to avoid importing implementation unless needed
        from naylence.fame.stickiness.aft_replica_stickiness_manager import (
            AFTReplicaStickinessManager,
        )

        cfg: Optional[AFTReplicaStickinessManagerConfig] = None
        if isinstance(config, AFTReplicaStickinessManagerConfig):
            cfg = config
        elif isinstance(config, dict):
            # Best-effort to coerce dict to config; tolerate None
            cfg = AFTReplicaStickinessManagerConfig.model_validate(config)

        return AFTReplicaStickinessManager(
            aft_helper=None,
            security_level=cfg.security_level if cfg else None,
            max_ttl_sec=cfg.max_ttl_sec if cfg else 7200,
        )

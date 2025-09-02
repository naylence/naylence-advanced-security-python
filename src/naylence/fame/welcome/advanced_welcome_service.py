from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Optional

from naylence.fame.core import NodeHelloFrame, NodeWelcomeFrame, generate_id
from naylence.fame.grants.http_connection_grant import HttpConnectionGrant
from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.auth.bearer_token_header_auth_injection_strategy_factory import (
    BearerTokenHeaderAuthInjectionStrategyConfig,
)
from naylence.fame.security.auth.static_token_provider_factory import (
    StaticTokenProviderConfig,
)
from naylence.fame.security.auth.token_issuer import TokenIssuer
from naylence.fame.security.cert.grants import GRANT_PURPOSE_CA_SIGN
from naylence.fame.util.formatter import AnsiColor, color, format_timestamp
from naylence.fame.util.util import pretty_model
from naylence.fame.welcome.welcome_service import WelcomeService

if TYPE_CHECKING:
    from naylence.fame.placement.node_placement_strategy import (
        NodePlacementStrategy,
    )
    from naylence.fame.transport.transport_provisioner import (
        TransportProvisioner,
        TransportProvisionResult,
    )

from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)

ENV_VAR_SHOW_ENVELOPES = "FAME_SHOW_ENVELOPES"

show_envelopes = bool(os.getenv(ENV_VAR_SHOW_ENVELOPES) == "true")


def _timestamp() -> str:
    return color(format_timestamp(), AnsiColor.GRAY)


class AdvancedWelcomeService(WelcomeService):
    def __init__(
        self,
        placement_strategy: NodePlacementStrategy,
        transport_provisioner: TransportProvisioner,
        token_issuer: TokenIssuer,
        ca_service_url: str,
        authorizer: Optional[Authorizer] = None,
        ttl_sec: int = 3600,
    ):
        self._placement_strategy = placement_strategy
        self._token_issuer = token_issuer
        self._transport_provisioner = transport_provisioner
        self._authorizer = authorizer
        self._ca_service_url = ca_service_url
        self._ttl = ttl_sec

        logger.debug(
            "initialized_advanced_welcome_service",
            ca_service_url=self._ca_service_url,
            ttl_sec=self._ttl,
        )

    @property
    def authorizer(self) -> Optional[Authorizer]:
        return self._authorizer

    async def handle_hello(
        self,
        hello: NodeHelloFrame,
        # parent_physical_path: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> NodeWelcomeFrame:
        if show_envelopes:
            if show_envelopes:
                print(
                    f"\n{_timestamp()} - {color('Received envelope 📨', AnsiColor.BLUE)}\n{
                        pretty_model(hello)
                    }"
                )

        logger.debug(
            "starting_hello_frame_processing",
            instance_id=hello.instance_id,
            system_id=hello.system_id,
            logicals=hello.logicals,
            capabilities=hello.capabilities,
            ttl_sec=self._ttl,
        )

        now = datetime.now(timezone.utc)
        expiry = now + timedelta(seconds=self._ttl)
        full_metadata = dict(metadata or {})
        full_metadata.setdefault("instance_id", hello.instance_id)

        # 0 ─ ensure we have a system_id (server-assigned on first connect)
        system_id = hello.system_id or generate_id()

        hello = hello.model_copy(update={"system_id": system_id})

        logger.debug(
            "system_id_assignment_completed",
            system_id=system_id,
            was_assigned=hello.system_id is None,
        )

        # Validate logicals for DNS hostname compatibility
        from naylence.fame.util.logicals_util import validate_host_logicals

        if hello.logicals:
            logger.debug("validating_logicals_for_dns_compatibility", logicals=hello.logicals)
            paths_valid, path_error = validate_host_logicals(hello.logicals)
            if not paths_valid:
                logger.error("logical_validation_failed", error=path_error, logicals=hello.logicals)
                raise Exception(f"Invalid logical format: {path_error}")
            logger.debug("logicals_validation_successful")

        logger.debug("requesting_node_placement", system_id=system_id)
        placement_result = await self._placement_strategy.place(hello)

        if not placement_result.accept:
            logger.error(
                "node_placement_rejected",
                system_id=system_id,
                reason=placement_result.reason,
            )
            raise Exception(placement_result.reason or "Node not accepted")

        logger.debug(
            "node_placement_accepted",
            system_id=system_id,
            assigned_path=placement_result.assigned_path,
            target_physical_path=placement_result.target_physical_path,
            target_system_id=placement_result.target_system_id,
        )

        assigned_path = placement_result.assigned_path
        accepted_capabilities = (
            placement_result.metadata.get("accepted_capabilities") if placement_result.metadata else None
        )
        accepted_logicals = (
            placement_result.metadata.get("accepted_logicals")
            if placement_result.metadata
            else hello.logicals
        )

        connection_grants = []

        logger.debug(
            "processing_placement_result_metadata",
            accepted_capabilities=accepted_capabilities,
            accepted_logicals=accepted_logicals,
            has_placement_metadata=placement_result.metadata is not None,
        )

        if placement_result.target_system_id:
            logger.debug("issuing_token", system_id=system_id, assigned_path=assigned_path)
            node_attach_token = self._token_issuer.issue(
                claims={
                    "aud": placement_result.target_physical_path,
                    "system_id": system_id,
                    "parent_path": placement_result.target_physical_path,
                    "assigned_path": placement_result.assigned_path,
                    "accepted_logicals": accepted_logicals,
                    "instance_id": full_metadata.get("instance_id") or generate_id(),
                },
            )
            logger.debug("token_issued_successfully")

            logger.debug("provisioning_transport", system_id=system_id)
            transport_info: TransportProvisionResult = await self._transport_provisioner.provision(
                placement_result, hello, full_metadata, node_attach_token
            )

            connection_grants.append(transport_info.connection_grant)

            logger.debug(
                "transport_provisioned_successfully",
                system_id=system_id,
                directive_type=type(transport_info.connection_grant).__name__,
            )

        ca_sign_token = self._token_issuer.issue(
            claims={
                "aud": "ca",
                "system_id": system_id,
                "assigned_path": placement_result.assigned_path,
                "accepted_logicals": accepted_logicals,
                "instance_id": full_metadata.get("instance_id") or generate_id(),
            },
        )

        ca_connection_grant = HttpConnectionGrant(
            purpose=GRANT_PURPOSE_CA_SIGN,
            url=self._ca_service_url,
            auth=BearerTokenHeaderAuthInjectionStrategyConfig(
                token_provider=StaticTokenProviderConfig(token=ca_sign_token, type="StaticTokenProvider")
            ),
        )

        connection_grants.append(ca_connection_grant)

        welcome_frame = NodeWelcomeFrame(
            system_id=system_id,
            target_system_id=placement_result.target_system_id,
            instance_id=hello.instance_id,
            assigned_path=assigned_path,
            accepted_capabilities=accepted_capabilities,
            accepted_logicals=accepted_logicals,
            rejected_logicals=None,  # Optional: enhance later
            target_physical_path=placement_result.target_physical_path,
            connection_grants=connection_grants,
            metadata=full_metadata,
            expires_at=expiry,
        )

        logger.debug(
            "hello_frame_processing_completed_successfully",
            system_id=system_id,
            assigned_path=assigned_path,
            accepted_logicals=accepted_logicals,
            accepted_capabilities=accepted_capabilities,
            expires_at=expiry,
            instance_id=hello.instance_id,
        )

        if show_envelopes:
            print(
                f"\n{_timestamp()} - {color('Sent envelope', AnsiColor.BLUE)} 🚀\n{
                    pretty_model(welcome_frame)
                }"
            )

        return welcome_frame

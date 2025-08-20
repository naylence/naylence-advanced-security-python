from __future__ import annotations

from typing import Any, Optional

from naylence.fame.core import (
    DeliveryOriginType,
    FameDeliveryContext,
    FameEnvelope,
    Stickiness,
)
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.node_like import NodeLike
from naylence.fame.stickiness.aft_helper import AFTHelper
from naylence.fame.stickiness.replica_stickiness_manager import ReplicaStickinessManager
from naylence.fame.stickiness.stickiness_mode import StickinessMode
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class AFTReplicaStickinessManager(NodeEventListener, ReplicaStickinessManager):
    """
    Handles automatic AFT token injection based on FameDeliveryContext.stickiness_required flag.

    This implements the behavioral contract where:
    1. Code sets context.stickiness_required = True when affinity is needed
    2. Outbound pipeline automatically applies AFT instructions
    3. Flag is automatically cleared per-delivery (context is per-delivery)

    This handler must be registered BEFORE AFTLoadBalancerStickinessManager in the event listener chain
    to ensure AFT tokens are set before the AFTLoadBalancerStickinessManager processes them.
    """

    def __init__(
        self,
        security_level: Optional[StickinessMode] = None,
        aft_helper: Optional[AFTHelper] = None,
        max_ttl_sec: int = 7200,
    ):
        self._security_level = security_level or StickinessMode.SIGNED_OPTIONAL
        self._aft_helper = aft_helper
        self._max_ttl_sec = max_ttl_sec
        self._is_initialized = aft_helper is not None
        # Negotiated policy from parent, if any
        self._negotiated_stickiness = None  # type: Optional[Stickiness]

        if self._aft_helper:
            logger.debug(
                "aft_replica_stickiness_manager_initialized",
                helper_type=type(self._aft_helper).__name__,
                security_level=self._aft_helper.signer.security_level.value,
            )
        else:
            logger.debug("aft_replica_stickiness_manager_created")

    async def on_forward_upstream(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Any:
        """
        Handle upstream forwarding - check for stickiness_required flag and apply AFT if needed.
        """
        if not context:
            return envelope

        if not self._aft_helper:
            # Not initialized yet; we can’t inject AFT now. Proceed without modification.
            logger.debug(
                "aft_helper_not_ready_skip_injection",
                envelope_id=envelope.id,
                delivery_origin=context.origin_type,
                reason="not_initialized",
            )
            return envelope

        if context.stickiness_required and context.origin_type == DeliveryOriginType.LOCAL:
            # If parent explicitly disabled or chose non-AFT mode, skip injection
            if self._negotiated_stickiness is not None:
                if not self._negotiated_stickiness.enabled or (
                    self._negotiated_stickiness.mode is not None
                    and self._negotiated_stickiness.mode != "aft"
                ):
                    logger.debug(
                        "aft_injection_skipped_due_to_policy",
                        envelope_id=envelope.id,
                        policy_mode=getattr(self._negotiated_stickiness, "mode", None),
                        policy_enabled=getattr(self._negotiated_stickiness, "enabled", None),
                    )
                    return envelope
            logger.debug(
                "applying_aft_for_upstream_stickiness_required",
                envelope_id=envelope.id,
                from_system_id=context.from_system_id,
                delivery_origin=context.origin_type,
            )

            success = self._aft_helper.request_stickiness(
                envelope, ttl_sec=None, scope="node", context=context
            )

            if success:
                logger.debug(
                    "aft_token_applied_via_context_flag_upstream",
                    envelope_id=envelope.id,
                    from_system_id=context.from_system_id,
                    delivery_origin=context.origin_type,
                )
            else:
                logger.debug(
                    "aft_token_not_applied_upstream",
                    envelope_id=envelope.id,
                    delivery_origin=context.origin_type,
                    reason="helper_returned_false",
                )

        return envelope

    # ReplicaStickinessManager implementation
    def offer(self) -> Optional[Stickiness]:
        """Advertise stickiness capabilities during NodeAttach.

        Prefer 'aft' but always include 'attr' as a compatible fallback.
        """

        return Stickiness(mode="aft", supported_modes=["aft", "attr"], version=1)

    def accept(self, stickiness: Optional[Stickiness]) -> None:
        """Accept negotiated policy from parent and cache locally for gating."""
        self._negotiated_stickiness = stickiness
        logger.debug(
            "replica_stickiness_policy_set",
            enabled=stickiness.enabled if stickiness else None,
            mode=stickiness.mode if stickiness else None,
            ttl=stickiness.ttl_sec if stickiness else None,
        )

    async def on_node_started(self, node: NodeLike) -> None:
        """Handle node startup - initialize AFT helper with proper node SID and crypto provider key ID."""
        # If we need to self-initialize, do it now with proper node SID
        if not self._is_initialized:
            await self._initialize_aft_helper(node)

        # If already initialized, just update the SID (legacy behavior)
        elif self._is_initialized and self._aft_helper and node.sid:
            actual_sid = node.sid
            if actual_sid:
                self.update_node_sid(actual_sid)
                logger.debug(
                    "aft_replica_stickiness_manager_sid_updated",
                    node_id=node.id,
                    node_sid=actual_sid,
                    security_level=self._aft_helper.signer.security_level.value,
                )
            else:
                logger.warning(
                    "aft_replica_stickiness_manager_no_sid_available",
                    node_id=node.id if node.id else "unknown",
                )
        else:
            logger.error(
                "aft_replica_stickiness_manager_node_missing_sid",
                node_type=type(node).__name__,
            )

    async def _initialize_aft_helper(self, node: NodeLike):
        """Initialize AFT helper with proper node SID and crypto provider key ID."""
        try:
            from naylence.fame.security.crypto.providers.crypto_provider import (
                get_crypto_provider,
            )
            from naylence.fame.stickiness.aft_helper import create_aft_helper

            # Get the proper node SID (secure hash of physical path)
            if not node.sid:
                logger.error(
                    "aft_replica_stickiness_manager_cannot_initialize_no_sid",
                    node_id=node.id if node.id else "unknown",
                )
                return

            # Get crypto provider to get the proper key ID
            crypto_provider = get_crypto_provider()
            key_id = (
                crypto_provider.signature_key_id
                if hasattr(crypto_provider, "signature_key_id")
                else "default-key-id"
            )

            # Create AFT helper with proper values
            self._aft_helper = create_aft_helper(
                security_level=self._security_level,
                node_sid=node.sid,
                kid=key_id,
                private_key_pem=crypto_provider.signing_private_pem,
                max_ttl_sec=self._max_ttl_sec,
            )

            self._is_initialized = True

            logger.debug(
                "aft_replica_stickiness_manager_initialized",
                node_id=node.id or "unknown",
                node_sid=node.sid,
                key_id=key_id,
                security_level=(
                    self._aft_helper.signer.security_level.value if self._aft_helper else "unknown"
                ),
            )

        except Exception as e:
            logger.error(
                "aft_replica_stickiness_manager_initialization_failed",
                node_id=getattr(node, "id", "unknown"),
                error=str(e),
            )

    def update_node_sid(self, node_sid: str):
        """Update the node SID for the AFT helper after node initialization."""
        if self._aft_helper:
            self._aft_helper.node_sid = node_sid
            logger.debug(
                "aft_replica_stickiness_manager_sid_updated",
                new_sid=node_sid,
            )


def create_aft_replica_stickiness_manager(aft_helper: AFTHelper) -> AFTReplicaStickinessManager:
    """Factory function to create an AFT context handler."""
    return AFTReplicaStickinessManager(aft_helper=aft_helper)

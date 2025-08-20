"""
Stickiness Manager for Sentinels.

This component manages AFT (Affinity Tag) associations and routing decisions
for sentinels implementing session affinity. It also implements NodeEventListener
to automatically process AFT setter instructions from downstream responses.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import Any, Dict, Optional, Sequence

from naylence.fame.core import DeliveryOriginType, FameDeliveryContext, FameEnvelope, Stickiness
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.node_like import NodeLike
from naylence.fame.stickiness.aft_load_balancer_stickiness_manager_factory import (
    AFTLoadBalancerStickinessManagerConfig,
)
from naylence.fame.stickiness.aft_verifier import AFTVerifier
from naylence.fame.stickiness.load_balancer_stickiness_manager import LoadBalancerStickinessManager
from naylence.fame.stickiness.stickiness_mode import StickinessMode
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class AFTAssociation:
    """Association between an AFT and a replica."""

    def __init__(
        self,
        replica_id: str,
        token: str,
        sid: str,
        exp: int,
        trust_level: str,
        scope: Optional[str] = None,
        client_sid: Optional[str] = None,
    ):
        self.replica_id = replica_id
        self.token = token
        self.sid = sid
        self.exp = exp
        self.trust_level = trust_level
        self.scope = scope
        self.client_sid = client_sid
        self.created_at = int(time.time())

    def is_expired(self) -> bool:
        """Check if this association has expired."""
        return int(time.time()) >= self.exp

    def is_low_trust(self) -> bool:
        """Check if this is a low-trust association."""
        return self.trust_level == "low-trust"


class AFTLoadBalancerStickinessManager(NodeEventListener, LoadBalancerStickinessManager):
    """
    Manages session affinity for a sentinel.

    Handles AFT verification, association caching, routing decisions, and
    automatically processes AFT setter instructions via NodeEventListener.
    """

    def __init__(self, config: AFTLoadBalancerStickinessManagerConfig, verifier: AFTVerifier):
        self.config = config
        self.verifier = verifier

        # AFT token -> association mapping
        self._aft_associations: OrderedDict[str, AFTAssociation] = OrderedDict()

        # SID -> latest token mapping (for node-wide stickiness)
        self._sid_cache: Dict[str, str] = {}

        # Metrics
        self._metrics = {
            "cache_hits": 0,
            "cache_misses": 0,
            "verify_failures": 0,
            "associations_created": 0,
            "associations_expired": 0,
        }

        logger.debug(
            "stickiness_manager_initialized",
            enabled=config.enabled,
            security_level=config.security_level.value,
            verifier_type=type(verifier).__name__,
            default_ttl=config.default_ttl_sec,
            cache_max=config.cache_max,
            client_echo=config.client_echo,
        )

    # LoadBalancerStickinessManager implementation
    def negotiate(self, stickiness: Optional[Stickiness]) -> Optional[Stickiness]:
        """Negotiate stickiness policy with a child based on local config and child offer.

        Returns an Optional[Stickiness] to be placed into NodeAttachAck. If config is disabled, return
        a disabled policy when an offer exists, else None for minimal wire.
        """
        # If no offer from child:
        # - If sentinel stickiness is enabled, advertise attribute mode which requires
        #   no replica participation.
        # - Otherwise, keep the handshake lean and send nothing.
        if stickiness is None:
            if self.config.enabled:
                logger.debug("stickiness_negotiated_no_offer_attr_fallback")
                return Stickiness(enabled=True, mode="attr", version=1)
            return None

        if not self.config.enabled:
            logger.debug("stickiness_negotiation_disabled_by_config")
            return Stickiness(enabled=False, version=stickiness.version or 1)

        # Prefer AFT if child supports it and verifier exists
        child_modes = set(
            stickiness.supported_modes or ([] if stickiness.mode is None else [stickiness.mode])
        )
        if "aft" in child_modes and self.verifier is not None:
            ttl = self.config.default_ttl_sec
            policy = Stickiness(enabled=True, mode="aft", ttl_sec=ttl, version=stickiness.version or 1)
            logger.debug("stickiness_negotiated", mode=policy.mode, ttl=ttl)
            return policy

        # Fallback to attribute-based if child indicated it
        if "attr" in child_modes:
            policy = Stickiness(enabled=True, mode="attr", version=stickiness.version or 1)
            logger.debug("stickiness_negotiated", mode=policy.mode)
            return policy

        # If nothing compatible, explicitly disable
        logger.debug("stickiness_negotiation_no_common_mode")
        return Stickiness(enabled=False, version=stickiness.version or 1)

    @property
    def sid_cache(self) -> Dict[str, str]:
        """Expose SID cache for load balancing strategy access."""
        return self._sid_cache

    async def handle_outbound_envelope(self, envelope: FameEnvelope, replica_id: str) -> Optional[str]:
        """
        Handle an envelope from a replica that may contain AFT instructions.

        Args:
            envelope: The envelope from the replica
            replica_id: ID of the replica that sent the envelope

        Returns:
            AFT token to cache for future routing, or None
        """
        if not self.config.enabled:
            logger.debug("stickiness_disabled", envelope_id=envelope.id)
            return None

        # Check for AFT instruction in meta (nested format preferred,
        # flat format for backward compatibility)
        aft_token = None
        if envelope.meta:
            # Try nested format first: meta["set"]["aft"]
            if "set" in envelope.meta and isinstance(envelope.meta["set"], dict):
                set_meta = envelope.meta["set"]
                if "aft" in set_meta:
                    aft_token = set_meta["aft"]

            # Fallback to flat format: meta["set.aft"]
            elif "set.aft" in envelope.meta:
                aft_token = envelope.meta["set.aft"]

        if not aft_token:
            logger.debug(
                "no_aft_instruction",
                envelope_id=envelope.id,
                has_meta=envelope.meta is not None,
                meta_keys=list(envelope.meta.keys()) if envelope.meta else [],
            )
            return None
        logger.debug(
            "found_aft_instruction",
            envelope_id=envelope.id,
            replica_id=replica_id,
            aft_type=type(aft_token).__name__,
            aft_preview=(str(aft_token)[:20] + "..." if len(str(aft_token)) > 20 else str(aft_token)),
        )
        if not isinstance(aft_token, str):
            logger.warning(
                "invalid_aft_instruction",
                envelope_id=envelope.id,
                replica_id=replica_id,
                reason="set.aft value is not a string",
            )
            return None

        # Verify the AFT
        result = await self.verifier.verify(aft_token, envelope.sid)

        if not result.valid:
            self._metrics["verify_failures"] += 1
            logger.warning(
                "aft_verification_failed",
                envelope_id=envelope.id,
                replica_id=replica_id,
                error=result.error,
            )
            return None

        # Create association
        association = AFTAssociation(
            replica_id=replica_id,
            token=aft_token,
            sid=result.sid or "",
            exp=result.exp or 0,
            trust_level=result.trust_level,
            scope=result.scope,
            client_sid=result.client_sid,
        )

        # Store association
        self._store_association(aft_token, association)

        # Update SID cache for node-wide stickiness using original client SID
        if result.client_sid:
            self._sid_cache[result.client_sid] = replica_id
            logger.debug(
                "sid_cache_updated",
                envelope_id=envelope.id,
                client_sid=result.client_sid,
                replica_id=replica_id,
            )

        self._metrics["associations_created"] += 1

        logger.debug(
            "aft_association_created",
            envelope_id=envelope.id,
            replica_id=replica_id,
            sid=result.sid,
            exp=result.exp,
            trust_level=result.trust_level,
            scope=result.scope,
        )

        # Return the token for potential client echo
        return aft_token if self.config.client_echo else None

    def get_sticky_replica_segment(
        self, envelope: FameEnvelope, segments: Optional[Sequence[str]] = None
    ) -> Optional[str]:
        """
        Handle an inbound envelope that may have an AFT for routing.

        Args:
            envelope: The inbound envelope
            segments: Available segments for deterministic fallback (optional)

        Returns:
            Replica ID to route to, or None for default routing
        """
        if not self.config.enabled:
            logger.debug("stickiness_disabled", envelope_id=envelope.id)
            return None

        # Check for existing AFT in envelope
        aft_token = envelope.aft
        if aft_token:
            logger.debug(
                "envelope_has_aft_token",
                envelope_id=envelope.id,
                aft_preview=(str(aft_token)[:20] + "..." if len(str(aft_token)) > 20 else str(aft_token)),
            )
            replica_id = self._route_by_aft(aft_token, envelope)
            if replica_id:
                self._metrics["cache_hits"] += 1
                logger.debug(
                    "aft_routed_envelope",
                    envelope_id=envelope.id,
                    replica_id=replica_id,
                    routing_type="aft_direct",
                )
                return replica_id

        # Check SID cache for node-wide stickiness
        if envelope.sid:
            logger.debug("checking_sid_cache", envelope_id=envelope.id, sid=envelope.sid)
            cached_replica = self._sid_cache.get(envelope.sid)
            if cached_replica:
                logger.debug(
                    "found_cached_replica_for_sid",
                    envelope_id=envelope.id,
                    sid=envelope.sid,
                    replica_id=cached_replica,
                )

                # For SID-only mode, return replica directly
                if self.config.security_level == StickinessMode.SID_ONLY:
                    self._metrics["cache_hits"] += 1
                    logger.debug(
                        "sid_cache_routed_envelope",
                        envelope_id=envelope.id,
                        replica_id=cached_replica,
                        sid=envelope.sid,
                        routing_type="sid_only",
                    )
                    return cached_replica

                # For other modes, try to find the AFT token for this replica
                # This handles the case where we have both AFT and SID associations
                for aft_token, association in self._aft_associations.items():
                    if association.replica_id == cached_replica and not association.is_expired():
                        envelope.aft = aft_token
                        self._metrics["cache_hits"] += 1
                        logger.debug(
                            "sid_cache_routed_envelope",
                            envelope_id=envelope.id,
                            replica_id=cached_replica,
                            sid=envelope.sid,
                            routing_type="sid_cache_with_aft",
                        )
                        return cached_replica

                # If no valid AFT found but we have replica ID, still route there
                self._metrics["cache_hits"] += 1
                logger.debug(
                    "sid_cache_routed_envelope",
                    envelope_id=envelope.id,
                    replica_id=cached_replica,
                    sid=envelope.sid,
                    routing_type="sid_cache_direct",
                )
                return cached_replica
            else:
                logger.debug(
                    "no_cached_replica_for_sid",
                    envelope_id=envelope.id,
                    sid=envelope.sid,
                )

        # Deterministic SID-based fallback when segments are provided
        if envelope.sid and segments and len(segments) > 0:
            import hashlib

            sid_bytes = envelope.sid.encode("utf-8")
            idx = int(hashlib.sha256(sid_bytes).hexdigest(), 16) % len(segments)
            chosen = segments[idx]
            self._metrics["cache_hits"] += (
                1  # Count as cache hit since we're providing a deterministic result
            )
            logger.debug(
                "sid_based_deterministic_choice",
                envelope_id=envelope.id,
                sid=envelope.sid,
                chosen=chosen,
                routing_type="sid_deterministic",
            )
            return chosen

        self._metrics["cache_misses"] += 1
        logger.debug(
            "no_stickiness_routing",
            envelope_id=envelope.id,
            has_aft=envelope.aft is not None,
            has_sid=envelope.sid is not None,
        )
        return None

    def _route_by_aft(self, aft_token: str, envelope: FameEnvelope) -> Optional[str]:
        """Route envelope based on AFT token."""
        # Check if we have a cached association
        association = self._aft_associations.get(aft_token)
        if not association:
            return None

        # Check if association is expired
        if association.is_expired():
            self._remove_association(aft_token)
            self._metrics["associations_expired"] += 1
            return None

        # For strict mode downstream hops, reject low-trust associations
        if self.verifier.security_level == StickinessMode.STRICT and association.is_low_trust():
            logger.warning(
                "rejecting_low_trust_association",
                envelope_id=envelope.id,
                replica_id=association.replica_id,
                reason="strict mode rejects low-trust associations",
            )
            return None

        # Move to end of LRU
        self._aft_associations.move_to_end(aft_token)

        return association.replica_id

    def _store_association(self, token: str, association: AFTAssociation):
        """Store an AFT association, enforcing cache limits."""
        # Remove if already exists
        if token in self._aft_associations:
            del self._aft_associations[token]

        # Add new association
        self._aft_associations[token] = association

        # Enforce cache size limit (LRU eviction)
        while len(self._aft_associations) > self.config.cache_max:
            oldest_token, _ = self._aft_associations.popitem(last=False)
            # Also remove from SID cache if it points to this token
            for sid, cached_token in list(self._sid_cache.items()):
                if cached_token == oldest_token:
                    del self._sid_cache[sid]

    def _remove_association(self, token: str):
        """Remove an AFT association and clean up related state."""
        association = self._aft_associations.pop(token, None)
        if association:
            # Remove from SID cache if it points to this token
            for sid, cached_token in list(self._sid_cache.items()):
                if cached_token == token:
                    del self._sid_cache[sid]

    def cleanup_expired_associations(self):
        """Clean up expired associations (should be called periodically)."""
        current_time = int(time.time())
        expired_tokens = []

        for token, association in self._aft_associations.items():
            if association.exp <= current_time:
                expired_tokens.append(token)

        for token in expired_tokens:
            self._remove_association(token)
            self._metrics["associations_expired"] += 1

        if expired_tokens:
            logger.debug("cleaned_expired_associations", count=len(expired_tokens))

    def replica_left(self, replica_id: str):
        """Handle a replica leaving the pool."""
        # Remove all associations for this replica
        tokens_to_remove = []
        for token, association in self._aft_associations.items():
            if association.replica_id == replica_id:
                tokens_to_remove.append(token)

        for token in tokens_to_remove:
            self._remove_association(token)

        if tokens_to_remove:
            logger.debug(
                "removed_associations_for_departed_replica",
                replica_id=replica_id,
                count=len(tokens_to_remove),
            )

    def handle_replica_left(self, replica_id: str):
        """Handle a replica leaving by cleaning up its session affinity associations."""
        self.replica_left(replica_id)
        logger.debug("stickiness_replica_cleanup", replica_id=replica_id)

    def get_metrics(self) -> Dict[str, int]:
        """Get current metrics."""
        return {
            **self._metrics,
            "cache_size": len(self._aft_associations),
            "sid_cache_size": len(self._sid_cache),
        }

    def get_associations(self) -> Dict[str, Dict[str, Any]]:
        """Get current associations for debugging."""
        return {
            token: {
                "replica_id": assoc.replica_id,
                "sid": assoc.sid,
                "client_sid": assoc.client_sid,
                "exp": assoc.exp,
                "trust_level": assoc.trust_level,
                "scope": assoc.scope,
                "created_at": assoc.created_at,
                "expired": assoc.is_expired(),
            }
            for token, assoc in self._aft_associations.items()
        }

    def get_stickiness_metrics(self):
        """Get session affinity metrics if available."""
        return self.get_metrics()

    def log_metrics(self) -> None:
        """Log current stickiness metrics and status."""
        logger.info(
            "📊 Stickiness Metrics Report",
            enabled=self.config.enabled,
            security_level=self.config.security_level.value,
            cache_hits=self._metrics["cache_hits"],
            cache_misses=self._metrics["cache_misses"],
            verify_failures=self._metrics["verify_failures"],
            associations_created=self._metrics["associations_created"],
            associations_expired=self._metrics["associations_expired"],
            active_associations=len(self._aft_associations),
            sid_cache_entries=len(self._sid_cache),
            hit_rate=round(
                self._metrics["cache_hits"]
                / max(1, self._metrics["cache_hits"] + self._metrics["cache_misses"])
                * 100,
                2,
            ),
        )

    # NodeEventListener implementation

    async def on_deliver(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Any:
        """
        Handle delivery of envelopes to intercept responses with AFT instructions.

        When a replica sends a response through the sentinel, this method checks
        for AFT setter instructions and processes them to create session affinity
        associations.
        """
        logger.debug(
            "stickiness_manager_on_deliver",
            envelope_id=envelope.id,
            origin_type=(context.origin_type.value if context and context.origin_type else "unknown"),
            from_system_id=getattr(context, "from_system_id", None),
        )

        # Only process responses from downstream routes (replicas)
        if context and context.origin_type == DeliveryOriginType.DOWNSTREAM:
            # Extract the source route from context if available
            source_route = context.from_system_id

            if source_route:
                logger.debug(
                    "processing_downstream_envelope",
                    envelope_id=envelope.id,
                    source_route=source_route,
                )

                # SID-ONLY mode: Create association on first message with SID
                if (
                    self.config.security_level == StickinessMode.SID_ONLY
                    and envelope.sid
                    and envelope.sid not in self._sid_cache
                ):
                    self._sid_cache[envelope.sid] = source_route
                    logger.debug(
                        "sid_only_association_recorded",
                        envelope_id=envelope.id,
                        sid=envelope.sid,
                        replica_id=source_route,
                    )

                # Process potential AFT setter instructions
                # Check if envelope has AFT instructions before processing
                has_aft_instruction = False
                if envelope.meta:
                    # Check for AFT instruction in meta (nested or flat format)
                    if (
                        "set" in envelope.meta
                        and isinstance(envelope.meta["set"], dict)
                        and "aft" in envelope.meta["set"]
                    ):
                        has_aft_instruction = True
                    elif "set.aft" in envelope.meta:
                        has_aft_instruction = True

                aft_token = await self.handle_outbound_envelope(envelope, source_route)

                if has_aft_instruction:
                    if aft_token:
                        logger.debug(
                            "processed_aft_setter_instruction",
                            envelope_id=envelope.id,
                            source_route=source_route,
                            aft_preview=(
                                str(aft_token)[:20] + "..." if len(str(aft_token)) > 20 else str(aft_token)
                            ),
                            client_echo=True,
                        )
                    else:
                        logger.debug(
                            "processed_aft_setter_instruction",
                            envelope_id=envelope.id,
                            source_route=source_route,
                            client_echo=False,
                        )
                else:
                    logger.debug(
                        "no_aft_setter_instruction",
                        envelope_id=envelope.id,
                        source_route=source_route,
                    )
            else:
                logger.debug("downstream_envelope_without_source_route", envelope_id=envelope.id)
        else:
            logger.debug("envelope_not_from_downstream", envelope_id=envelope.id)

        # Always return the envelope to continue normal delivery
        return envelope

    @property
    def has_stickiness(self) -> bool:
        """Check if stickiness is enabled."""
        return bool(self.config.enabled)

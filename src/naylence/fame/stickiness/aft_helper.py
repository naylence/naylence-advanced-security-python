"""
AFT Helper for Replicas.

This component provides a simple interface for replicas to generate AFTs
when they need session stickiness.
"""

from __future__ import annotations

from typing import Optional

from naylence.fame.core import FameDeliveryContext, FameEnvelope
from naylence.fame.stickiness.aft_signer import AFTSigner, create_aft_signer
from naylence.fame.stickiness.stickiness_mode import StickinessMode
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class AFTHelper:
    """
    Helper for replicas to request session affinity.

    Provides simple methods to inject AFT instructions into envelope metadata.
    """

    def __init__(self, signer: AFTSigner, node_sid: str, max_ttl_sec: int):
        self.max_ttl_sec = max_ttl_sec
        self.signer = signer
        self.node_sid = node_sid

    def request_stickiness(
        self,
        envelope: FameEnvelope,
        *,
        ttl_sec: Optional[int] = None,
        scope: Optional[str] = None,
        context: Optional[FameDeliveryContext] = None,
    ) -> bool:
        """
        Request session stickiness for this envelope's conversation.

        Args:
            envelope: The envelope to modify
            ttl_sec: TTL for the stickiness (defaults to max_ttl_sec)
            scope: Optional scope hint ('node', 'flow', 'sess')
            context: Optional delivery context containing sticky_sid

        Returns:
            True if AFT was successfully added, False otherwise
        """

        # Use default TTL if not specified
        if ttl_sec is None:
            ttl_sec = self.max_ttl_sec

        try:
            # Extract original client SID from delivery context for session affinity
            client_sid = None
            if context and context.sticky_sid:
                client_sid = context.sticky_sid

            if client_sid:
                logger.debug("client_sticky_sid_extracted", client_sid=client_sid)
            else:
                logger.warning("client_sticky_sid_not_found_in_context", context=context)

            # Generate AFT
            aft_token = self.signer.sign_aft(
                sid=self.node_sid, ttl_sec=ttl_sec, scope=scope, client_sid=client_sid
            )

            # Skip if no token generated (e.g., SID-only mode)
            if not aft_token:
                return False

            # Initialize meta if needed
            if envelope.meta is None:
                envelope.meta = {}

            # Add the AFT instruction using nested format
            # Ensure we have a "set" dict in meta
            if "set" not in envelope.meta:
                envelope.meta["set"] = {}

            # Cast to dict to satisfy type checker
            set_meta = envelope.meta["set"]
            if isinstance(set_meta, dict):
                set_meta["aft"] = aft_token
            else:
                # Fallback to creating new dict if somehow not a dict
                envelope.meta["set"] = {"aft": aft_token}

            logger.debug(
                "aft_instruction_added",
                envelope_id=envelope.id,
                ttl_sec=ttl_sec,
                scope=scope,
                security_level=self.signer.security_level.value,
            )

            return True

        except Exception as e:
            logger.error("aft_generation_failed", envelope_id=envelope.id, error=str(e))
            return False

    def request_node_stickiness(self, envelope: FameEnvelope, ttl_sec: Optional[int] = None) -> bool:
        """Request node-wide stickiness (most common case)."""
        return self.request_stickiness(envelope, ttl_sec=ttl_sec, scope="node")

    def request_flow_stickiness(self, envelope: FameEnvelope, ttl_sec: Optional[int] = None) -> bool:
        """Request flow-specific stickiness."""
        return self.request_stickiness(envelope, ttl_sec=ttl_sec, scope="flow")

    def request_session_stickiness(self, envelope: FameEnvelope, ttl_sec: Optional[int] = None) -> bool:
        """Request session-specific stickiness."""
        return self.request_stickiness(envelope, ttl_sec=ttl_sec, scope="sess")


def create_aft_helper(
    security_level: StickinessMode,
    node_sid: str,
    kid: str,
    private_key_pem: Optional[str] = None,
    algorithm: str = "EdDSA",
    max_ttl_sec: int = 7200,
) -> AFTHelper:
    """Factory function to create an AFT helper."""

    signer = create_aft_signer(
        security_level=security_level,
        kid=kid,
        private_key_pem=private_key_pem,
        algorithm=algorithm,
        max_ttl_sec=max_ttl_sec,
    )

    return AFTHelper(signer, node_sid, max_ttl_sec)

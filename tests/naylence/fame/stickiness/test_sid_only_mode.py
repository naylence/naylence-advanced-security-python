"""
Test SID-only stickiness fix
"""

import asyncio
from unittest.mock import MagicMock

from naylence.fame.core import DeliveryOriginType, FameDeliveryContext, FameEnvelope
from naylence.fame.sentinel.load_balancing_strategy import StickyLoadBalancingStrategy
from naylence.fame.stickiness.aft_load_balancer_stickiness_manager import (
    AFTLoadBalancerStickinessManager,
    AFTLoadBalancerStickinessManagerConfig,
)
from naylence.fame.stickiness.aft_verifier import SidOnlyAFTVerifier
from naylence.fame.stickiness.stickiness_mode import StickinessMode


async def test_sid_only_stickiness_fix():
    """Test that SID-only mode creates associations on first message and routes correctly."""

    # Create SID-only stickiness manager
    config = AFTLoadBalancerStickinessManagerConfig(
        enabled=True,
        security_level=StickinessMode.SID_ONLY,
        default_ttl_sec=300,
        cache_max=1000,
        client_echo=False,
    )

    verifier = SidOnlyAFTVerifier()
    manager = AFTLoadBalancerStickinessManager(config, verifier)

    # Create sticky load balancing strategy
    strategy = StickyLoadBalancingStrategy(manager)

    # Create test envelope with SID
    from naylence.fame.core.protocol.frames import DataFrame

    envelope = FameEnvelope(
        id="test-envelope-1", sid="test-session-123", frame=DataFrame(payload=b"test-data")
    )

    # Create delivery context from downstream replica
    context = FameDeliveryContext(
        from_system_id="replica-A", from_connector=MagicMock(), origin_type=DeliveryOriginType.DOWNSTREAM
    )

    # 1. Process first message from replica - should create association
    result = await manager.on_deliver(MagicMock(), envelope, context)
    assert result == envelope  # Should pass envelope through

    # Verify SID cache has the association
    assert "test-session-123" in manager.sid_cache
    assert manager.sid_cache["test-session-123"] == "replica-A"

    # 2. Test load balancing strategy routing
    segments = ["replica-A", "replica-B", "replica-C"]
    chosen = strategy.choose("test-pool", segments, envelope)

    # Should route to replica-A based on SID cache
    assert chosen == "replica-A"

    # 3. Test with new envelope from same session
    envelope2 = FameEnvelope(
        id="test-envelope-2",
        sid="test-session-123",  # Same SID
        frame=DataFrame(payload=b"test-data-2"),
    )

    chosen2 = strategy.choose("test-pool", segments, envelope2)
    assert chosen2 == "replica-A"  # Should stick to same replica

    # 4. Test with different session
    envelope3 = FameEnvelope(
        id="test-envelope-3", sid="different-session-456", frame=DataFrame(payload=b"test-data-3")
    )

    chosen3 = strategy.choose("test-pool", segments, envelope3)
    # With deterministic SID routing, different SID should route to a specific replica
    assert chosen3 is not None  # Should deterministically route to some replica
    assert chosen3 in segments  # Should be one of the available segments

    # Test deterministic behavior - same SID should always route to same replica
    chosen3_again = strategy.choose("test-pool", segments, envelope3)
    assert chosen3_again == chosen3  # Should be deterministic

    print("✅ SID-only stickiness fix working correctly!")


if __name__ == "__main__":
    asyncio.run(test_sid_only_stickiness_fix())

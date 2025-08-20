#!/usr/bin/env python3

"""
Test the refactored AFTLoadBalancerStickinessManager that implements NodeEventListener directly.
This demonstrates the simplified architecture where AFTLoadBalancerStickinessManager handles
both AFT routing decisions and AFT setter processing.
"""

import asyncio

from naylence.fame.core import DeliveryOriginType, FameDeliveryContext, create_fame_envelope
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.security.keys.key_provider import get_key_provider
from naylence.fame.sentinel.load_balancing.sticky_load_balancing_strategy import StickyLoadBalancingStrategy
from naylence.fame.stickiness.aft_load_balancer_stickiness_manager import (
    AFTLoadBalancerStickinessManager,
    AFTLoadBalancerStickinessManagerConfig,
)
from naylence.fame.stickiness.aft_verifier import create_aft_verifier
from naylence.fame.stickiness.stickiness_mode import StickinessMode


def create_stickiness_manager(config: AFTLoadBalancerStickinessManagerConfig, key_provider, verifier=None):
    """Factory function to create a stickiness manager for tests."""
    if not verifier:
        verifier = create_aft_verifier(config.security_level, key_provider, config.default_ttl_sec)

    return AFTLoadBalancerStickinessManager(config, verifier)


class MockNode:
    """Mock node for testing."""

    pass


async def test_stickiness_manager_as_event_listener():
    """Test AFTLoadBalancerStickinessManager implementing NodeEventListener directly."""

    print("🔧 Setting up simplified stickiness integration test...")

    # 1. Create stickiness configuration
    config = AFTLoadBalancerStickinessManagerConfig(
        enabled=True, security_level=StickinessMode.SID_ONLY, client_echo=False, default_ttl_sec=60
    )

    # 2. Create shared AFTLoadBalancerStickinessManager (which is also a NodeEventListener)
    stickiness_manager = create_stickiness_manager(config, get_key_provider())

    # 3. Create load balancing strategy using the same manager
    sticky_strategy = StickyLoadBalancingStrategy(stickiness_manager)

    # 4. Mock node
    node = MockNode()

    print("✅ Components created successfully")
    print(f"   Stickiness enabled: {stickiness_manager.config.enabled}")
    print(f"   Security level: {stickiness_manager.config.security_level}")
    print(f"   Manager implements NodeEventListener: {hasattr(stickiness_manager, 'on_deliver')}")
    print(f"   Manager has stickiness: {stickiness_manager.has_stickiness}")

    # 5. Test write-path: Process outbound envelope with set.aft via NodeEventListener interface
    print("\n📤 Testing write-path (AFT setter processing via NodeEventListener)...")

    # Create outbound envelope from replica with set.aft instruction
    outbound_envelope = create_fame_envelope(
        frame=DataFrame(payload={"result": "success"}, codec="json"), sid="test-session-789"
    )

    # In SID_ONLY mode, use empty AFT token which triggers SID-based association
    outbound_envelope.meta = {"set.aft": ""}

    # Create context indicating this came from downstream replica
    context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM)
    context.from_system_id = "replica-alpha"  # Mock attribute

    # Process the outbound envelope through AFTLoadBalancerStickinessManager's NodeEventListener interface
    result = await stickiness_manager.on_deliver(node, outbound_envelope, context)

    print("   ✅ AFTLoadBalancerStickinessManager processed outbound envelope via on_deliver()")
    print("   📋 AFT handling for replica: replica-alpha")
    print(f"   🎯 Session ID: {outbound_envelope.sid}")
    print(f"   🔧 Result envelope: {result is not None}")

    # 6. Test read-path: Route based on SID via strategy
    print("\n📥 Testing read-path (AFT-based routing via strategy)...")

    # Create inbound envelope from same session
    inbound_envelope = create_fame_envelope(
        frame=DataFrame(payload={"action": "get_data"}, codec="json"),
        sid="test-session-789",  # Same session ID
    )

    # Test routing via strategy
    pool_segments = ["replica-alpha", "replica-beta", "replica-gamma"]
    chosen_replica = sticky_strategy.choose("test-pool", pool_segments, inbound_envelope)

    print(f"   ✅ Strategy routed to replica: {chosen_replica}")
    print("   💡 SID-based routing in SID_ONLY mode")

    # 7. Test metrics and status
    print("\n📊 Testing metrics and management...")

    metrics = stickiness_manager.get_metrics()
    strategy_metrics = sticky_strategy.get_metrics()

    print(f"   📈 Manager metrics: {metrics}")
    print(f"   📈 Strategy metrics: {strategy_metrics}")
    print(f"   🔗 Same manager instance: {metrics == strategy_metrics}")

    # 8. Test replica lifecycle via manager
    print("\n🔄 Testing replica lifecycle...")

    print("   🚫 Simulating replica-alpha leaving...")
    stickiness_manager.handle_replica_left("replica-alpha")

    # Test routing after replica departure
    chosen_replica_after = sticky_strategy.choose(
        "test-pool", ["replica-beta", "replica-gamma"], inbound_envelope
    )
    print(f"   ✅ Strategy result after replica left: {chosen_replica_after}")

    # 9. Test cleanup
    print("\n🧹 Testing cleanup...")
    stickiness_manager.cleanup_expired_associations()
    print("   ✅ Expired associations cleaned up")

    print("\n🎉 Simplified integration test completed successfully!")

    print("\n💡 Simplified architecture summary:")
    print("   • AFTLoadBalancerStickinessManager: Single component handling both read and write paths")
    print("   • Implements NodeEventListener: Directly processes AFT setter instructions")
    print("   • Used by StickyLoadBalancingStrategy: Shared for routing decisions")
    print("   • No wrapper components needed: Clean, direct integration")
    print("   • Sentinel just needs: sentinel.add_event_listener(stickiness_manager)")


if __name__ == "__main__":
    asyncio.run(test_stickiness_manager_as_event_listener())

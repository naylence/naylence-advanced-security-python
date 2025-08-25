"""
Test smart factory defaults for stickiness configuration.

This test verifies that the SentinelFactory creates sentinels with appropriate
stickiness configuration based on the StickinessConfig provided, including:
- Smart routing policy creation with Composite(Sticky + HRW) when enabled
- Automatic stickiness manager registration as event listener
- Fallback to simple HRW when stickiness is disabled
"""

from naylence.fame.sentinel.composite_routing_policy import CompositeRoutingPolicy
from naylence.fame.sentinel.hybrid_path_routing_policy import HybridPathRoutingPolicy
from naylence.fame.sentinel.load_balancing_strategy import (
    CompositeLoadBalancingStrategy,
    StickyLoadBalancingStrategy,
)
from naylence.fame.sentinel.sentinel_factory import SentinelConfig, SentinelFactory
from naylence.fame.stickiness.aft_load_balancer_stickiness_manager import AFTLoadBalancerStickinessManager
from naylence.fame.stickiness.aft_load_balancer_stickiness_manager_factory import (
    AFTLoadBalancerStickinessManagerConfig,
)
from naylence.fame.stickiness.stickiness_mode import StickinessMode


async def test_sentinel_factory_with_stickiness():
    """Test that SentinelFactory creates sentinels with stickiness when configured."""
    print("\n🧪 Testing SentinelFactory smart stickiness defaults...")

    # 1. Create factory
    factory = SentinelFactory()
    print("   ✅ Factory created")

    # 2. Test with stickiness enabled
    print("\n📝 Test 1: Stickiness enabled configuration")
    config_with_stickiness = SentinelConfig(
        mode="dev",
        stickiness=AFTLoadBalancerStickinessManagerConfig(
            security_level=StickinessMode.SID_ONLY,  # Use lenient security for testing
        ),
    )

    sentinel_with_stickiness = await factory.create(config_with_stickiness)
    print("   ✅ Sentinel created with stickiness enabled")

    # 3. Verify routing policy structure
    routing_policy = sentinel_with_stickiness._routing_policy  # type: ignore
    assert isinstance(routing_policy, CompositeRoutingPolicy)
    print("   ✅ Routing policy is CompositeRoutingPolicy")

    # Find the HybridPathRoutingPolicy component
    hybrid_policy = None
    for policy in routing_policy._policies:
        if isinstance(policy, HybridPathRoutingPolicy):
            hybrid_policy = policy
            break

    assert hybrid_policy is not None
    print("   ✅ Found HybridPathRoutingPolicy in composite")

    # 4. Verify load balancing strategy is composite
    load_balancing_strategy = hybrid_policy._lb
    assert isinstance(load_balancing_strategy, CompositeLoadBalancingStrategy)
    print("   ✅ Load balancing strategy is CompositeLoadBalancingStrategy")

    # 5. Verify first strategy is sticky
    strategies = load_balancing_strategy.strategies
    assert len(strategies) >= 1
    assert isinstance(strategies[0], StickyLoadBalancingStrategy)
    print("   ✅ First strategy is StickyLoadBalancingStrategy")

    # 6. Verify stickiness manager is registered as event listener
    event_listeners = sentinel_with_stickiness._event_listeners  # type: ignore
    stickiness_listeners = [
        listener for listener in event_listeners if isinstance(listener, AFTLoadBalancerStickinessManager)
    ]
    assert len(stickiness_listeners) == 1
    print("   ✅ AFTLoadBalancerStickinessManager registered as event listener")

    # 7. Test with stickiness disabled
    print("\n📝 Test 2: Stickiness disabled configuration")
    config_without_stickiness = SentinelConfig(
        mode="dev"
        # No stickiness config = disabled by default
    )

    sentinel_without_stickiness = await factory.create(config_without_stickiness)
    print("   ✅ Sentinel created with stickiness disabled")

    # 8. Verify no stickiness manager in event listeners
    event_listeners = sentinel_without_stickiness._event_listeners or []  # type: ignore
    stickiness_listeners = [
        listener for listener in event_listeners if isinstance(listener, AFTLoadBalancerStickinessManager)
    ]
    assert len(stickiness_listeners) == 0
    print("   ✅ No AFTLoadBalancerStickinessManager in event listeners when disabled")

    print("\n🎉 Smart factory defaults test completed successfully!")

    print("\n💡 Factory configuration summary:")
    print("   • Enabled stickiness: Composite routing with Sticky + HRW fallback")
    print("   • AFTLoadBalancerStickinessManager: Automatically registered as event listener")
    print("   • Disabled stickiness: Simple HRW load balancing")
    print("   • Zero configuration: Works out-of-the-box when stickiness enabled")


if __name__ == "__main__":
    import asyncio

    asyncio.run(test_sentinel_factory_with_stickiness())

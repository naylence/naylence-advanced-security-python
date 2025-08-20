#!/usr/bin/env python3
"""
Test the refactored stickiness implementation that moved AFTReplicaStickinessManager
from Sentinel-specific to base node level.
"""

import asyncio

from naylence.fame.node.node_config import FameNodeConfig
from naylence.fame.node.node_factory import NodeFactory
from naylence.fame.sentinel.sentinel_factory import SentinelConfig, SentinelFactory
from naylence.fame.stickiness.aft_load_balancer_stickiness_manager_factory import (
    AFTLoadBalancerStickinessManagerConfig,
)
from naylence.fame.stickiness.stickiness_mode import StickinessMode


async def test_base_node_stickiness():
    """Test that base FameNode supports stickiness when configured."""
    print("=== Testing Base Node Stickiness ===")

    # Create base node config that triggers AFTReplicaStickinessManager creation
    # Conditions: has_parent + wildcard logicals
    config = FameNodeConfig(
        mode="dev",
        has_parent=True,  # Acts as a child node
        requested_logicals=["*.fame.com"],  # Wildcard logicals signal LB participation
    )

    factory = NodeFactory()
    node = await factory.create(config)

    # Check that node has AFTReplicaStickinessManager
    aft_handlers = [
        listener
        for listener in node._event_listeners
        if listener.__class__.__name__ == "AFTReplicaStickinessManager"
    ]

    print(f"✓ Base node created with {len(aft_handlers)} AFTReplicaStickinessManager(s)")
    assert len(aft_handlers) == 1, "Base node should have exactly one AFTReplicaStickinessManager"

    print("✅ Base node supports stickiness behavioral contract")
    return True


async def test_sentinel_stickiness():
    """Test that Sentinel supports stickiness and has both AFT and routing components."""
    print("\n=== Testing Sentinel Stickiness ===")

    # Create Sentinel config with stickiness
    config = SentinelConfig(
        mode="dev",
        has_parent=True,  # Conditions for AFTReplicaStickinessManager
        requested_logicals=["*.fame.com"],  # Wildcard logicals
        stickiness=AFTLoadBalancerStickinessManagerConfig(
            enabled=True,
            security_level=StickinessMode.SIGNED_OPTIONAL,
            default_ttl_sec=3600,
            cache_max=1000,
            client_echo=True,
        ),
    )

    factory = SentinelFactory()
    sentinel = await factory.create(config)

    # Check that sentinel has both AFTReplicaStickinessManager (from base)
    # and AFTLoadBalancerStickinessManager (routing-specific)
    aft_handlers = [
        listener
        for listener in sentinel._event_listeners
        if listener.__class__.__name__ == "AFTReplicaStickinessManager"
    ]

    stickiness_managers = [
        listener
        for listener in sentinel._event_listeners
        if listener.__class__.__name__ == "AFTLoadBalancerStickinessManager"
    ]

    print(f"✓ Sentinel created with {len(aft_handlers)} AFTReplicaStickinessManager(s)")
    print(f"✓ Sentinel created with {len(stickiness_managers)} AFTLoadBalancerStickinessManager(s)")

    assert len(aft_handlers) == 1, (
        "Sentinel should have exactly one AFTReplicaStickinessManager (from base)"
    )
    assert len(stickiness_managers) == 1, (
        "Sentinel should have exactly one AFTLoadBalancerStickinessManager (routing-specific)"
    )

    print("✅ Sentinel supports both AFT context handling and routing-specific stickiness")
    return True


async def test_listener_ordering():
    """Test that AFTReplicaStickinessManager comes before AFTLoadBalancerStickinessManager in Sentinels."""
    print("\n=== Testing Event Listener Ordering ===")

    config = SentinelConfig(
        mode="dev",
        has_parent=True,  # Conditions for AFTReplicaStickinessManager
        requested_logicals=["*.fame.com"],  # Wildcard logicals
        stickiness=AFTLoadBalancerStickinessManagerConfig(
            enabled=True,
            security_level=StickinessMode.SIGNED_OPTIONAL,
            default_ttl_sec=3600,
            cache_max=1000,
            client_echo=True,
        ),
    )

    factory = SentinelFactory()
    sentinel = await factory.create(config)

    # Check listener ordering
    listener_types = [listener.__class__.__name__ for listener in sentinel._event_listeners]
    print(f"✓ Listener order: {listener_types}")

    # AFTReplicaStickinessManager should come before AFTLoadBalancerStickinessManager
    aft_index = next(
        (i for i, name in enumerate(listener_types) if name == "AFTReplicaStickinessManager"), -1
    )
    sm_index = next(
        (i for i, name in enumerate(listener_types) if name == "AFTLoadBalancerStickinessManager"), -1
    )

    if aft_index != -1 and sm_index != -1:
        if aft_index < sm_index:
            print(
                "✅ AFTReplicaStickinessManager correctly ordered before AFTLoadBalancerStickinessManager"
            )
            return True
        else:
            print("❌ AFTReplicaStickinessManager should come before AFTLoadBalancerStickinessManager")
            return False
    else:
        print(f"❌ Missing listeners: AFT={aft_index}, SM={sm_index}")
        return False


async def main():
    """Run all tests."""
    print("Testing Refactored Stickiness Implementation")
    print("=" * 50)

    try:
        # Test base node stickiness
        base_result = await test_base_node_stickiness()

        # Test Sentinel stickiness
        sentinel_result = await test_sentinel_stickiness()

        # Test listener ordering
        ordering_result = await test_listener_ordering()

        print("\n" + "=" * 50)
        print("SUMMARY:")
        print(f"Base Node Stickiness: {'✅ PASS' if base_result else '❌ FAIL'}")
        print(f"Sentinel Stickiness:  {'✅ PASS' if sentinel_result else '❌ FAIL'}")
        print(f"Listener Ordering:    {'✅ PASS' if ordering_result else '❌ FAIL'}")

        if all([base_result, sentinel_result, ordering_result]):
            print("\n🎉 All tests passed! Refactored implementation working correctly.")
            return True
        else:
            print("\n❌ Some tests failed. Check implementation.")
            return False

    except Exception as e:
        print(f"❌ Test failed with exception: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    result = asyncio.run(main())
    exit(0 if result else 1)

#!/usr/bin/env python3
"""
Integration test to verify that KeyRequest frames now use the same
deterministic SID routing as Data frames through the routing pipeline.
"""

import sys

from naylence.fame.core import FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame, KeyRequestFrame
from naylence.fame.sentinel.load_balancing_strategy import StickyLoadBalancingStrategy

from naylence.fame.stickiness.aft_load_balancer_stickiness_manager import AFTLoadBalancerStickinessManager
from naylence.fame.stickiness.aft_load_balancer_stickiness_manager_factory import AFTLoadBalancerStickinessManagerConfig
from naylence.fame.stickiness.stickiness_mode import StickinessMode


def test_keyrequest_data_routing_consistency():
    """Test that KeyRequest and Data frames with same SID route to same segment."""
    print("Testing KeyRequest and Data frame routing consistency...")

    # Create stickiness config with sid-only mode
    config = AFTLoadBalancerStickinessManagerConfig(
        enabled=True,
        security_level=StickinessMode.SID_ONLY,
        client_echo=False,
        default_ttl_sec=3600,
    )

    class MockVerifier:
        @property
        def security_level(self):
            return StickinessMode.SID_ONLY

    stickiness_manager = AFTLoadBalancerStickinessManager(config, MockVerifier())
    strategy = StickyLoadBalancingStrategy(stickiness_manager)

    segments = ["segment1", "segment2", "segment3"]
    test_sid = "consistent-sid-789"

    # Test Data frame routing
    data_envelope = FameEnvelope(sid=test_sid, frame=DataFrame(payload="test"), id="data-envelope")
    data_result = strategy.choose("test-pool", segments, data_envelope)

    # Test KeyRequest frame routing
    keyrequest_envelope = FameEnvelope(
        sid=test_sid, frame=KeyRequestFrame(kid="test", from_seg="test"), id="keyrequest-envelope"
    )
    keyrequest_result = strategy.choose("test-pool", segments, keyrequest_envelope)

    print(f"Data frame with SID '{test_sid}' → segment '{data_result}'")
    print(f"KeyRequest frame with SID '{test_sid}' → segment '{keyrequest_result}'")

    # Both should route to the same segment for deterministic SID routing
    assert data_result == keyrequest_result, (
        f"Data and KeyRequest frames with same SID should route to same segment. "
        f"Data: {data_result}, KeyRequest: {keyrequest_result}"
    )

    print("✅ SUCCESS: Data and KeyRequest frames with same SID route to same segment")


def test_multiple_sids_routing_consistency():
    """Test that multiple SIDs maintain consistency between Data and KeyRequest frames."""
    print("\nTesting multiple SIDs routing consistency...")

    # Create stickiness config
    config = AFTLoadBalancerStickinessManagerConfig(
        enabled=True,
        security_level=StickinessMode.SID_ONLY,
        client_echo=False,
        default_ttl_sec=3600,
    )

    class MockVerifier:
        @property
        def security_level(self):
            return StickinessMode.SID_ONLY

    stickiness_manager = AFTLoadBalancerStickinessManager(config, MockVerifier())
    strategy = StickyLoadBalancingStrategy(stickiness_manager)

    segments = ["segment1", "segment2", "segment3"]
    test_sids = [f"sid-{i}" for i in range(5)]

    for sid in test_sids:
        # Test Data frame routing
        data_envelope = FameEnvelope(sid=sid, frame=DataFrame(payload="test"), id="data-envelope")
        data_result = strategy.choose("test-pool", segments, data_envelope)

        # Test KeyRequest frame routing
        keyrequest_envelope = FameEnvelope(
            sid=sid, frame=KeyRequestFrame(kid="test", from_seg="test"), id="keyrequest-envelope"
        )
        keyrequest_result = strategy.choose("test-pool", segments, keyrequest_envelope)

        assert data_result == keyrequest_result, (
            f"SID '{sid}': Data and KeyRequest frames should route to same segment. "
            f"Data: {data_result}, KeyRequest: {keyrequest_result}"
        )

        print(f"SID '{sid}': Data and KeyRequest both route to '{data_result}' ✅")

    print("✅ SUCCESS: All SIDs maintain consistent routing between Data and KeyRequest frames")


if __name__ == "__main__":
    print("Testing KeyRequest and Data frame routing consistency after pipeline integration...\n")

    try:
        test_keyrequest_data_routing_consistency()
        test_multiple_sids_routing_consistency()
        print(
            "\n🎉 All tests passed! KeyRequest frames now use deterministic SID routing like Data frames."
        )
        sys.exit(0)
    except AssertionError as e:
        print(f"\n💥 Test failed: {e}")
        sys.exit(1)

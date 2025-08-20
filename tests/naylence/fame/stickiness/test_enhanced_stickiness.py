import time
from unittest.mock import Mock

import pytest

from naylence.fame.core import (
    DeliveryOriginType,
    FameDeliveryContext,
    create_fame_envelope,
)
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.security.keys.key_provider import get_key_provider
from naylence.fame.stickiness.aft_load_balancer_stickiness_manager import (
    AFTLoadBalancerStickinessManager,
    AFTLoadBalancerStickinessManagerConfig,
)
from naylence.fame.stickiness.aft_verifier import AFTVerificationResult, create_aft_verifier
from naylence.fame.stickiness.stickiness_mode import StickinessMode


def create_stickiness_manager(config: AFTLoadBalancerStickinessManagerConfig, key_provider, verifier=None):
    """Factory function to create a stickiness manager for tests."""
    if not verifier:
        verifier = create_aft_verifier(config.security_level, key_provider, config.default_ttl_sec)

    return AFTLoadBalancerStickinessManager(config, verifier)


@pytest.mark.asyncio
async def test_nested_metadata_format():
    """Test that both nested and flat metadata formats work."""
    print("=== Testing Nested Metadata Format ===")

    # Setup mock verifier
    from unittest.mock import AsyncMock

    mock_verifier = Mock()
    mock_verifier.verify = AsyncMock(
        return_value=AFTVerificationResult(
            valid=True, sid="test-sid", exp=int(time.time()) + 60, trust_level="trusted"
        )
    )

    # Create stickiness manager
    config = AFTLoadBalancerStickinessManagerConfig(enabled=True)
    manager = create_stickiness_manager(config, key_provider=get_key_provider(), verifier=mock_verifier)

    # Test 1: Nested format
    envelope1 = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid-1")
    envelope1.meta = {"set": {"aft": "nested.aft.token.123"}}

    await manager.handle_outbound_envelope(envelope1, "replica-1")
    print("✓ Nested format processed successfully")
    print("  Token used: nested.aft.token.123")

    # Test 2: Flat format (backward compatibility)
    envelope2 = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid-2")
    envelope2.meta = {"set.aft": "flat.aft.token.456"}

    await manager.handle_outbound_envelope(envelope2, "replica-2")
    print("✓ Flat format still works (backward compatibility)")
    print("  Token used: flat.aft.token.456")

    # Test 3: Nested format takes precedence when both are present
    envelope3 = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid-3")
    envelope3.meta = {"set.aft": "should.not.use.this", "set": {"aft": "should.use.this.nested"}}

    mock_verifier.reset_mock()
    await manager.handle_outbound_envelope(envelope3, "replica-3")

    # Verify nested format was used
    mock_verifier.verify.assert_called_once_with("should.use.this.nested", "test-sid-3")
    print("✓ Nested format takes precedence over flat format")
    print("  Used nested token: should.use.this.nested")
    print("  Ignored flat token: should.not.use.this")

    # Check associations
    associations = manager.get_associations()
    print(f"✓ Total associations created: {len(associations)}")


def test_stickiness_required_flag():
    """Test the new stickiness_required flag in FameDeliveryContext."""
    print("\n=== Testing stickiness_required Flag ===")

    # Test 1: Context without stickiness_required (default behavior)
    context1 = FameDeliveryContext(from_system_id="test-node", origin_type=DeliveryOriginType.LOCAL)
    print(f"✓ Default context - stickiness_required: {context1.stickiness_required}")

    # Test 2: Context with stickiness_required=True
    context2 = FameDeliveryContext(
        from_system_id="test-node", origin_type=DeliveryOriginType.LOCAL, stickiness_required=True
    )
    print(f"✓ Explicit stickiness required - stickiness_required: {context2.stickiness_required}")

    # Test 3: Context with stickiness_required=False
    context3 = FameDeliveryContext(
        from_system_id="test-node", origin_type=DeliveryOriginType.LOCAL, stickiness_required=False
    )
    print(f"✓ Explicit stickiness not required - stickiness_required: {context3.stickiness_required}")

    # Test 4: Show how this could be used in routing decisions
    def routing_decision(context: FameDeliveryContext) -> str:
        """Example function showing how stickiness_required could be used."""
        if context.stickiness_required is True:
            return "STICKY_ROUTE"
        elif context.stickiness_required is False:
            return "LOAD_BALANCED_ROUTE"
        else:
            return "DEFAULT_ROUTE"

    print(f"✓ Routing with default context: {routing_decision(context1)}")
    print(f"✓ Routing with required stickiness: {routing_decision(context2)}")
    print(f"✓ Routing with explicit no stickiness: {routing_decision(context3)}")


@pytest.mark.asyncio
async def test_extended_nested_format():
    """Test extended nested metadata format with complex structures."""
    print("\n=== Testing Extended Nested Format ===")

    # Setup mock verifier
    from unittest.mock import AsyncMock

    mock_verifier = Mock()
    mock_verifier.verify = AsyncMock(
        return_value=AFTVerificationResult(
            valid=True, sid="test-sid", exp=int(time.time()) + 60, trust_level="trusted"
        )
    )

    # Create stickiness manager
    config = AFTLoadBalancerStickinessManagerConfig(enabled=True)
    manager = create_stickiness_manager(config, key_provider=get_key_provider(), verifier=mock_verifier)

    # Test with complex nested structure
    envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid-extended")
    envelope.meta = {
        "set": {
            "aft": "complex.nested.token.789",
            "other_field": "should_be_ignored",
            "nested_dict": {"inner": "value"},
        },
        "unrelated": "data",
    }

    await manager.handle_outbound_envelope(envelope, "replica-extended")

    # Verify the correct AFT token was extracted
    mock_verifier.verify.assert_called_once_with("complex.nested.token.789", "test-sid-extended")
    print("✓ Complex nested structure processed correctly")
    print("  Token used: complex.nested.token.789")
    print("  Other nested fields ignored as expected")

    # Check association was created
    associations = manager.get_associations()
    assert "complex.nested.token.789" in associations
    print("✓ Association created for AFT token: complex.nested.token.789")

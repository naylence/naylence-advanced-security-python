import json
import time
from unittest.mock import Mock, patch

import pytest

from naylence.fame.core import create_fame_envelope
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.stickiness.aft_helper import create_aft_helper
from naylence.fame.stickiness.aft_load_balancer_stickiness_manager import AFTLoadBalancerStickinessManager
from naylence.fame.stickiness.aft_load_balancer_stickiness_manager_factory import (
    AFTLoadBalancerStickinessManagerConfig,
)
from naylence.fame.stickiness.aft_signer import create_aft_signer
from naylence.fame.stickiness.aft_verifier import AFTVerificationResult, create_aft_verifier
from naylence.fame.stickiness.stickiness_mode import StickinessMode


def create_stickiness_manager(config: AFTLoadBalancerStickinessManagerConfig, key_provider, verifier=None):
    """Factory function to create a stickiness manager for tests."""
    if not verifier:
        verifier = create_aft_verifier(config.security_level, key_provider, config.default_ttl_sec)

    return AFTLoadBalancerStickinessManager(config, verifier)


class TestStickinessConfig:
    """Test stickiness configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = AFTLoadBalancerStickinessManagerConfig()

        assert config.enabled is True
        assert config.client_echo is False
        assert config.default_ttl_sec == 30
        assert config.cache_max == 100_000
        assert config.security_level == StickinessMode.SIGNED_OPTIONAL
        assert config.max_ttl_sec == 7200

    def test_custom_config(self):
        """Test custom configuration."""
        config = AFTLoadBalancerStickinessManagerConfig(
            enabled=False,
            client_echo=True,
            default_ttl_sec=60,
            cache_max=50_000,
            security_level=StickinessMode.SIGNED_OPTIONAL,
            max_ttl_sec=3600,
        )

        assert config.enabled is False
        assert config.client_echo is True
        assert config.default_ttl_sec == 60
        assert config.cache_max == 50_000
        assert config.security_level == StickinessMode.SIGNED_OPTIONAL
        assert config.max_ttl_sec == 3600


class TestAFTSigner:
    """Test AFT signing functionality."""

    def test_unsigned_signer(self):
        """Test unsigned AFT signer."""
        signer = create_aft_signer(StickinessMode.SIGNED_OPTIONAL, "test-kid")

        token = signer.sign_aft(sid="test-node", ttl_sec=30)
        assert token
        assert "." in token

        # Should be 3 parts (header.payload.signature)
        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] == ""  # Empty signature for unsigned

    def test_sid_only_signer(self):
        """Test SID-only mode signer."""
        signer = create_aft_signer(StickinessMode.SID_ONLY, "none")

        token = signer.sign_aft(sid="test-node", ttl_sec=30)
        assert token == ""  # No token in SID-only mode

    def test_signed_signer(self):
        """Test signed AFT signer."""
        # Use a valid Ed25519 private key for testing
        # This is a test key generated specifically for this test
        private_key_pem = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIG7Ld8VQKDyLdXEsJZIl2CHyZKnrZbJMUpQ6LQKFo7tN
-----END PRIVATE KEY-----"""

        signer = create_aft_signer(StickinessMode.STRICT, "test-kid", private_key_pem)

        token = signer.sign_aft(sid="test-node", ttl_sec=30, scope="node")

        # Verify token is a valid JWT format (3 parts separated by dots)
        assert token
        parts = token.split(".")
        assert len(parts) == 3

        # Decode and verify the header and payload (without signature verification)
        import base64

        # Decode header
        header_data = base64.urlsafe_b64decode(parts[0] + "=" * (4 - len(parts[0]) % 4))
        header = json.loads(header_data)
        assert header["alg"] == "EdDSA"
        assert header["kid"] == "test-kid"
        assert header["typ"] == "JWT"

        # Decode payload
        payload_data = base64.urlsafe_b64decode(parts[1] + "=" * (4 - len(parts[1]) % 4))
        payload = json.loads(payload_data)
        assert payload["sid"] == "test-node"
        assert payload["scp"] == "node"
        assert "exp" in payload

    async def test_sid_only_verifier(self):
        """Test SID-only verifier always returns invalid."""
        # Create a mock key provider for the verifier
        from unittest.mock import Mock

        from naylence.fame.security.keys.key_provider import KeyProvider

        mock_key_provider = Mock(spec=KeyProvider)
        verifier = create_aft_verifier(StickinessMode.SID_ONLY, mock_key_provider)

        result = await verifier.verify("any.token.here", "test-sid")

        assert not result.valid
        assert "SID-only mode ignores AFTs" in result.error

    def test_verification_result(self):
        """Test verification result structure."""
        result = AFTVerificationResult(
            valid=True, sid="test-sid", exp=1234567890, scope="node", trust_level="trusted"
        )

        assert result.valid
        assert result.sid == "test-sid"
        assert result.exp == 1234567890
        assert result.scope == "node"
        assert result.trust_level == "trusted"
        assert result.error is None


class TestAFTSentinelStickinessManager:
    """Test stickiness management functionality."""

    @pytest.fixture
    def config(self):
        """Test configuration."""
        return AFTLoadBalancerStickinessManagerConfig(
            enabled=True,
            default_ttl_sec=30,
            cache_max=100,
            security_level=StickinessMode.SIGNED_OPTIONAL,
        )

    @pytest.fixture
    def mock_verifier(self):
        """Mock AFT verifier."""
        verifier = Mock()
        verifier.security_level = StickinessMode.SIGNED_OPTIONAL
        return verifier

    @pytest.fixture
    def mock_key_provider(self):
        """Mock key provider."""
        from unittest.mock import Mock

        from naylence.fame.security.keys.key_provider import KeyProvider

        return Mock(spec=KeyProvider)

    @pytest.fixture
    def manager(self, config, mock_key_provider, mock_verifier):
        """Test stickiness manager."""
        return create_stickiness_manager(config, mock_key_provider, mock_verifier)

    async def test_disabled_stickiness(self, mock_verifier, mock_key_provider):
        """Test that disabled stickiness does nothing."""
        config = AFTLoadBalancerStickinessManagerConfig(enabled=False)
        manager = create_stickiness_manager(config, mock_key_provider, mock_verifier)

        envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid")
        envelope.meta = {"set.aft": "test.token.here"}

        # Should return None for disabled stickiness
        result = await manager.handle_outbound_envelope(envelope, "replica-1")
        assert result is None

        # Should also return None for inbound
        result = manager.get_sticky_replica_segment(envelope)
        assert result is None

    async def test_outbound_aft_handling(self, manager, mock_verifier):
        """Test handling outbound envelope with AFT instruction."""
        # Setup mock verification - make it async
        from unittest.mock import AsyncMock

        mock_verifier.verify = AsyncMock(
            return_value=AFTVerificationResult(
                valid=True, sid="test-sid", exp=int(time.time()) + 60, trust_level="trusted"
            )
        )

        envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid")
        envelope.meta = {"set.aft": "valid.aft.token"}

        # Handle the envelope - await it
        await manager.handle_outbound_envelope(envelope, "replica-1")

        # Should verify the token
        mock_verifier.verify.assert_called_once_with("valid.aft.token", "test-sid")

        # Should store association
        associations = manager.get_associations()
        assert len(associations) == 1

        # Check metrics
        metrics = manager.get_metrics()
        assert metrics["associations_created"] == 1
        assert metrics["verify_failures"] == 0

    async def test_outbound_invalid_aft(self, manager, mock_verifier):
        """Test handling outbound envelope with invalid AFT."""
        # Setup mock verification to fail - make it async
        from unittest.mock import AsyncMock

        mock_verifier.verify = AsyncMock(
            return_value=AFTVerificationResult(valid=False, error="Invalid signature")
        )

        envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid")
        envelope.meta = {"set.aft": "invalid.aft.token"}

        # Handle the envelope - await it
        await manager.handle_outbound_envelope(envelope, "replica-1")

        # Should not create association
        associations = manager.get_associations()
        assert len(associations) == 0

        # Check metrics
        metrics = manager.get_metrics()
        assert metrics["verify_failures"] == 1
        assert metrics["associations_created"] == 0

    async def test_inbound_routing(self, manager, mock_verifier):
        """Test inbound envelope routing."""
        # First, create an association
        from unittest.mock import AsyncMock

        mock_verifier.verify = AsyncMock(
            return_value=AFTVerificationResult(
                valid=True, sid="test-sid", exp=int(time.time()) + 60, trust_level="trusted"
            )
        )

        # Outbound envelope creates association
        outbound_envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid")
        outbound_envelope.meta = {"set.aft": "valid.aft.token"}
        await manager.handle_outbound_envelope(outbound_envelope, "replica-1")

        # Now test inbound routing with AFT
        inbound_envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid")
        inbound_envelope.aft = "valid.aft.token"

        replica_id = manager.get_sticky_replica_segment(inbound_envelope)
        assert replica_id == "replica-1"

        # Check cache hit metric
        metrics = manager.get_metrics()
        assert metrics["cache_hits"] == 1

    async def test_sid_cache_routing(self, manager, mock_verifier):
        """Test routing via SID cache when no AFT present."""
        # Create association first
        from unittest.mock import AsyncMock

        mock_verifier.verify = AsyncMock(
            return_value=AFTVerificationResult(
                valid=True,
                sid="replica-sid",
                exp=int(time.time()) + 60,
                trust_level="trusted",
                client_sid="test-sid",
            )
        )

        outbound_envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid")
        outbound_envelope.meta = {"set.aft": "valid.aft.token"}
        await manager.handle_outbound_envelope(outbound_envelope, "replica-1")

        # Now test inbound without AFT but with matching SID
        inbound_envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid")
        # No AFT set initially

        replica_id = manager.get_sticky_replica_segment(inbound_envelope)
        assert replica_id == "replica-1"

        # Should have injected the AFT
        assert inbound_envelope.aft == "valid.aft.token"

    async def test_replica_departure(self, manager, mock_verifier):
        """Test handling replica departure."""
        # Create some associations
        from unittest.mock import AsyncMock

        mock_verifier.verify = AsyncMock(
            return_value=AFTVerificationResult(
                valid=True, sid="test-sid", exp=int(time.time()) + 60, trust_level="trusted"
            )
        )

        for i in range(3):
            envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid=f"test-sid-{i}")
            envelope.meta = {"set.aft": f"token-{i}"}
            await manager.handle_outbound_envelope(envelope, "replica-1")

        # Create association for different replica
        envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid-other")
        envelope.meta = {"set.aft": "token-other"}
        await manager.handle_outbound_envelope(envelope, "replica-2")

        # Should have 4 associations
        assert len(manager.get_associations()) == 4

        # Remove replica-1
        manager.replica_left("replica-1")

        # Should have 1 association remaining
        associations = manager.get_associations()
        assert len(associations) == 1

        # The remaining association should be for replica-2
        remaining = list(associations.values())[0]
        assert remaining["replica_id"] == "replica-2"

    async def test_nested_metadata_format(self, manager, mock_verifier):
        """Test handling envelopes with nested 'set' metadata format."""
        # Setup mock verification
        from unittest.mock import AsyncMock

        mock_verifier.verify = AsyncMock(
            return_value=AFTVerificationResult(
                valid=True, sid="test-sid", exp=int(time.time()) + 60, trust_level="trusted"
            )
        )

        # Test nested format: {"set": {"aft": "token"}}
        envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid")
        envelope.meta = {"set": {"aft": "nested.aft.token"}}

        # Handle the envelope
        await manager.handle_outbound_envelope(envelope, "replica-1")

        # Should verify the token
        mock_verifier.verify.assert_called_once_with("nested.aft.token", "test-sid")

        # Should store association
        associations = manager.get_associations()
        assert len(associations) == 1

        # Test that both old and new formats work together
        envelope2 = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid-2")
        envelope2.meta = {"set.aft": "flat.aft.token"}

        await manager.handle_outbound_envelope(envelope2, "replica-2")

        # Should have 2 associations now
        assert len(manager.get_associations()) == 2

        # Test that nested format takes precedence when both are present
        envelope3 = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid-3")
        envelope3.meta = {
            "set.aft": "should.not.use.this",
            "set": {"aft": "should.use.this"},
        }

        mock_verifier.reset_mock()
        await manager.handle_outbound_envelope(envelope3, "replica-3")

        # Should use the nested format value
        mock_verifier.verify.assert_called_once_with("should.use.this", "test-sid-3")

    async def test_stickiness_required_flag(self, manager, mock_verifier):
        """Test the stickiness_required flag in FameDeliveryContext."""
        # Setup mock verification
        from unittest.mock import AsyncMock

        mock_verifier.verify = AsyncMock(
            return_value=AFTVerificationResult(
                valid=True, sid="test-sid", exp=int(time.time()) + 60, trust_level="trusted"
            )
        )

        # Test with stickiness_required=True
        envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid")
        envelope.meta = {"set": {"aft": "stickiness.required.token"}}

        # Create context with stickiness_required flag
        from naylence.fame.core import DeliveryOriginType, FameDeliveryContext

        context_required = FameDeliveryContext(
            from_system_id="test-node", origin_type=DeliveryOriginType.LOCAL, stickiness_required=True
        )

        # Verify the context has the flag set
        assert context_required.stickiness_required is True

        # Test with stickiness_required=False
        context_not_required = FameDeliveryContext(
            from_system_id="test-node", origin_type=DeliveryOriginType.LOCAL, stickiness_required=False
        )

        assert context_not_required.stickiness_required is False

        # Test default (None)
        context_default = FameDeliveryContext(
            from_system_id="test-node", origin_type=DeliveryOriginType.LOCAL
        )

        assert context_default.stickiness_required is None

        # The actual stickiness processing should still work regardless of the flag
        await manager.handle_outbound_envelope(envelope, "replica-1")
        mock_verifier.verify.assert_called_once_with("stickiness.required.token", "test-sid")


class TestAFTHelper:
    """Test AFT helper for replicas."""

    @pytest.fixture
    def config(self):
        """Test configuration - use SID_ONLY to avoid needing private keys."""
        return AFTLoadBalancerStickinessManagerConfig(
            enabled=True, default_ttl_sec=30, security_level=StickinessMode.SID_ONLY
        )

    @pytest.fixture
    def mock_signer(self):
        """Mock AFT signer."""
        signer = Mock()
        signer.security_level = StickinessMode.SID_ONLY
        signer.sign_aft.return_value = ""  # SID_ONLY returns empty string
        return signer

    @pytest.fixture
    def helper(self, config, mock_signer):
        """Test AFT helper."""
        return create_aft_helper(config.security_level, "test-node", "test-kid")

    def test_request_stickiness(self, helper, config, mock_signer):
        """Test requesting stickiness."""
        # Patch the signer creation
        with patch("naylence.fame.stickiness.aft_helper.create_aft_signer", return_value=mock_signer):
            helper = create_aft_helper(config, "test-node", "test-kid")

            envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"))

            success = helper.request_stickiness(envelope, ttl_sec=60, scope="flow")

            # In SID_ONLY mode, no AFT is generated, so success should be False
            if config.security_level == StickinessMode.SID_ONLY:
                assert not success  # No AFT generated in SID_ONLY mode
                assert envelope.meta is None or envelope.meta.get("set.aft") is None
            else:
                assert success
                assert envelope.meta is not None
                assert envelope.meta["set.aft"] == ""

            # Check signer was called correctly
            mock_signer.sign_aft.assert_called_once_with(
                sid="test-node", ttl_sec=60, scope="flow", client_sid=None
            )

    def test_convenience_methods(self, helper, config, mock_signer):
        """Test convenience methods."""
        with patch("naylence.fame.stickiness.aft_helper.create_aft_signer", return_value=mock_signer):
            helper = create_aft_helper(
                config.security_level, "test-node", "test-kid", max_ttl_sec=config.default_ttl_sec
            )

            envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"))

            # Test node stickiness
            success = helper.request_node_stickiness(envelope)
            # In SID_ONLY mode, success is False because no AFT is generated
            if config.security_level == StickinessMode.SID_ONLY:
                assert not success
            else:
                assert success
            # When ttl_sec=None, the helper uses the default TTL from config
            mock_signer.sign_aft.assert_called_with(
                sid="test-node", ttl_sec=30, scope="node", client_sid=None
            )

            # Reset mock
            mock_signer.reset_mock()

            # Test flow stickiness
            success = helper.request_flow_stickiness(envelope, ttl_sec=120)
            if config.security_level == StickinessMode.SID_ONLY:
                assert not success
            else:
                assert success
            mock_signer.sign_aft.assert_called_with(
                sid="test-node", ttl_sec=120, scope="flow", client_sid=None
            )

            # Reset mock
            mock_signer.reset_mock()

            # Test session stickiness
            success = helper.request_session_stickiness(envelope)
            if config.security_level == StickinessMode.SID_ONLY:
                assert not success
            else:
                assert success
            # When ttl_sec=None, the helper uses the default TTL from config
            mock_signer.sign_aft.assert_called_with(
                sid="test-node", ttl_sec=30, scope="sess", client_sid=None
            )


class TestIntegration:
    """Test integration points for AFT and stickiness."""

    def test_aft_replica_stickiness_manager_integration(self):
        """Test AFTReplicaStickinessManager integration with behavioral contract."""
        from naylence.fame.core import DeliveryOriginType, FameDeliveryContext
        from naylence.fame.stickiness.aft_helper import create_aft_helper
        from naylence.fame.stickiness.aft_replica_stickiness_manager import (
            create_aft_replica_stickiness_manager,
        )

        # Create AFT helper and context handler
        config = AFTLoadBalancerStickinessManagerConfig(
            enabled=True,
            security_level=StickinessMode.SIGNED_OPTIONAL,
            default_ttl_sec=30,
        )

        aft_helper = create_aft_helper(
            security_level=config.security_level,
            node_sid="test-node-123",
            kid="test-kid",
        )

        context_handler = create_aft_replica_stickiness_manager(aft_helper)

        # Test case: stickiness_required = True
        envelope = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid")
        context = FameDeliveryContext(
            from_system_id="test-node-123", origin_type=DeliveryOriginType.LOCAL, stickiness_required=True
        )

        # Mock node
        class MockNode:
            def __init__(self):
                self.sid = "test-node-123"
                self.system_id = "test-node-123"

        mock_node = MockNode()

        # Process envelope
        import asyncio

        async def test_processing():
            return await context_handler.on_forward_upstream(mock_node, envelope, context)

        result_envelope = asyncio.run(test_processing())

        # Verify AFT token was added
        assert result_envelope.meta is not None
        assert "set" in result_envelope.meta
        assert isinstance(result_envelope.meta["set"], dict)
        assert "aft" in result_envelope.meta["set"]
        assert result_envelope.meta["set"]["aft"]  # Non-empty token

        # Test case: stickiness_required = False/None
        envelope2 = create_fame_envelope(frame=DataFrame(payload={}, codec="json"), sid="test-sid-2")
        context2 = FameDeliveryContext(
            from_system_id="test-node-123", origin_type=DeliveryOriginType.LOCAL, stickiness_required=False
        )

        async def test_no_stickiness():
            return await context_handler.on_forward_upstream(mock_node, envelope2, context2)

        result_envelope2 = asyncio.run(test_no_stickiness())

        # Verify no AFT token was added
        assert result_envelope2.meta is None or "set" not in result_envelope2.meta

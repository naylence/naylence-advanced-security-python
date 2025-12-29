"""
Tests for AdvancedAuthorizationPolicy.
"""

from dataclasses import dataclass
from typing import Any, Optional

import pytest

from naylence.fame.security.auth.policy.advanced_authorization_policy import (
    AdvancedAuthorizationPolicy,
    AdvancedAuthorizationPolicyOptions,
)
from naylence.fame.security.auth.policy.authorization_policy_definition import (
    AuthorizationPolicyDefinition,
)


# Mock types for testing
@dataclass
class MockFrame:
    """Mock frame object."""

    type: str


@dataclass
class MockSignatureHeader:
    """Mock signature header."""

    alg: Optional[str] = None
    kid: Optional[str] = None
    val: Optional[str] = None


@dataclass
class MockEncryptionHeader:
    """Mock encryption header."""

    alg: Optional[str] = None
    kid: Optional[str] = None
    val: Optional[str] = None


@dataclass
class MockSecurityHeader:
    """Mock security header."""

    sig: Optional[MockSignatureHeader] = None
    enc: Optional[MockEncryptionHeader] = None


@dataclass
class MockEnvelope:
    """Mock envelope for testing."""

    id: Optional[str] = None
    to: Optional[str] = None
    from_: Optional[str] = None
    frame: Optional[MockFrame] = None
    corr_id: Optional[str] = None
    sid: Optional[str] = None
    sec: Optional[MockSecurityHeader] = None


@dataclass
class MockAuthorizationContext:
    """Mock authorization context."""

    claims: Optional[dict[str, Any]] = None
    granted_scopes: Optional[list[str]] = None


@dataclass
class MockSecurity:
    """Mock security context."""

    authorization: Optional[MockAuthorizationContext] = None


@dataclass
class MockDeliveryContext:
    """Mock delivery context for testing."""

    security: Optional[MockSecurity] = None
    origin_type: Optional[str] = None


@dataclass
class MockNode:
    """Mock node for testing."""

    id: str
    sid: Optional[str] = None
    provisional_id: Optional[str] = None
    physical_path: Optional[str] = None
    has_parent: bool = False
    public_url: Optional[str] = None


def create_mock_node() -> MockNode:
    """Create a default mock node."""
    return MockNode(id="node-1")


def create_mock_envelope(frame_type: str = "action") -> MockEnvelope:
    """Create a default mock envelope."""
    return MockEnvelope(
        id="env-1",
        frame=MockFrame(type=frame_type),
    )


def create_policy(
    definition: AuthorizationPolicyDefinition,
) -> AdvancedAuthorizationPolicy:
    """Create an AdvancedAuthorizationPolicy from a definition."""
    options = AdvancedAuthorizationPolicyOptions(
        policy_definition=definition,
        warn_on_unknown_fields=False,
    )
    return AdvancedAuthorizationPolicy(options)


class TestFrameTypeValidation:
    """Tests for frame_type validation."""

    def test_accepts_valid_frame_type_data(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "frame_type": "Data",
                },
            ],
            default_effect="deny",
        )
        # Should not throw
        create_policy(definition)

    def test_accepts_valid_frame_type_node_hello(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "frame_type": "NodeHello",
                },
            ],
            default_effect="deny",
        )
        create_policy(definition)

    def test_accepts_array_of_valid_frame_types(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "frame_type": ["Data", "NodeHello", "NodeWelcome"],
                },
            ],
            default_effect="deny",
        )
        create_policy(definition)

    def test_rejects_invalid_frame_type(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "frame_type": "InvalidFrameType",
                },
            ],
            default_effect="deny",
        )
        with pytest.raises(ValueError, match=r"Invalid frame_type.*InvalidFrameType"):
            create_policy(definition)

    def test_rejects_invalid_frame_type_in_array(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "frame_type": ["Data", "BadType", "NodeHello"],
                },
            ],
            default_effect="deny",
        )
        with pytest.raises(ValueError, match=r"Invalid frame_type.*BadType"):
            create_policy(definition)

    def test_rejects_empty_frame_type_string(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "frame_type": "  ",
                },
            ],
            default_effect="deny",
        )
        with pytest.raises(ValueError, match=r"empty"):
            create_policy(definition)

    def test_accepts_valid_frame_type_secure_open(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "frame_type": "SecureOpen",
                },
            ],
            default_effect="deny",
        )
        create_policy(definition)

    def test_accepts_valid_frame_type_secure_accept(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "frame_type": "SecureAccept",
                },
            ],
            default_effect="deny",
        )
        create_policy(definition)

    def test_accepts_valid_frame_type_secure_close(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "frame_type": "SecureClose",
                },
            ],
            default_effect="deny",
        )
        create_policy(definition)

    @pytest.mark.asyncio
    async def test_normalizes_frame_type_to_lowercase_for_matching(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "frame_type": "Data",  # Uppercase in policy
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = MockEnvelope(
            id="env-1",
            frame=MockFrame(type="data"),  # Lowercase in envelope
        )

        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "allow"


class TestBasicRuleMatchingWithoutWhen:
    """Tests for basic rule matching without when expressions."""

    @pytest.mark.asyncio
    async def test_matches_allow_rule_without_when_expression(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()

        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "allow"

    @pytest.mark.asyncio
    async def test_matches_deny_rule_without_when_expression(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "deny",
                    "action": "*",
                },
            ],
            default_effect="allow",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()

        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "deny"

    @pytest.mark.asyncio
    async def test_falls_back_to_default_when_no_rules_match(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "Connect",  # Only matches Connect, not *
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()

        result = await policy.evaluate_request(node, envelope, None, "DeliverLocal")
        assert result.effect == "deny"


class TestWhenExpressionEvaluation:
    """Tests for when expression evaluation."""

    @pytest.mark.asyncio
    async def test_allows_when_expression_is_true(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "when": 'claims.role == "admin"',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()
        context = MockDeliveryContext(
            security=MockSecurity(
                authorization=MockAuthorizationContext(
                    claims={"role": "admin"},
                ),
            ),
        )

        result = await policy.evaluate_request(node, envelope, context, "*")
        assert result.effect == "allow"

    @pytest.mark.asyncio
    async def test_denies_when_expression_is_false(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "when": 'claims.role == "admin"',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()
        context = MockDeliveryContext(
            security=MockSecurity(
                authorization=MockAuthorizationContext(
                    claims={"role": "user"},
                ),
            ),
        )

        result = await policy.evaluate_request(node, envelope, context, "*")
        assert result.effect == "deny"

    @pytest.mark.asyncio
    async def test_checks_scope_requirements_in_when(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "when": 'has_scope("admin")',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()
        context = MockDeliveryContext(
            security=MockSecurity(
                authorization=MockAuthorizationContext(
                    granted_scopes=["admin", "read"],
                ),
            ),
        )

        result = await policy.evaluate_request(node, envelope, context, "*")
        assert result.effect == "allow"

    @pytest.mark.asyncio
    async def test_combines_claims_and_scope_checks(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "when": 'claims.role == "admin" && has_scope("write")',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()
        context = MockDeliveryContext(
            security=MockSecurity(
                authorization=MockAuthorizationContext(
                    claims={"role": "admin"},
                    granted_scopes=["write"],
                ),
            ),
        )

        result = await policy.evaluate_request(node, envelope, context, "*")
        assert result.effect == "allow"


class TestExpressionParseErrorHandling:
    """Tests for expression parse error handling."""

    @pytest.mark.asyncio
    async def test_does_not_match_rule_with_parse_error_in_when(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "when": "invalid syntax (((",
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()

        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "deny"

    @pytest.mark.asyncio
    async def test_includes_parse_error_info_in_traces(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "when": "missing_paren(",
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()

        result = await policy.evaluate_request(node, envelope, None, "*")
        assert len(result.evaluation_trace) > 0


class TestRuleEvaluationOrder:
    """Tests for rule evaluation order."""

    @pytest.mark.asyncio
    async def test_first_matching_rule_wins(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "deny",
                    "action": "*",
                    "when": 'claims.role == "blocked"',
                },
                {
                    "effect": "allow",
                    "action": "*",
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()

        # Blocked user
        blocked_context = MockDeliveryContext(
            security=MockSecurity(
                authorization=MockAuthorizationContext(
                    claims={"role": "blocked"},
                ),
            ),
        )
        blocked_result = await policy.evaluate_request(
            node, envelope, blocked_context, "*"
        )
        assert blocked_result.effect == "deny"

        # Regular user - first deny rule doesn't match, falls to second allow
        allowed_context = MockDeliveryContext(
            security=MockSecurity(
                authorization=MockAuthorizationContext(
                    claims={"role": "user"},
                ),
            ),
        )
        allowed_result = await policy.evaluate_request(
            node, envelope, allowed_context, "*"
        )
        assert allowed_result.effect == "allow"


class TestEnvelopeBindings:
    """Tests for envelope bindings in expressions."""

    @pytest.mark.asyncio
    async def test_accesses_envelope_id_in_when(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "when": "envelope.id != null",
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = MockEnvelope(
            id="env-123",
            frame=MockFrame(type="action"),
        )

        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "allow"


class TestDeliveryBindings:
    """Tests for delivery context bindings in expressions."""

    @pytest.mark.asyncio
    async def test_accesses_origin_type_in_when(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "effect": "allow",
                    "action": "*",
                    "when": 'delivery.origin_type == "downstream"',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()
        context = MockDeliveryContext(
            origin_type="downstream",
        )

        result = await policy.evaluate_request(node, envelope, context, "*")
        assert result.effect == "allow"


class TestNullHandlingInWhenExpressions:
    """Tests for null/undefined handling in when expressions."""

    @pytest.mark.asyncio
    async def test_handles_missing_claims_sub_with_starts_with(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "node-rule",
                    "effect": "allow",
                    "action": "*",
                    "when": 'starts_with(claims.sub, "node-")',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()
        context = MockDeliveryContext(
            security=MockSecurity(
                authorization=MockAuthorizationContext(
                    claims={},  # sub is missing
                ),
            ),
        )

        result = await policy.evaluate_request(node, envelope, context, "*")
        # Rule does NOT match (starts_with returns False for None)
        assert result.effect == "deny"
        # Trace should NOT include error (expression returned False, not error)
        rule_trace = next(
            (t for t in result.evaluation_trace if t.rule_id == "node-rule"),
            None,
        )
        assert rule_trace is not None
        assert "false" in rule_trace.expression.lower()

    @pytest.mark.asyncio
    async def test_handles_valid_claims_sub(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "node-rule",
                    "effect": "allow",
                    "action": "*",
                    "when": 'starts_with(claims.sub, "node-")',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()
        context = MockDeliveryContext(
            security=MockSecurity(
                authorization=MockAuthorizationContext(
                    claims={"sub": "node-123"},
                ),
            ),
        )

        result = await policy.evaluate_request(node, envelope, context, "*")
        assert result.effect == "allow"
        assert result.matched_rule == "node-rule"

    @pytest.mark.asyncio
    async def test_handles_null_scope_in_has_scope(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "scope-rule",
                    "effect": "allow",
                    "action": "*",
                    "when": "has_scope(claims.requiredScope)",
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()
        context = MockDeliveryContext(
            security=MockSecurity(
                authorization=MockAuthorizationContext(
                    claims={"requiredScope": None},
                    granted_scopes=["admin"],
                ),
            ),
        )

        result = await policy.evaluate_request(node, envelope, context, "*")
        # Rule does NOT match (has_scope returns False for None)
        assert result.effect == "deny"
        # No error in trace
        rule_trace = next(
            (t for t in result.evaluation_trace if t.rule_id == "scope-rule"),
            None,
        )
        assert rule_trace is not None
        assert "error" not in rule_trace.expression.lower()

    @pytest.mark.asyncio
    async def test_handles_contains_with_missing_field(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "email-rule",
                    "effect": "allow",
                    "action": "*",
                    "when": 'contains(claims.email, "@example.com")',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()
        context = MockDeliveryContext(
            security=MockSecurity(
                authorization=MockAuthorizationContext(
                    claims={},  # email is missing
                ),
            ),
        )

        result = await policy.evaluate_request(node, envelope, context, "*")
        # Rule does NOT match (contains returns False for None)
        assert result.effect == "deny"

    @pytest.mark.asyncio
    async def test_handles_glob_match_with_null_value(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "pattern-rule",
                    "effect": "allow",
                    "action": "*",
                    "when": 'glob_match(claims.resource, "service.*")',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()
        context = MockDeliveryContext(
            security=MockSecurity(
                authorization=MockAuthorizationContext(
                    claims={"resource": None},
                ),
            ),
        )

        result = await policy.evaluate_request(node, envelope, context, "*")
        assert result.effect == "deny"

    @pytest.mark.asyncio
    async def test_handles_ends_with_with_valid_match(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "domain-rule",
                    "effect": "allow",
                    "action": "*",
                    "when": 'ends_with(claims.email, "@corp.example.com")',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()
        context = MockDeliveryContext(
            security=MockSecurity(
                authorization=MockAuthorizationContext(
                    claims={"email": "user@corp.example.com"},
                ),
            ),
        )

        result = await policy.evaluate_request(node, envelope, context, "*")
        assert result.effect == "allow"


class TestParameterizedNullHandling:
    """Parameterized tests for null handling."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "when_expr,claims,expected_effect,should_have_error",
        [
            ('starts_with(claims.sub, "x")', {}, "deny", False),
            ('starts_with(claims.sub, "x")', {"sub": None}, "deny", False),
            ('ends_with(claims.sub, "x")', {}, "deny", False),
            ('contains(claims.sub, "x")', {"sub": 42}, "deny", True),
            ('starts_with(claims.sub, "test")', {"sub": "test-123"}, "allow", False),
            ('starts_with(claims.sub, "other")', {"sub": "test-123"}, "deny", False),
        ],
    )
    async def test_when_expression_returns_expected_effect(
        self, when_expr, claims, expected_effect, should_have_error
    ):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "test-rule",
                    "effect": "allow",
                    "action": "*",
                    "when": when_expr,
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = create_mock_node()
        envelope = create_mock_envelope()
        context = MockDeliveryContext(
            security=MockSecurity(
                authorization=MockAuthorizationContext(claims=claims),
            ),
        )

        result = await policy.evaluate_request(node, envelope, context, "*")
        assert result.effect == expected_effect

        trace = next(
            (t for t in result.evaluation_trace if t.rule_id == "test-rule"),
            None,
        )
        if should_have_error and trace:
            assert "error" in trace.expression.lower()
        elif expected_effect == "deny" and trace:
            assert "error" not in trace.expression.lower() or should_have_error


class TestNodeContextInExpressions:
    """Tests for node context in expressions."""

    @pytest.mark.asyncio
    async def test_provides_access_to_node_id_in_when_expressions(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "node-id-check",
                    "effect": "allow",
                    "action": "*",
                    "when": 'node.id == "node-1"',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = MockNode(id="node-1")
        envelope = create_mock_envelope()

        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "allow"
        assert result.matched_rule == "node-id-check"

    @pytest.mark.asyncio
    async def test_provides_access_to_node_sid_in_when_expressions(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "node-sid-check",
                    "effect": "allow",
                    "action": "*",
                    "when": 'node.sid == "production-cluster"',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = MockNode(
            id="node-1",
            sid="production-cluster",
            provisional_id="prov-1",
            physical_path="/",
            has_parent=False,
            public_url=None,
        )
        envelope = create_mock_envelope()

        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "allow"
        assert result.matched_rule == "node-sid-check"

    @pytest.mark.asyncio
    async def test_handles_null_node_sid_correctly(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "null-sid-check",
                    "effect": "allow",
                    "action": "*",
                    "when": "node.sid == null",
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = MockNode(
            id="node-1",
            sid=None,
            provisional_id="prov-1",
            physical_path="/",
            has_parent=False,
            public_url=None,
        )
        envelope = create_mock_envelope()

        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "allow"

    @pytest.mark.asyncio
    async def test_provides_access_to_node_physical_path_in_when_expressions(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "path-check",
                    "effect": "allow",
                    "action": "*",
                    "when": 'starts_with(node.physicalPath, "/systems/prod/")',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = MockNode(
            id="node-1",
            sid=None,
            provisional_id="prov-1",
            physical_path="/systems/prod/worker-01",
            has_parent=True,
            public_url=None,
        )
        envelope = create_mock_envelope()

        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "allow"
        assert result.matched_rule == "path-check"

    @pytest.mark.asyncio
    async def test_provides_access_to_node_has_parent_in_when_expressions(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "parent-check",
                    "effect": "allow",
                    "action": "*",
                    "when": "node.hasParent == true",
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = MockNode(
            id="node-1",
            sid=None,
            provisional_id="prov-1",
            physical_path="/child",
            has_parent=True,
            public_url=None,
        )
        envelope = create_mock_envelope()

        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "allow"

    @pytest.mark.asyncio
    async def test_provides_access_to_node_public_url_in_when_expressions(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "url-check",
                    "effect": "allow",
                    "action": "*",
                    "when": 'starts_with(node.publicUrl, "https://secure")',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = MockNode(
            id="node-1",
            sid=None,
            provisional_id="prov-1",
            physical_path="/",
            has_parent=False,
            public_url="https://secure.example.com",
        )
        envelope = create_mock_envelope()

        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "allow"

    @pytest.mark.asyncio
    async def test_handles_null_node_public_url_correctly(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "null-url-check",
                    "effect": "deny",
                    "action": "*",
                    "when": "node.publicUrl == null",
                },
            ],
            default_effect="allow",
        )
        policy = create_policy(definition)
        node = MockNode(
            id="node-1",
            sid=None,
            provisional_id="prov-1",
            physical_path="/",
            has_parent=False,
            public_url=None,
        )
        envelope = create_mock_envelope()

        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "deny"

    @pytest.mark.asyncio
    async def test_combines_node_properties_with_other_context_in_when(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "combined-check",
                    "effect": "allow",
                    "action": "*",
                    "when": (
                        'node.sid == "prod" && has_scope("admin:write") && '
                        'envelope.frame.type == "action"'
                    ),
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = MockNode(
            id="node-1",
            sid="prod",
            provisional_id="prov-1",
            physical_path="/",
            has_parent=False,
            public_url=None,
        )
        envelope = create_mock_envelope()
        context = MockDeliveryContext(
            security=MockSecurity(
                authorization=MockAuthorizationContext(
                    granted_scopes=["admin:write", "read"],
                ),
            ),
        )

        result = await policy.evaluate_request(node, envelope, context, "*")
        assert result.effect == "allow"
        assert result.matched_rule == "combined-check"

    @pytest.mark.asyncio
    async def test_denies_when_node_condition_does_not_match(self):
        definition = AuthorizationPolicyDefinition(
            version="1.0.0",
            rules=[
                {
                    "id": "mismatch-check",
                    "effect": "allow",
                    "action": "*",
                    "when": 'node.id == "different-node"',
                },
            ],
            default_effect="deny",
        )
        policy = create_policy(definition)
        node = MockNode(id="node-1")
        envelope = create_mock_envelope()

        result = await policy.evaluate_request(node, envelope, None, "*")
        assert result.effect == "deny"
        trace = next(
            (t for t in result.evaluation_trace if t.rule_id == "mismatch-check"),
            None,
        )
        assert trace is not None
        assert "false" in trace.expression.lower()


# ============================================================
# Security posture builtin integration tests
# ============================================================


class TestSecurityPostureBuiltinIntegration:
    """Integration tests for security posture builtins in policy evaluation."""

    class TestIsSignedBuiltin:
        """Tests for is_signed() builtin in policy rules."""

        @pytest.mark.asyncio
        async def test_allows_when_envelope_is_signed(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "require-signature",
                        "effect": "allow",
                        "action": "*",
                        "when": "is_signed()",
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
                sec=MockSecurityHeader(sig=MockSignatureHeader(kid="key-1")),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "allow"
            assert result.matched_rule == "require-signature"

        @pytest.mark.asyncio
        async def test_denies_when_envelope_is_not_signed(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "require-signature",
                        "effect": "allow",
                        "action": "*",
                        "when": "is_signed()",
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "deny"

    class TestIsEncryptedBuiltin:
        """Tests for is_encrypted() builtin in policy rules."""

        @pytest.mark.asyncio
        async def test_allows_when_envelope_is_encrypted(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "require-encryption",
                        "effect": "allow",
                        "action": "*",
                        "when": "is_encrypted()",
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
                sec=MockSecurityHeader(
                    enc=MockEncryptionHeader(alg="ECDH-ES+A256GCM")
                ),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "allow"
            assert result.matched_rule == "require-encryption"

        @pytest.mark.asyncio
        async def test_denies_when_envelope_is_not_encrypted(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "require-encryption",
                        "effect": "allow",
                        "action": "*",
                        "when": "is_encrypted()",
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "deny"

    class TestEncryptionLevelBuiltin:
        """Tests for encryption_level() builtin in policy rules."""

        @pytest.mark.asyncio
        async def test_exposes_encryption_level_for_comparison(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "check-sealed",
                        "effect": "allow",
                        "action": "*",
                        "when": 'encryption_level() == "sealed"',
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
                sec=MockSecurityHeader(
                    enc=MockEncryptionHeader(alg="ECDH-ES+A256GCM")
                ),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "allow"

        @pytest.mark.asyncio
        async def test_returns_plaintext_for_no_encryption(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "check-plaintext",
                        "effect": "allow",
                        "action": "*",
                        "when": 'encryption_level() == "plaintext"',
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "allow"

    class TestIsEncryptedAtLeastBuiltin:
        """Tests for is_encrypted_at_least(level) builtin in policy rules."""

        @pytest.mark.asyncio
        async def test_allows_channel_for_channel_requirement(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "require-channel",
                        "effect": "allow",
                        "action": "*",
                        "when": 'is_encrypted_at_least("channel")',
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
                sec=MockSecurityHeader(
                    enc=MockEncryptionHeader(alg="chacha20-poly1305-channel")
                ),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "allow"

        @pytest.mark.asyncio
        async def test_allows_sealed_for_channel_requirement(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "require-channel",
                        "effect": "allow",
                        "action": "*",
                        "when": 'is_encrypted_at_least("channel")',
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
                sec=MockSecurityHeader(
                    enc=MockEncryptionHeader(alg="ECDH-ES+A256GCM")
                ),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "allow"

        @pytest.mark.asyncio
        async def test_denies_plaintext_for_channel_requirement(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "require-channel",
                        "effect": "allow",
                        "action": "*",
                        "when": 'is_encrypted_at_least("channel")',
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "deny"

        @pytest.mark.asyncio
        async def test_denies_channel_for_sealed_requirement(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "require-sealed",
                        "effect": "allow",
                        "action": "*",
                        "when": 'is_encrypted_at_least("sealed")',
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
                sec=MockSecurityHeader(
                    enc=MockEncryptionHeader(alg="chacha20-poly1305-channel")
                ),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "deny"

        @pytest.mark.asyncio
        async def test_denies_unknown_for_channel_conservative(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "require-channel",
                        "effect": "allow",
                        "action": "*",
                        "when": 'is_encrypted_at_least("channel")',
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
                sec=MockSecurityHeader(
                    enc=MockEncryptionHeader(alg="custom-unknown-algo")
                ),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "deny"

    class TestEnvelopeSecBindings:
        """Tests for envelope.sec bindings in policy rules."""

        @pytest.mark.asyncio
        async def test_accesses_envelope_sec_enc_level(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "check-enc-level",
                        "effect": "allow",
                        "action": "*",
                        "when": 'envelope.sec.enc.level == "sealed"',
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
                sec=MockSecurityHeader(
                    enc=MockEncryptionHeader(alg="ECDH-ES+A256GCM")
                ),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "allow"

        @pytest.mark.asyncio
        async def test_does_not_expose_sec_sig_val_in_bindings(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "check-no-val",
                        "effect": "allow",
                        "action": "*",
                        "when": "envelope.sec.sig.val == null",
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
                sec=MockSecurityHeader(
                    sig=MockSignatureHeader(kid="key-1", val="secret-signature")
                ),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            # val should be undefined/null in bindings, not the actual value
            assert result.effect == "allow"

    class TestEnvelopeSidBinding:
        """Tests for envelope.sid binding in policy rules."""

        @pytest.mark.asyncio
        async def test_accesses_envelope_sid(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "check-sid",
                        "effect": "allow",
                        "action": "*",
                        "when": 'envelope.sid == "source-system-hash"',
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                sid="source-system-hash",
                frame=MockFrame(type="Data"),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "allow"

    class TestCombinedSecurityConditions:
        """Tests for combined security conditions."""

        @pytest.mark.asyncio
        async def test_allows_when_both_signed_and_encrypted(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "require-both",
                        "effect": "allow",
                        "action": "*",
                        "when": "is_signed() && is_encrypted()",
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
                sec=MockSecurityHeader(
                    sig=MockSignatureHeader(kid="sig-key"),
                    enc=MockEncryptionHeader(alg="ECDH-ES+A256GCM"),
                ),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "allow"

        @pytest.mark.asyncio
        async def test_denies_when_only_signed_requires_both(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "require-both",
                        "effect": "allow",
                        "action": "*",
                        "when": "is_signed() && is_encrypted()",
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
                sec=MockSecurityHeader(sig=MockSignatureHeader(kid="sig-key")),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            assert result.effect == "deny"

        @pytest.mark.asyncio
        async def test_combines_security_with_scope_requirements(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "secure-admin",
                        "effect": "allow",
                        "action": "*",
                        "when": (
                            'is_signed() && is_encrypted_at_least("channel") '
                            '&& has_scope("admin")'
                        ),
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
                sec=MockSecurityHeader(
                    sig=MockSignatureHeader(kid="sig-key"),
                    enc=MockEncryptionHeader(alg="ECDH-ES+A256GCM"),
                ),
            )
            context = MockDeliveryContext(
                security=MockSecurity(
                    authorization=MockAuthorizationContext(
                        granted_scopes=["admin", "read"]
                    )
                )
            )

            result = await policy.evaluate_request(node, envelope, context, "*")
            assert result.effect == "allow"

    class TestSecurityExpressionErrorHandling:
        """Tests for error handling in security expressions."""

        @pytest.mark.asyncio
        async def test_surfaces_error_for_invalid_is_encrypted_at_least_arg(self):
            definition = AuthorizationPolicyDefinition(
                version="1.0.0",
                rules=[
                    {
                        "id": "invalid-level",
                        "effect": "allow",
                        "action": "*",
                        "when": 'is_encrypted_at_least("invalid_level")',
                    },
                ],
                default_effect="deny",
            )
            policy = create_policy(definition)
            node = create_mock_node()
            envelope = MockEnvelope(
                id="env-1",
                frame=MockFrame(type="Data"),
            )

            result = await policy.evaluate_request(node, envelope, None, "*")
            # Invalid arg should cause evaluation error, rule doesn't match
            assert result.effect == "deny"
            trace = next(
                (t for t in result.evaluation_trace if t.rule_id == "invalid-level"),
                None,
            )
            assert trace is not None
            assert "evaluation error" in trace.expression

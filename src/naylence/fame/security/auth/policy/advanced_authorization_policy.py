"""
Expression-based authorization policy implementation.

Extends the basic policy with support for `when` expression evaluation.
This is part of the BSL-licensed Advanced Security package.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Optional, Sequence

if TYPE_CHECKING:
    from naylence.fame.core import FameDeliveryContext, FameEnvelope
    from naylence.fame.node.node_like import NodeLike

from naylence.fame.expr.ast import AstNode
from naylence.fame.expr.builtins import ExprValue, FunctionRegistry
from naylence.fame.expr.evaluator import EvaluationContext, evaluate_as_boolean
from naylence.fame.expr.limits import DEFAULT_EXPRESSION_LIMITS, ExpressionLimits
from naylence.fame.expr.parser import parse
from naylence.fame.security.auth.policy.authorization_policy import (
    AuthorizationDecision,
    AuthorizationEffect,
    AuthorizationEvaluationStep,
    AuthorizationPolicy,
)
from naylence.fame.security.auth.policy.authorization_policy_definition import (
    KNOWN_POLICY_FIELDS,
    KNOWN_RULE_FIELDS,
    VALID_ACTIONS,
    VALID_EFFECTS,
    VALID_ORIGIN_TYPES,
    AuthorizationPolicyDefinition,
    AuthorizationRuleDefinition,
    RuleAction,
    RuleActionInput,
)
from naylence.fame.security.auth.policy.pattern_matcher import (
    CompiledPattern,
    compile_glob_pattern,
)
from naylence.fame.security.auth.policy.scope_matcher import (
    compile_glob_only_scope_requirement,
)

from .expr_builtins import (
    SecurityBindings,
    create_auth_function_registry,
    create_security_bindings,
)

logger = logging.getLogger(
    "naylence.fame.security.auth.policy.advanced_authorization_policy"
)


# Valid frame types that can be validated through authorization.
# These frame types reach the dispatchRoutingActionSelected hook and can be
# subject to authorization checks. Frame types NOT in this list either:
# - Bypass authorization entirely (e.g., AddressBindAck)
# - Are not valid frame types in the protocol
VALID_FRAME_TYPES = (
    "Data",
    "DeliveryAck",
    "NodeAttach",
    "NodeHello",
    "NodeWelcome",
    "NodeAttachAck",
    "AddressBind",
    "AddressUnbind",
    "CapabilityAdvertise",
    "CapabilityWithdraw",
    "NodeHeartbeat",
    "NodeHeartbeatAck",
    "CreditUpdate",
    "KeyAnnounce",
    "KeyRequest",
    "SecureOpen",
    "SecureAccept",
    "SecureClose",
)


@dataclass
class CompiledExpressionRule:
    """Compiled rule for efficient repeated evaluation."""

    # Rule identifier
    id: str
    # Optional description
    description: Optional[str]
    # Effect when rule matches
    effect: str  # 'allow' or 'deny'
    # Set of allowed actions. Contains '*' if wildcard.
    actions: set[RuleAction]
    # Set of allowed frame types (lowercase). If None, matches any.
    frame_types: Optional[set[str]] = None
    # Set of allowed origin types (lowercase). If None, matches any origin.
    origin_types: Optional[set[str]] = None
    # Address matchers (any-of). If None, matches any address.
    address_patterns: Optional[list[CompiledPattern]] = None
    # Compiled scope matcher. If None, no scope check.
    scope_matcher: Optional[Callable[[Sequence[str]], bool]] = None
    # Compiled when expression AST. If None, no when check.
    when_ast: Optional[AstNode] = None
    # Original when expression source (for tracing)
    when_source: Optional[str] = None
    # Parse error if when expression failed to compile
    when_parse_error: Optional[str] = None


def _extract_address(envelope: FameEnvelope) -> Optional[str]:
    """Extract the target address string from the envelope."""
    to = envelope.to
    if to is None:
        return None

    # FameAddress can be a string or object with __str__
    if isinstance(to, str):
        return to

    if hasattr(to, "__str__"):
        return str(to)

    return None


def _extract_granted_scopes(
    context: Optional[FameDeliveryContext],
) -> Sequence[str]:
    """Extract granted scopes from the authorization context."""
    if context is None:
        return []

    # Access security.authorization from context
    security = getattr(context, "security", None)
    if security is None:
        return []

    auth_context = getattr(security, "authorization", None)
    if auth_context is None:
        return []

    # Check grantedScopes first (snake_case for Python)
    granted = getattr(auth_context, "granted_scopes", None)
    if granted is None:
        granted = getattr(auth_context, "grantedScopes", None)
    if isinstance(granted, list | tuple):
        return list(granted)

    # Fall back to claims.scope if available
    claims = getattr(auth_context, "claims", None)
    if isinstance(claims, dict):
        # Try various scope claim names
        scope_claim = claims.get("scope") or claims.get("scopes") or claims.get("scp")

        if isinstance(scope_claim, str):
            # Space-separated scopes (OAuth2 convention)
            return [s for s in scope_claim.split() if s]

        if isinstance(scope_claim, list | tuple):
            return [s for s in scope_claim if isinstance(s, str)]

    return []


def _extract_claims(
    context: Optional[FameDeliveryContext],
) -> dict[str, ExprValue]:
    """Extract claims from the authorization context."""
    if context is None:
        return {}

    security = getattr(context, "security", None)
    if security is None:
        return {}

    auth_context = getattr(security, "authorization", None)
    if auth_context is None:
        return {}

    claims = getattr(auth_context, "claims", None)
    if claims is None:
        return {}

    if isinstance(claims, dict):
        return claims  # type: ignore

    return {}


def _create_envelope_bindings(
    envelope: FameEnvelope,
) -> tuple[dict[str, ExprValue], SecurityBindings]:
    """
    Create a safe envelope subset for expression bindings.

    Returns:
        A tuple of (bindings, security_bindings) where bindings is the envelope
        data for expression evaluation and security_bindings is the normalized
        security metadata for security builtins.
    """
    frame = getattr(envelope, "frame", None)
    frame_type: Optional[str] = None
    if frame is not None:
        frame_type = getattr(frame, "type", None)
        if frame_type is None and isinstance(frame, dict):
            frame_type = frame.get("type")

    envelope_id = getattr(envelope, "id", None)
    trace_id = getattr(envelope, "trace_id", None)
    if trace_id is None:
        trace_id = getattr(envelope, "traceId", None)
    corr_id = getattr(envelope, "corr_id", None)
    if corr_id is None:
        corr_id = getattr(envelope, "corrId", None)
    flow_id = getattr(envelope, "flow_id", None)
    if flow_id is None:
        flow_id = getattr(envelope, "flowId", None)

    # Extract sid (source identity hash)
    sid = getattr(envelope, "sid", None)

    # Extract sec header for security bindings
    sec = getattr(envelope, "sec", None)
    sec_dict: Optional[dict[str, Any]] = None
    if sec is not None:
        if isinstance(sec, dict):
            sec_dict = sec
        elif hasattr(sec, "__dict__"):
            sec_dict = {
                "sig": getattr(sec, "sig", None),
                "enc": getattr(sec, "enc", None),
            }
            # Convert sig/enc objects to dicts if needed
            if sec_dict["sig"] is not None and not isinstance(sec_dict["sig"], dict):
                sig_obj = sec_dict["sig"]
                sec_dict["sig"] = {
                    "alg": getattr(sig_obj, "alg", None),
                    "kid": getattr(sig_obj, "kid", None),
                }
            if sec_dict["enc"] is not None and not isinstance(sec_dict["enc"], dict):
                enc_obj = sec_dict["enc"]
                sec_dict["enc"] = {
                    "alg": getattr(enc_obj, "alg", None),
                    "kid": getattr(enc_obj, "kid", None),
                }

    # Create security bindings from sec header
    security_bindings = create_security_bindings(sec_dict)

    # Build sec object for envelope bindings (exposes metadata only, not val)
    sec_binding: dict[str, ExprValue] = {}
    if security_bindings["sig"]["present"]:
        sec_binding["sig"] = {
            "kid": security_bindings["sig"]["kid"],
        }
    if security_bindings["enc"]["present"]:
        sec_binding["enc"] = {
            "alg": security_bindings["enc"]["alg"],
            "kid": security_bindings["enc"]["kid"],
            "level": security_bindings["enc"]["level"],
        }

    bindings: dict[str, ExprValue] = {
        "id": envelope_id,
        "traceId": trace_id,
        "corrId": corr_id,
        "flowId": flow_id,
        "to": _extract_address(envelope),
        "frame": {"type": frame_type},
        "sid": sid,
        "sec": sec_binding if sec_binding else None,
    }

    return bindings, security_bindings


def _create_delivery_bindings(
    context: Optional[FameDeliveryContext],
    action: RuleAction,
) -> dict[str, ExprValue]:
    """Create delivery context bindings for expression evaluation."""
    origin_type: Optional[str] = None
    if context is not None:
        origin_type = getattr(context, "origin_type", None)
        if origin_type is None:
            origin_type = getattr(context, "originType", None)

    return {
        "origin_type": origin_type,
        "routing_action": action,
    }


def _create_node_bindings(node: NodeLike) -> dict[str, ExprValue]:
    """Create node context bindings for expression evaluation."""
    return {
        "id": getattr(node, "id", None),
        "sid": getattr(node, "sid", None),
        "provisionalId": getattr(node, "provisional_id", None) or getattr(
            node, "provisionalId", None
        ),
        "physicalPath": getattr(node, "physical_path", None) or getattr(
            node, "physicalPath", None
        ),
        "hasParent": getattr(node, "has_parent", None) or getattr(
            node, "hasParent", None
        ),
        "publicUrl": getattr(node, "public_url", None) or getattr(
            node, "publicUrl", None
        ),
    }


@dataclass
class AdvancedAuthorizationPolicyOptions:
    """Options for creating an AdvancedAuthorizationPolicy."""

    # The policy definition to evaluate
    policy_definition: AuthorizationPolicyDefinition
    # Whether to log warnings for unknown fields
    warn_on_unknown_fields: bool = True
    # Expression limits for parsing and evaluation
    expression_limits: Optional[ExpressionLimits] = None


class AdvancedAuthorizationPolicy(AuthorizationPolicy):
    """
    Expression-based authorization policy that evaluates rules with `when` expressions.

    Features:
    - All features of BasicAuthorizationPolicy
    - Expression evaluation for `when` clauses
    - Deterministic, side-effect-free evaluation
    - Missing fields evaluate to null (not error)
    - Parse/evaluation errors cause rule to not match
    """

    def __init__(self, options: AdvancedAuthorizationPolicyOptions):
        policy_definition = options.policy_definition
        warn_on_unknown_fields = options.warn_on_unknown_fields
        expression_limits = options.expression_limits or DEFAULT_EXPRESSION_LIMITS

        self._expression_limits = expression_limits

        # Validate and extract default effect
        self._default_effect: AuthorizationEffect = self._validate_default_effect(
            policy_definition.default_effect
        )

        # Warn about unknown policy fields
        if warn_on_unknown_fields:
            self._warn_unknown_policy_fields(policy_definition)

        # Compile rules for efficient evaluation
        self._compiled_rules = self._compile_rules(
            policy_definition.rules,
            warn_on_unknown_fields,
        )

        rules_with_when = sum(1 for r in self._compiled_rules if r.when_ast)
        logger.debug(
            "expression_policy_compiled",
            extra={
                "default_effect": self._default_effect,
                "rule_count": len(self._compiled_rules),
                "rules_with_when": rules_with_when,
            },
        )

    async def evaluate_request(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        action: Optional[RuleAction] = None,
    ) -> AuthorizationDecision:
        """
        Evaluate the policy against a request.

        Args:
            node: The node handling the request
            envelope: The FAME envelope being authorized
            context: Optional delivery context with authorization info, origin, etc.
            action: Optional authorization action token

        Returns:
            Authorization decision indicating allow/deny
        """
        resolved_action: RuleAction = action or "*"
        resolved_action_normalized = (
            self._normalize_action_token(resolved_action) or resolved_action
        )
        address = _extract_address(envelope)
        granted_scopes = _extract_granted_scopes(context)

        # Get frame type
        frame = getattr(envelope, "frame", None)
        raw_frame_type: Optional[str] = None
        if frame is not None:
            raw_frame_type = getattr(frame, "type", None)
            if raw_frame_type is None and isinstance(frame, dict):
                raw_frame_type = frame.get("type")

        frame_type_normalized: str = ""
        if isinstance(raw_frame_type, str) and raw_frame_type.strip():
            frame_type_normalized = raw_frame_type.strip().lower()

        # Get origin type
        raw_origin_type = getattr(context, "origin_type", None)
        if raw_origin_type is None and context is not None:
            raw_origin_type = getattr(context, "originType", None)

        origin_type_normalized: Optional[str] = None
        if isinstance(raw_origin_type, str):
            origin_type_normalized = self._normalize_origin_type_token(raw_origin_type)
        elif raw_origin_type is not None:
            # Handle enum types
            try:
                origin_type_normalized = self._normalize_origin_type_token(
                    str(raw_origin_type.value)
                    if hasattr(raw_origin_type, "value")
                    else str(raw_origin_type)
                )
            except Exception:
                origin_type_normalized = None

        # Lazy initialization of expression bindings and function registry
        expression_bindings: Optional[dict[str, ExprValue]] = None
        security_bindings: Optional[SecurityBindings] = None
        function_registry: Optional[FunctionRegistry] = None

        evaluation_trace: list[AuthorizationEvaluationStep] = []

        # Evaluate rules in order (first match wins)
        for rule in self._compiled_rules:
            step = AuthorizationEvaluationStep(rule_id=rule.id, result=False)

            # Check frame type match
            if rule.frame_types is not None:
                if not frame_type_normalized:
                    step.expression = "frame_type: missing"
                    step.result = False
                    evaluation_trace.append(step)
                    continue

                if frame_type_normalized not in rule.frame_types:
                    step.expression = (
                        f"frame_type: {raw_frame_type or 'unknown'} not in rule set"
                    )
                    step.result = False
                    evaluation_trace.append(step)
                    continue

            # Check origin type match
            if rule.origin_types is not None:
                if origin_type_normalized is None:
                    step.expression = "origin_type: missing (rule requires origin)"
                    step.result = False
                    evaluation_trace.append(step)
                    continue

                if origin_type_normalized not in rule.origin_types:
                    origin_types_str = ", ".join(rule.origin_types)
                    step.expression = (
                        f"origin_type: {raw_origin_type or 'unknown'} "
                        f"not in [{origin_types_str}]"
                    )
                    step.result = False
                    evaluation_trace.append(step)
                    continue

            # Check action match
            if "*" not in rule.actions and resolved_action_normalized not in rule.actions:
                actions_str = ", ".join(rule.actions)
                step.expression = (
                    f"action: {resolved_action_normalized} not in [{actions_str}]"
                )
                step.result = False
                evaluation_trace.append(step)
                continue

            # Check address match
            if rule.address_patterns is not None:
                if not address:
                    step.expression = (
                        "address: pattern requires address, but none provided"
                    )
                    step.result = False
                    evaluation_trace.append(step)
                    continue

                matched = any(p.match(address) for p in rule.address_patterns)
                if not matched:
                    patterns = ", ".join(p.source for p in rule.address_patterns)
                    step.expression = (
                        f"address: none of [{patterns}] matched {address}"
                    )
                    step.result = False
                    evaluation_trace.append(step)
                    continue

            # Check scope match
            if rule.scope_matcher is not None:
                if not rule.scope_matcher(granted_scopes):
                    step.expression = "scope: requirement not satisfied"
                    step.bound_values = {"grantedScopes": list(granted_scopes)}
                    step.result = False
                    evaluation_trace.append(step)
                    continue

            # Check when expression
            if rule.when_parse_error:
                # Parse error - rule does not match
                step.expression = f"when: parse error - {rule.when_parse_error}"
                step.result = False
                evaluation_trace.append(step)
                continue

            if rule.when_ast is not None:
                # Lazy initialization of expression bindings
                if expression_bindings is None:
                    now = datetime.now(timezone.utc)
                    envelope_bindings, security_bindings = _create_envelope_bindings(
                        envelope
                    )
                    expression_bindings = {
                        "claims": _extract_claims(context),
                        "envelope": envelope_bindings,
                        "delivery": _create_delivery_bindings(context, resolved_action),
                        "node": _create_node_bindings(node),
                        "time": {
                            "now_ms": int(time.time() * 1000),
                            "now_iso": now.isoformat().replace("+00:00", "Z"),
                        },
                    }

                if function_registry is None:
                    # security_bindings should be set when expression_bindings is set
                    # but provide a safe default in case of edge cases
                    sec_bindings_for_registry = security_bindings or {
                        "sig": {"present": False, "kid": None},
                        "enc": {
                            "present": False,
                            "alg": None,
                            "kid": None,
                            "level": "plaintext",
                        },
                    }
                    function_registry = create_auth_function_registry({
                        "granted_scopes": granted_scopes,
                        "security_bindings": sec_bindings_for_registry,
                    })

                eval_context = EvaluationContext(
                    bindings=expression_bindings,
                    limits=self._expression_limits,
                    source=rule.when_source,
                    functions=function_registry,
                )

                when_value, when_error = evaluate_as_boolean(rule.when_ast, eval_context)

                if when_error:
                    # Evaluation error - rule does not match
                    step.expression = f"when: evaluation error - {when_error}"
                    step.result = False
                    evaluation_trace.append(step)
                    continue

                if not when_value:
                    # Expression evaluated to false
                    step.expression = "when: expression evaluated to false"
                    step.bound_values = {"whenExpression": rule.when_source}
                    step.result = False
                    evaluation_trace.append(step)
                    continue

                # Expression evaluated to true
                step.expression = "when: expression evaluated to true"

            # Rule matched
            step.result = True
            if not step.expression:
                step.expression = "all conditions matched"
            step.bound_values = {
                "action": resolved_action,
                "address": address,
                "grantedScopes": list(granted_scopes),
            }
            if rule.when_source:
                step.bound_values["whenExpression"] = rule.when_source
            evaluation_trace.append(step)

            logger.debug(
                "rule_matched",
                extra={
                    "rule_id": rule.id,
                    "effect": rule.effect,
                    "action": resolved_action,
                    "address": address,
                    "had_when_clause": rule.when_ast is not None,
                },
            )

            return AuthorizationDecision(
                effect=rule.effect,  # type: ignore[arg-type]
                reason=rule.description or f"Matched rule: {rule.id}",
                matched_rule=rule.id,
                evaluation_trace=evaluation_trace,
            )

        # No rule matched, apply default effect
        logger.debug(
            "no_rule_matched",
            extra={
                "default_effect": self._default_effect,
                "action": resolved_action,
                "address": address,
            },
        )

        return AuthorizationDecision(
            effect=self._default_effect,
            reason=f"No rule matched, applying default effect: {self._default_effect}",
            evaluation_trace=evaluation_trace,
        )

    def _validate_default_effect(self, effect: Any) -> AuthorizationEffect:
        """Validate and return the default effect."""
        if effect is None:
            return "deny"
        if effect not in ("allow", "deny"):
            raise ValueError(
                f'Invalid default_effect: "{effect}". Must be "allow" or "deny"'
            )
        return effect  # type: ignore

    def _warn_unknown_policy_fields(
        self, definition: AuthorizationPolicyDefinition
    ) -> None:
        """Warn about unknown fields in the policy definition."""
        # Get all fields from the model
        known_fields = set(definition.model_fields.keys())
        # Add the constant known fields
        known_fields.update(KNOWN_POLICY_FIELDS)

        # Get all keys from the actual data
        if hasattr(definition, "model_extra") and definition.model_extra:
            for key in definition.model_extra.keys():
                if key not in KNOWN_POLICY_FIELDS:
                    logger.warning(
                        "unknown_policy_field",
                        extra={"field": key},
                    )

    def _compile_rules(
        self,
        rules: list[AuthorizationRuleDefinition],
        warn_on_unknown: bool,
    ) -> list[CompiledExpressionRule]:
        """Compile all rules."""
        return [
            self._compile_rule(rule, index, warn_on_unknown)
            for index, rule in enumerate(rules)
        ]

    def _compile_rule(
        self,
        rule: AuthorizationRuleDefinition,
        index: int,
        warn_on_unknown: bool,
    ) -> CompiledExpressionRule:
        """Compile a single rule."""
        rule_id = rule.id or f"rule_{index}"

        # Validate effect
        if rule.effect not in VALID_EFFECTS:
            raise ValueError(
                f'Invalid effect in rule "{rule_id}": "{rule.effect}". '
                'Must be "allow" or "deny"'
            )

        # Compile action(s)
        actions = self._compile_actions(rule.action, rule_id)

        # Compile address patterns
        address_patterns = self._compile_address(rule.address, rule_id)

        # Compile frame type gating
        frame_types = self._compile_frame_types(rule.frame_type, rule_id)

        # Compile origin type gating
        origin_types = self._compile_origin_types(rule.origin_type, rule_id)

        # Compile scope matcher
        scope_matcher: Optional[Callable[[Sequence[str]], bool]] = None
        if rule.scope is not None:
            try:
                compiled = compile_glob_only_scope_requirement(rule.scope, rule_id)
                scope_matcher = compiled.evaluate
            except Exception as e:
                raise ValueError(
                    f'Invalid scope requirement in rule "{rule_id}": {e}'
                ) from e

        # Compile when expression
        when_ast: Optional[AstNode] = None
        when_source: Optional[str] = None
        when_parse_error: Optional[str] = None

        if isinstance(rule.when, str) and rule.when.strip():
            when_source = rule.when.strip()
            try:
                when_ast = parse(when_source, self._expression_limits)
            except Exception as e:
                # Parse error - store for evaluation time
                when_parse_error = str(e)
                logger.warning(
                    "when_parse_error",
                    extra={
                        "rule_id": rule_id,
                        "expression": when_source,
                        "error": when_parse_error,
                    },
                )

        # Warn about unknown fields
        if warn_on_unknown:
            if hasattr(rule, "model_extra") and rule.model_extra:
                for key in rule.model_extra.keys():
                    if key not in KNOWN_RULE_FIELDS:
                        logger.warning(
                            "unknown_rule_field",
                            extra={"rule_id": rule_id, "field": key},
                        )

        return CompiledExpressionRule(
            id=rule_id,
            description=rule.description,
            effect=rule.effect,
            actions=actions,
            frame_types=frame_types,
            origin_types=origin_types,
            address_patterns=address_patterns,
            scope_matcher=scope_matcher,
            when_ast=when_ast,
            when_source=when_source,
            when_parse_error=when_parse_error,
        )

    def _compile_actions(
        self,
        action: Optional[RuleActionInput | list[RuleActionInput]],
        rule_id: str,
    ) -> set[RuleAction]:
        """Compile action specification into a set."""
        if action is None:
            return {"*"}

        if isinstance(action, str):
            normalized = self._normalize_action_token(action)
            if not normalized:
                raise ValueError(
                    f'Invalid action in rule "{rule_id}": "{action}". '
                    f"Must be one of: {', '.join(VALID_ACTIONS)}"
                )
            return {normalized}

        if not isinstance(action, list):
            raise ValueError(
                f'Invalid action in rule "{rule_id}": '
                "must be a string or array of strings"
            )

        if len(action) == 0:
            raise ValueError(
                f'Invalid action in rule "{rule_id}": array must not be empty'
            )

        actions: set[RuleAction] = set()
        for a in action:
            if not isinstance(a, str):
                raise ValueError(
                    f'Invalid action in rule "{rule_id}": '
                    "all values must be strings"
                )
            normalized = self._normalize_action_token(a)
            if not normalized:
                raise ValueError(
                    f'Invalid action in rule "{rule_id}": "{a}". '
                    f"Must be one of: {', '.join(VALID_ACTIONS)}"
                )
            actions.add(normalized)

        return actions

    def _compile_address(
        self,
        address: Optional[str | list[str]],
        rule_id: str,
    ) -> Optional[list[CompiledPattern]]:
        """Compile address patterns."""
        if address is None:
            return None

        context = f'address in rule "{rule_id}"'

        if isinstance(address, str):
            trimmed = address.strip()
            if not trimmed:
                raise ValueError(
                    f'Invalid address in rule "{rule_id}": value must not be empty'
                )
            try:
                return [compile_glob_pattern(trimmed, context)]
            except Exception as e:
                raise ValueError(
                    f'Invalid address in rule "{rule_id}": {e}'
                ) from e

        if not isinstance(address, list):
            raise ValueError(
                f'Invalid address in rule "{rule_id}": '
                "must be a string or array of strings"
            )

        if len(address) == 0:
            raise ValueError(
                f'Invalid address in rule "{rule_id}": array must not be empty'
            )

        patterns: list[CompiledPattern] = []
        for addr in address:
            if not isinstance(addr, str):
                raise ValueError(
                    f'Invalid address in rule "{rule_id}": '
                    "all values must be strings"
                )
            trimmed = addr.strip()
            if not trimmed:
                raise ValueError(
                    f'Invalid address in rule "{rule_id}": values must not be empty'
                )
            try:
                patterns.append(compile_glob_pattern(trimmed, context))
            except Exception as e:
                raise ValueError(
                    f'Invalid address in rule "{rule_id}": {e}'
                ) from e

        return patterns

    def _compile_frame_types(
        self,
        frame_type: Optional[str | list[str]],
        rule_id: str,
    ) -> Optional[set[str]]:
        """Compile frame type gating."""
        if frame_type is None:
            return None

        if isinstance(frame_type, str):
            trimmed = frame_type.strip()
            if not trimmed:
                raise ValueError(
                    f'Invalid frame_type in rule "{rule_id}": value must not be empty'
                )
            if trimmed not in VALID_FRAME_TYPES:
                raise ValueError(
                    f'Invalid frame_type in rule "{rule_id}": "{trimmed}". '
                    f"Must be one of: {', '.join(VALID_FRAME_TYPES)}"
                )
            return {trimmed.lower()}

        if not isinstance(frame_type, list):
            raise ValueError(
                f'Invalid frame_type in rule "{rule_id}": '
                "must be a string or array of strings"
            )

        if len(frame_type) == 0:
            raise ValueError(
                f'Invalid frame_type in rule "{rule_id}": array must not be empty'
            )

        types: set[str] = set()
        for ft in frame_type:
            if not isinstance(ft, str):
                raise ValueError(
                    f'Invalid frame_type in rule "{rule_id}": '
                    "all values must be strings"
                )
            trimmed = ft.strip()
            if not trimmed:
                raise ValueError(
                    f'Invalid frame_type in rule "{rule_id}": values must not be empty'
                )
            if trimmed not in VALID_FRAME_TYPES:
                raise ValueError(
                    f'Invalid frame_type in rule "{rule_id}": "{trimmed}". '
                    f"Must be one of: {', '.join(VALID_FRAME_TYPES)}"
                )
            types.add(trimmed.lower())

        return types

    def _compile_origin_types(
        self,
        origin_type: Optional[str | list[str]],
        rule_id: str,
    ) -> Optional[set[str]]:
        """Compile origin type gating."""
        if origin_type is None:
            return None

        if isinstance(origin_type, str):
            trimmed = origin_type.strip()
            if not trimmed:
                raise ValueError(
                    f'Invalid origin_type in rule "{rule_id}": value must not be empty'
                )
            normalized = self._normalize_origin_type_token(trimmed)
            if not normalized:
                raise ValueError(
                    f'Invalid origin_type in rule "{rule_id}": "{origin_type}". '
                    f"Must be one of: {', '.join(VALID_ORIGIN_TYPES)}"
                )
            return {normalized}

        if not isinstance(origin_type, list):
            raise ValueError(
                f'Invalid origin_type in rule "{rule_id}": '
                "must be a string or array of strings"
            )

        if len(origin_type) == 0:
            raise ValueError(
                f'Invalid origin_type in rule "{rule_id}": array must not be empty'
            )

        origin_types: set[str] = set()
        for ot in origin_type:
            if not isinstance(ot, str):
                raise ValueError(
                    f'Invalid origin_type in rule "{rule_id}": '
                    "all values must be strings"
                )
            trimmed = ot.strip()
            if not trimmed:
                raise ValueError(
                    f'Invalid origin_type in rule "{rule_id}": values must not be empty'
                )
            normalized = self._normalize_origin_type_token(trimmed)
            if not normalized:
                raise ValueError(
                    f'Invalid origin_type in rule "{rule_id}": "{ot}". '
                    f"Must be one of: {', '.join(VALID_ORIGIN_TYPES)}"
                )
            origin_types.add(normalized)

        return origin_types

    def _normalize_action_token(self, value: str) -> Optional[RuleAction]:
        """Normalize an action token to its canonical form."""
        trimmed = value.strip()
        if not trimmed:
            return None
        if trimmed == "*":
            return "*"
        # Normalize: remove whitespace, underscores, hyphens; lowercase
        import re

        normalized = re.sub(r"[\s_-]+", "", trimmed).lower()
        action_map: dict[str, RuleAction] = {
            "connect": "Connect",
            "forwardupstream": "ForwardUpstream",
            "forwarddownstream": "ForwardDownstream",
            "forwardpeer": "ForwardPeer",
            "deliverlocal": "DeliverLocal",
        }
        return action_map.get(normalized)

    def _normalize_origin_type_token(self, value: str) -> Optional[str]:
        """Normalize an origin type token to its canonical form."""
        trimmed = value.strip()
        if not trimmed:
            return None
        # Normalize: remove whitespace, underscores, hyphens; lowercase
        import re

        normalized = re.sub(r"[\s_-]+", "", trimmed).lower()
        origin_map: dict[str, str] = {
            "downstream": "downstream",
            "upstream": "upstream",
            "peer": "peer",
            "local": "local",
        }
        return origin_map.get(normalized)

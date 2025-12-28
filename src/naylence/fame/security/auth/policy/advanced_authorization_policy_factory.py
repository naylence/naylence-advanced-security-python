"""
Factory for creating AdvancedAuthorizationPolicy instances.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import ConfigDict, Field

from naylence.fame.expr.limits import ExpressionLimits
from naylence.fame.security.auth.policy.authorization_policy import (
    AuthorizationPolicy,
)
from naylence.fame.security.auth.policy.authorization_policy_definition import (
    AuthorizationPolicyDefinition,
)
from naylence.fame.security.auth.policy.authorization_policy_factory import (
    AUTHORIZATION_POLICY_FACTORY_BASE_TYPE,
    AuthorizationPolicyConfig,
    AuthorizationPolicyFactory,
)


class AdvancedAuthorizationPolicyConfig(AuthorizationPolicyConfig):
    """Configuration for creating an AdvancedAuthorizationPolicy via factory."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: str = "AdvancedAuthorizationPolicy"

    # The policy definition to evaluate - can be dict or Pydantic model
    policy_definition: AuthorizationPolicyDefinition | dict[str, Any] | None = Field(
        default=None, alias="policyDefinition"
    )

    # Whether to log warnings for unknown fields (default: True)
    warn_on_unknown_fields: bool = Field(
        default=True, alias="warnOnUnknownFields"
    )

    # Expression limits for the policy
    expression_limits: ExpressionLimits | dict[str, Any] | None = Field(
        default=None, alias="expressionLimits"
    )


# Factory metadata for registration
FACTORY_META = {
    "base": AUTHORIZATION_POLICY_FACTORY_BASE_TYPE,
    "key": "AdvancedAuthorizationPolicy",
}


def _normalize_config(
    config: AdvancedAuthorizationPolicyConfig | dict[str, Any] | None,
) -> dict[str, Any]:
    """Normalize configuration for AdvancedAuthorizationPolicy."""
    if config is None:
        raise ValueError(
            "AdvancedAuthorizationPolicyFactory requires a configuration "
            "with a policyDefinition"
        )

    if isinstance(config, AdvancedAuthorizationPolicyConfig):
        candidate = config.model_dump(by_alias=False)
    else:
        candidate = config

    # Support both snake_case and camelCase for policy_definition
    policy_definition = candidate.get("policy_definition") or candidate.get(
        "policyDefinition"
    )

    if not policy_definition:
        raise ValueError(
            "AdvancedAuthorizationPolicyConfig requires a policyDefinition object"
        )

    # policy_definition can be a dict or already an AuthorizationPolicyDefinition
    if not isinstance(policy_definition, dict | AuthorizationPolicyDefinition):
        raise ValueError(
            "AdvancedAuthorizationPolicyConfig requires a policyDefinition object"
        )

    # Support both snake_case and camelCase for warn_on_unknown_fields
    warn_on_unknown_fields = candidate.get(
        "warn_on_unknown_fields", candidate.get("warnOnUnknownFields")
    )

    if warn_on_unknown_fields is not None and not isinstance(
        warn_on_unknown_fields, bool
    ):
        raise ValueError("warnOnUnknownFields must be a boolean")

    # Support both snake_case and camelCase for expression_limits
    expression_limits = candidate.get(
        "expression_limits", candidate.get("expressionLimits")
    )

    return {
        "policy_definition": policy_definition,
        "warn_on_unknown_fields": (
            warn_on_unknown_fields if warn_on_unknown_fields is not None else True
        ),
        "expression_limits": expression_limits,
    }


class AdvancedAuthorizationPolicyFactory(
    AuthorizationPolicyFactory[AdvancedAuthorizationPolicyConfig]
):
    """Factory for creating AdvancedAuthorizationPolicy instances."""

    type: str = "AdvancedAuthorizationPolicy"

    async def create(
        self,
        config: AdvancedAuthorizationPolicyConfig | dict[str, Any] | None = None,
        **factory_args: Any,
    ) -> AuthorizationPolicy:
        """
        Create an AdvancedAuthorizationPolicy from the given configuration.

        Args:
            config: Configuration with policyDefinition

        Returns:
            The created authorization policy
        """
        normalized = _normalize_config(config)

        # Lazy import to avoid circular dependencies
        from .advanced_authorization_policy import (
            AdvancedAuthorizationPolicy,
            AdvancedAuthorizationPolicyOptions,
        )

        # Parse policy definition if it's a dict
        policy_def = normalized["policy_definition"]
        if isinstance(policy_def, dict):
            policy_def = AuthorizationPolicyDefinition.from_dict(policy_def)

        # Parse expression limits if provided
        expression_limits: Optional[ExpressionLimits] = None
        if normalized["expression_limits"]:
            expr_limits_data = normalized["expression_limits"]
            if isinstance(expr_limits_data, dict):
                from naylence.fame.expr.limits import DEFAULT_EXPRESSION_LIMITS

                expression_limits = ExpressionLimits(
                    max_expression_length=expr_limits_data.get(
                        "maxExpressionLength",
                        expr_limits_data.get(
                            "max_expression_length",
                            DEFAULT_EXPRESSION_LIMITS.max_expression_length,
                        ),
                    ),
                    max_ast_depth=expr_limits_data.get(
                        "maxAstDepth",
                        expr_limits_data.get(
                            "max_ast_depth",
                            DEFAULT_EXPRESSION_LIMITS.max_ast_depth,
                        ),
                    ),
                    max_ast_nodes=expr_limits_data.get(
                        "maxAstNodes",
                        expr_limits_data.get(
                            "max_ast_nodes",
                            DEFAULT_EXPRESSION_LIMITS.max_ast_nodes,
                        ),
                    ),
                    max_function_args=expr_limits_data.get(
                        "maxFunctionArgs",
                        expr_limits_data.get(
                            "max_function_args",
                            DEFAULT_EXPRESSION_LIMITS.max_function_args,
                        ),
                    ),
                    max_array_elements=expr_limits_data.get(
                        "maxArrayElements",
                        expr_limits_data.get(
                            "max_array_elements",
                            DEFAULT_EXPRESSION_LIMITS.max_array_elements,
                        ),
                    ),
                    max_member_access_depth=expr_limits_data.get(
                        "maxMemberAccessDepth",
                        expr_limits_data.get(
                            "max_member_access_depth",
                            DEFAULT_EXPRESSION_LIMITS.max_member_access_depth,
                        ),
                    ),
                    max_regex_pattern_length=expr_limits_data.get(
                        "maxRegexPatternLength",
                        expr_limits_data.get(
                            "max_regex_pattern_length",
                            DEFAULT_EXPRESSION_LIMITS.max_regex_pattern_length,
                        ),
                    ),
                    max_glob_pattern_length=expr_limits_data.get(
                        "maxGlobPatternLength",
                        expr_limits_data.get(
                            "max_glob_pattern_length",
                            DEFAULT_EXPRESSION_LIMITS.max_glob_pattern_length,
                        ),
                    ),
                )
            elif isinstance(expr_limits_data, ExpressionLimits):
                expression_limits = expr_limits_data

        options = AdvancedAuthorizationPolicyOptions(
            policy_definition=policy_def,
            warn_on_unknown_fields=normalized["warn_on_unknown_fields"],
            expression_limits=expression_limits,
        )

        return AdvancedAuthorizationPolicy(options)

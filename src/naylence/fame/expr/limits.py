"""
Resource limits for expression parsing and evaluation.

These limits protect against resource exhaustion attacks and
overly complex expressions.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ExpressionLimits:
    """Expression limits configuration."""

    # Maximum expression string length in characters
    max_expression_length: int = 4096

    # Maximum AST depth (nesting level)
    max_ast_depth: int = 32

    # Maximum number of AST nodes
    max_ast_nodes: int = 256

    # Maximum regex pattern length
    max_regex_pattern_length: int = 256

    # Maximum glob pattern length
    max_glob_pattern_length: int = 256

    # Maximum string literal length
    max_string_length: int = 1024

    # Maximum array literal length
    max_array_length: int = 64

    # Maximum function call arguments
    max_function_args: int = 16

    # Maximum member access chain depth
    max_member_access_depth: int = 16


# Default expression limits.
#
# These values are chosen to allow reasonable expressions while
# preventing resource exhaustion.
DEFAULT_EXPRESSION_LIMITS = ExpressionLimits()


def check_expression_length(
    expression: str, limits: Optional[ExpressionLimits] = None
) -> None:
    """Validates that expression length is within limits."""
    limits = limits or DEFAULT_EXPRESSION_LIMITS
    if len(expression) > limits.max_expression_length:
        raise ValueError(
            f"Expression length {len(expression)} exceeds limit of "
            f"{limits.max_expression_length}"
        )


def check_ast_depth(depth: int, limits: Optional[ExpressionLimits] = None) -> None:
    """Validates AST depth during parsing."""
    limits = limits or DEFAULT_EXPRESSION_LIMITS
    if depth > limits.max_ast_depth:
        raise ValueError(f"AST depth {depth} exceeds limit of {limits.max_ast_depth}")


def check_ast_node_count(
    count: int, limits: Optional[ExpressionLimits] = None
) -> None:
    """Validates AST node count during parsing."""
    limits = limits or DEFAULT_EXPRESSION_LIMITS
    if count > limits.max_ast_nodes:
        raise ValueError(
            f"AST node count {count} exceeds limit of {limits.max_ast_nodes}"
        )


def check_regex_pattern_length(
    pattern: str, limits: Optional[ExpressionLimits] = None
) -> None:
    """Validates regex pattern length before compilation."""
    limits = limits or DEFAULT_EXPRESSION_LIMITS
    if len(pattern) > limits.max_regex_pattern_length:
        raise ValueError(
            f"Regex pattern length {len(pattern)} exceeds limit of "
            f"{limits.max_regex_pattern_length}"
        )


def check_glob_pattern_length(
    pattern: str, limits: Optional[ExpressionLimits] = None
) -> None:
    """Validates glob pattern length before compilation."""
    limits = limits or DEFAULT_EXPRESSION_LIMITS
    if len(pattern) > limits.max_glob_pattern_length:
        raise ValueError(
            f"Glob pattern length {len(pattern)} exceeds limit of "
            f"{limits.max_glob_pattern_length}"
        )


def check_array_length(length: int, limits: Optional[ExpressionLimits] = None) -> None:
    """Validates array length during evaluation."""
    limits = limits or DEFAULT_EXPRESSION_LIMITS
    if length > limits.max_array_length:
        raise ValueError(
            f"Array length {length} exceeds limit of {limits.max_array_length}"
        )


def check_function_arg_count(
    count: int, limits: Optional[ExpressionLimits] = None
) -> None:
    """Validates function argument count."""
    limits = limits or DEFAULT_EXPRESSION_LIMITS
    if count > limits.max_function_args:
        raise ValueError(
            f"Function argument count {count} exceeds limit of "
            f"{limits.max_function_args}"
        )

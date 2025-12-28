"""
Authorization-specific expression built-ins.

Null handling semantics:
- Scope predicate builtins (has_scope, has_any_scope, has_all_scopes)
  return False when passed None for required args.
- Wrong non-null types still raise BuiltinError to surface real bugs.
"""

from typing import List, Optional, Sequence

from naylence.fame.expr.builtins import (
    BUILTIN_FUNCTIONS,
    BuiltinContext,
    ExprValue,
    FunctionRegistry,
    get_type_name,
)
from naylence.fame.expr.errors import BuiltinError


def _is_null(value: ExprValue) -> bool:
    """Checks if a value is null."""
    return value is None


def _get_arg(args: Sequence[ExprValue], index: int, function_name: str) -> ExprValue:
    """Gets an argument by index, throwing if not present."""
    if index >= len(args):
        raise BuiltinError(function_name, f"missing argument at index {index}")
    return args[index]


def _assert_arg_count(
    args: Sequence[ExprValue], expected: int, function_name: str
) -> None:
    """Asserts argument count."""
    if len(args) != expected:
        raise BuiltinError(
            function_name, f"expected {expected} argument(s), got {len(args)}"
        )


def _assert_string_or_null(
    value: ExprValue, arg_name: str, function_name: str
) -> Optional[str]:
    """
    Asserts that a non-null value is a string (for null-tolerant predicates).
    Returns None if the value is null (indicating predicate should return false).
    Throws BuiltinError if the value is non-null but not a string.
    """
    if _is_null(value):
        return None
    if not isinstance(value, str):
        raise BuiltinError(
            function_name, f"{arg_name} must be a string, got {get_type_name(value)}"
        )
    return value


def _assert_string_array_or_null(
    value: ExprValue, arg_name: str, function_name: str
) -> Optional[List[str]]:
    """
    Asserts that a non-null value is an array of strings (for null-tolerant predicates).
    Returns None if the value is null (indicating predicate should return false).
    Throws BuiltinError if the value is non-null but not a string array.
    """
    if _is_null(value):
        return None
    if not isinstance(value, list | tuple):
        raise BuiltinError(
            function_name,
            f"{arg_name} must be an array of strings, got {get_type_name(value)}",
        )
    result: List[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str):
            raise BuiltinError(
                function_name,
                f"{arg_name}[{i}] must be a string, got {get_type_name(item)}",
            )
        result.append(item)
    return result


def create_auth_function_registry(
    granted_scopes: Optional[Sequence[str]] = None,
) -> FunctionRegistry:
    """
    Creates a function registry with auth helpers installed.

    Args:
        granted_scopes: List of scopes granted to the current principal.

    Returns:
        A function registry including all built-in functions plus auth helpers.
    """
    scopes = list(granted_scopes) if granted_scopes else []

    def matches_scope(scope: str) -> bool:
        """Checks if any granted scope matches a pattern (exact match for now)."""
        return scope in scopes

    def has_scope(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
        """
        has_scope(scope: string) -> bool

        Returns True if the scope is in the granted scopes.
        Null-tolerant: returns False if scope is null.
        """
        _assert_arg_count(args, 1, "has_scope")
        scope = _get_arg(args, 0, "has_scope")
        # Null-tolerant: return False if scope is null
        scope_str = _assert_string_or_null(scope, "scope", "has_scope")
        if scope_str is None:
            return False
        return matches_scope(scope_str)

    def has_any_scope(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
        """
        has_any_scope(scopes: string[]) -> bool

        Returns True if any scope in the array is in the granted scopes.
        Null-tolerant: returns False if scopes is null.
        """
        _assert_arg_count(args, 1, "has_any_scope")
        values = _get_arg(args, 0, "has_any_scope")
        # Null-tolerant: return False if scopes is null
        values_list = _assert_string_array_or_null(values, "scopes", "has_any_scope")
        if values_list is None:
            return False
        if len(values_list) == 0:
            return False
        return any(matches_scope(scope) for scope in values_list)

    def has_all_scopes(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
        """
        has_all_scopes(scopes: string[]) -> bool

        Returns True if all scopes in the array are in the granted scopes.
        Null-tolerant: returns False if scopes is null.
        """
        _assert_arg_count(args, 1, "has_all_scopes")
        values = _get_arg(args, 0, "has_all_scopes")
        # Null-tolerant: return False if scopes is null
        values_list = _assert_string_array_or_null(values, "scopes", "has_all_scopes")
        if values_list is None:
            return False
        if len(values_list) == 0:
            return True
        return all(matches_scope(scope) for scope in values_list)

    # Create new registry with all built-in functions plus auth helpers
    registry: FunctionRegistry = {
        **BUILTIN_FUNCTIONS,
        "has_scope": has_scope,
        "has_any_scope": has_any_scope,
        "has_all_scopes": has_all_scopes,
    }

    return registry

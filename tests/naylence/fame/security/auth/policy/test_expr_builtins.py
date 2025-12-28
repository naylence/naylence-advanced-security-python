"""
Tests for authorization-specific expression built-ins.
"""

import pytest

from naylence.fame.expr import (
    EvaluationContext,
    ExprValue,
    evaluate,
    evaluate_as_boolean,
    parse,
)
from naylence.fame.security.auth.policy.expr_builtins import (
    create_auth_function_registry,
)


def eval_bool(
    expression: str,
    bindings: dict[str, ExprValue] = None,
    granted_scopes: list[str] = None,
) -> bool:
    """Helper to evaluate an expression as boolean and return the value."""
    bindings = bindings or {}
    granted_scopes = granted_scopes or []
    ast = parse(expression)
    context = EvaluationContext(
        bindings=bindings,
        source=expression,
        functions=create_auth_function_registry(granted_scopes),
    )
    value, error = evaluate_as_boolean(ast, context)
    if error:
        raise RuntimeError(error)
    return value


def eval_bool_result(
    expression: str,
    bindings: dict[str, ExprValue] = None,
    granted_scopes: list[str] = None,
) -> tuple[bool, str | None]:
    """Helper to evaluate an expression as boolean and return (value, error)."""
    bindings = bindings or {}
    granted_scopes = granted_scopes or []
    ast = parse(expression)
    context = EvaluationContext(
        bindings=bindings,
        source=expression,
        functions=create_auth_function_registry(granted_scopes),
    )
    return evaluate_as_boolean(ast, context)


def eval_expr(
    expression: str,
    bindings: dict[str, ExprValue] = None,
    granted_scopes: list[str] = None,
) -> ExprValue:
    """Helper to evaluate an expression and return the value."""
    bindings = bindings or {}
    granted_scopes = granted_scopes or []
    ast = parse(expression)
    context = EvaluationContext(
        bindings=bindings,
        source=expression,
        functions=create_auth_function_registry(granted_scopes),
    )
    result = evaluate(ast, context)
    if not result.success:
        raise RuntimeError(result.error)
    return result.value


class TestHasScope:
    """Tests for has_scope builtin."""

    def test_returns_true_for_granted_scope(self):
        assert eval_bool('has_scope("admin")', {}, ["admin", "write"]) is True

    def test_returns_false_for_missing_scope(self):
        assert eval_bool('has_scope("admin")', {}, ["read"]) is False

    def test_returns_false_for_empty_granted_scopes(self):
        assert eval_bool('has_scope("admin")', {}, []) is False


class TestHasAnyScope:
    """Tests for has_any_scope builtin."""

    def test_returns_true_if_any_scope_is_granted(self):
        result = eval_bool('has_any_scope(["admin", "write"])', {}, ["write"])
        assert result is True

    def test_returns_false_if_no_scope_is_granted(self):
        result = eval_bool('has_any_scope(["admin", "write"])', {}, ["read"])
        assert result is False

    def test_returns_false_for_empty_input_array(self):
        assert eval_bool("has_any_scope([])", {}, ["admin"]) is False


class TestHasAllScopes:
    """Tests for has_all_scopes builtin."""

    def test_returns_true_if_all_scopes_are_granted(self):
        result = eval_bool(
            'has_all_scopes(["read", "write"])',
            {},
            ["read", "write", "admin"],
        )
        assert result is True

    def test_returns_false_if_not_all_scopes_are_granted(self):
        result = eval_bool('has_all_scopes(["read", "write"])', {}, ["read"])
        assert result is False

    def test_returns_true_for_empty_input_array(self):
        # Vacuously true
        assert eval_bool("has_all_scopes([])", {}, ["admin"]) is True


class TestHasScopeWithNull:
    """Tests for has_scope with null values."""

    def test_returns_false_when_scope_arg_is_null(self):
        assert eval_expr("has_scope(null)", {}, ["admin"]) is False

    def test_returns_false_when_scope_arg_is_missing_property(self):
        assert eval_expr("has_scope(obj.missing)", {"obj": {}}, ["admin"]) is False

    def test_throws_for_wrong_type_number(self):
        with pytest.raises(RuntimeError, match="string"):
            eval_expr("has_scope(42)", {}, [])

    def test_throws_for_wrong_type_array(self):
        with pytest.raises(RuntimeError, match="string"):
            eval_expr("has_scope(arr)", {"arr": []}, [])


class TestHasAnyScopeWithNull:
    """Tests for has_any_scope with null values."""

    def test_returns_false_when_scopes_arg_is_null(self):
        assert eval_expr("has_any_scope(null)", {}, ["admin"]) is False

    def test_returns_false_when_scopes_arg_is_missing_property(self):
        assert eval_expr("has_any_scope(obj.missing)", {"obj": {}}, ["admin"]) is False

    def test_throws_for_wrong_type_string(self):
        with pytest.raises(RuntimeError, match="array"):
            eval_expr('has_any_scope("admin")', {}, [])

    def test_throws_for_wrong_type_number(self):
        with pytest.raises(RuntimeError, match="array"):
            eval_expr("has_any_scope(123)", {}, [])


class TestHasAllScopesWithNull:
    """Tests for has_all_scopes with null values."""

    def test_returns_false_when_scopes_arg_is_null(self):
        assert eval_expr("has_all_scopes(null)", {}, ["admin"]) is False

    def test_returns_false_when_scopes_arg_is_missing_property(self):
        assert eval_expr("has_all_scopes(obj.missing)", {"obj": {}}, ["admin"]) is False

    def test_throws_for_wrong_type_object(self):
        with pytest.raises(RuntimeError, match="array"):
            eval_expr("has_all_scopes(obj)", {"obj": {}}, [])

    def test_throws_for_array_containing_non_strings(self):
        with pytest.raises(RuntimeError, match="string"):
            eval_expr("has_all_scopes(arr)", {"arr": ["valid", 123]}, [])


class TestAuthBuiltinsEvaluateAsBooleanBehavior:
    """Tests for auth builtins with evaluate_as_boolean behavior."""

    def test_returns_value_false_with_no_error_for_null_scope(self):
        value, error = eval_bool_result("has_scope(null)", {}, ["admin"])
        assert value is False
        assert error is None

    def test_returns_value_false_with_no_error_for_null_scopes_array(self):
        value, error = eval_bool_result("has_any_scope(null)", {}, ["admin"])
        assert value is False
        assert error is None

    def test_returns_value_false_with_error_for_wrong_type(self):
        value, error = eval_bool_result("has_scope(42)", {}, [])
        assert value is False
        assert error is not None
        assert "string" in error

    def test_returns_value_true_with_no_error_for_valid_scope_match(self):
        value, error = eval_bool_result('has_scope("admin")', {}, ["admin"])
        assert value is True
        assert error is None

    def test_handles_complex_expression_with_null_scope_propagation(self):
        value, error = eval_bool_result(
            'has_scope(claims.requiredScope) && has_any_scope(["admin"])',
            {"claims": {"requiredScope": None}},
            ["admin"],
        )
        # has_scope returns False due to null, && short-circuits
        assert value is False
        assert error is None


class TestParameterizedAuthBuiltinNullTolerance:
    """Parameterized tests for auth builtin null tolerance."""

    @pytest.mark.parametrize(
        "expr,bindings,scopes,expected_value,should_error",
        [
            ("has_scope(null)", {}, ["admin"], False, False),
            ("has_scope(x)", {"x": None}, ["admin"], False, False),
            ("has_scope(x.y)", {"x": {}}, ["admin"], False, False),
            ("has_scope(42)", {}, [], False, True),
            ('has_scope("admin")', {}, ["admin"], True, False),
            ('has_scope("admin")', {}, ["read"], False, False),
            ("has_any_scope(null)", {}, ["admin"], False, False),
            ("has_any_scope(x)", {"x": None}, ["admin"], False, False),
            ('has_any_scope("str")', {}, [], False, True),
            ('has_any_scope(["admin"])', {}, ["admin"], True, False),
            ('has_any_scope(["admin"])', {}, ["read"], False, False),
            ("has_all_scopes(null)", {}, ["admin"], False, False),
            ("has_all_scopes(x)", {"x": None}, ["admin"], False, False),
            ("has_all_scopes(123)", {}, [], False, True),
            ('has_all_scopes(["a", "b"])', {}, ["a", "b", "c"], True, False),
            ('has_all_scopes(["a", "b"])', {}, ["a"], False, False),
        ],
    )
    def test_auth_predicate(self, expr, bindings, scopes, expected_value, should_error):
        value, error = eval_bool_result(expr, bindings, scopes)
        assert value == expected_value
        if should_error:
            assert error is not None
        else:
            assert error is None

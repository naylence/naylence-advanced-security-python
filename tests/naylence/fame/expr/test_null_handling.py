"""
Tests for null handling in the expression engine.

This test suite verifies:
1. Value resolution: None is the canonical null value
2. Predicate builtins are null-tolerant: return False for None args
3. Wrong types still throw BuiltinError
4. evaluate_as_boolean behavior with null-tolerant predicates
"""

import pytest

from naylence.fame.expr import (
    EvaluationContext,
    ExprValue,
    evaluate,
    evaluate_as_boolean,
    normalize_js_value,
    parse,
)


def eval_expr(
    expression: str,
    bindings: dict[str, ExprValue] | None = None,
) -> ExprValue:
    """Helper to evaluate an expression and return the value."""
    bindings = bindings or {}
    ast = parse(expression)
    context = EvaluationContext(
        bindings=bindings,
        source=expression,
    )
    result = evaluate(ast, context)
    if not result.success:
        raise RuntimeError(result.error)
    return result.value


def eval_bool_result(
    expression: str,
    bindings: dict[str, ExprValue] | None = None,
) -> tuple[bool, str | None]:
    """Helper to evaluate an expression as boolean and return (value, error)."""
    bindings = bindings or {}
    ast = parse(expression)
    context = EvaluationContext(
        bindings=bindings,
        source=expression,
    )
    return evaluate_as_boolean(ast, context)


class TestNormalizeJsValue:
    """Tests for normalize_js_value function."""

    def test_normalizes_none_to_none(self):
        assert normalize_js_value(None) is None

    def test_preserves_booleans(self):
        assert normalize_js_value(True) is True
        assert normalize_js_value(False) is False

    def test_preserves_numbers(self):
        assert normalize_js_value(42) == 42
        assert normalize_js_value(3.14) == 3.14
        assert normalize_js_value(0) == 0
        assert normalize_js_value(-1) == -1

    def test_preserves_strings(self):
        assert normalize_js_value("hello") == "hello"
        assert normalize_js_value("") == ""

    def test_normalizes_list_elements(self):
        input_list = [1, None, "test", None]
        expected = [1, None, "test", None]
        assert normalize_js_value(input_list) == expected

    def test_normalizes_nested_list_elements(self):
        input_list = [[None, 1], [2, None]]
        expected = [[None, 1], [2, None]]
        assert normalize_js_value(input_list) == expected

    def test_preserves_dicts(self):
        input_dict = {"a": 1, "b": None}
        result = normalize_js_value(input_dict)
        assert result is input_dict  # Same reference

    def test_converts_functions_to_none(self):
        def func():
            pass
        assert normalize_js_value(func) is None


class TestValueResolutionIdentifierBinding:
    """Tests for identifier binding lookup with null normalization."""

    def test_returns_none_for_missing_binding(self):
        assert eval_expr("unknown") is None

    def test_returns_value_for_present_binding(self):
        assert eval_expr("x", {"x": 42}) == 42

    def test_normalizes_none_binding_value(self):
        assert eval_expr("x", {"x": None}) is None


class TestValueResolutionMemberAccess:
    """Tests for member access with null normalization."""

    def test_returns_none_for_none_base_object(self):
        assert eval_expr("x.prop", {"x": None}) is None

    def test_returns_none_for_missing_property(self):
        assert eval_expr("obj.missing", {"obj": {}}) is None

    def test_returns_value_for_present_property(self):
        assert eval_expr("obj.prop", {"obj": {"prop": "value"}}) == "value"

    def test_returns_none_for_non_object_base_primitive(self):
        assert eval_expr("x.prop", {"x": "string"}) is None

    def test_returns_none_for_non_object_base_array(self):
        assert eval_expr("x.prop", {"x": [1, 2, 3]}) is None


class TestValueResolutionNestedMemberAccess:
    """Tests for nested member access with null normalization."""

    def test_returns_none_for_deeply_nested_missing_property(self):
        assert eval_expr("a.b.c.d", {"a": {}}) is None

    def test_returns_none_when_intermediate_is_none(self):
        assert eval_expr("a.b.c", {"a": {"b": None}}) is None

    def test_returns_value_for_deeply_nested_present_property(self):
        assert eval_expr("a.b.c", {"a": {"b": {"c": "deep"}}}) == "deep"


class TestValueResolutionIndexAccess:
    """Tests for index access with null normalization."""

    def test_returns_none_for_none_base(self):
        assert eval_expr("x[0]", {"x": None}) is None

    def test_returns_none_for_out_of_bounds_index(self):
        assert eval_expr("arr[10]", {"arr": [1, 2, 3]}) is None

    def test_returns_none_for_negative_index(self):
        assert eval_expr("arr[-1]", {"arr": [1, 2, 3]}) is None

    def test_returns_value_for_valid_array_index(self):
        assert eval_expr("arr[1]", {"arr": ["a", "b", "c"]}) == "b"

    def test_returns_none_for_missing_object_key(self):
        assert eval_expr('obj["missing"]', {"obj": {}}) is None

    def test_returns_value_for_present_object_key(self):
        assert eval_expr('obj["key"]', {"obj": {"key": "value"}}) == "value"


class TestNullTolerantPredicates:
    """Tests for null-tolerant predicate builtins."""

    def test_starts_with_returns_false_for_none_subject(self):
        assert eval_expr('starts_with(null, "x")') is False

    def test_starts_with_returns_false_for_none_prefix(self):
        assert eval_expr('starts_with("hello", null)') is False

    def test_ends_with_returns_false_for_none_subject(self):
        assert eval_expr('ends_with(null, "x")') is False

    def test_ends_with_returns_false_for_none_suffix(self):
        assert eval_expr('ends_with("hello", null)') is False

    def test_contains_returns_false_for_none_subject(self):
        assert eval_expr('contains(null, "x")') is False

    def test_contains_returns_false_for_none_substring(self):
        assert eval_expr('contains("hello", null)') is False

    def test_glob_match_returns_false_for_none_value(self):
        assert eval_expr('glob_match(null, "*.txt")') is False

    def test_glob_match_returns_false_for_none_pattern(self):
        assert eval_expr('glob_match("file.txt", null)') is False

    def test_regex_match_returns_false_for_none_value(self):
        assert eval_expr('regex_match(null, "[a-z]+")') is False

    def test_regex_match_returns_false_for_none_pattern(self):
        assert eval_expr('regex_match("hello", null)') is False

    def test_predicates_throw_for_wrong_types(self):
        with pytest.raises(RuntimeError, match="string"):
            eval_expr("starts_with(123, \"x\")")

        with pytest.raises(RuntimeError, match="string"):
            eval_expr("ends_with(123, \"x\")")

        with pytest.raises(RuntimeError, match="string"):
            eval_expr("contains(123, \"x\")")


class TestNullFriendlyBuiltins:
    """Tests for null-friendly non-predicate builtins."""

    def test_trim_returns_empty_for_none(self):
        assert eval_expr("trim(null)") == ""

    def test_secure_hash_returns_empty_for_none(self):
        assert eval_expr("secure_hash(null, 8)") == ""

    def test_trim_throws_for_wrong_type(self):
        with pytest.raises(RuntimeError, match="string"):
            eval_expr("trim(123)")


class TestEvaluateAsBooleanWithNullPredicates:
    """Tests for evaluate_as_boolean with null-tolerant predicates."""

    def test_returns_false_for_null_safe_predicate(self):
        value, error = eval_bool_result('starts_with(null, "x")')
        assert error is None
        assert value is False

    def test_returns_true_for_matching_predicate(self):
        value, error = eval_bool_result('starts_with("hello", "hel")')
        assert error is None
        assert value is True

    def test_works_with_missing_binding(self):
        value, error = eval_bool_result('starts_with(missing, "x")', {})
        assert error is None
        assert value is False

    def test_works_with_missing_property(self):
        value, error = eval_bool_result('starts_with(obj.name, "x")', {"obj": {}})
        assert error is None
        assert value is False

    def test_returns_error_for_type_error(self):
        value, error = eval_bool_result('starts_with(123, "x")')
        assert error is not None
        assert "string" in error
        assert value is False


class TestComplexNullScenarios:
    """Tests for complex null handling scenarios."""

    def test_coalesce_with_null_and_predicate(self):
        result = eval_expr(
            'starts_with(coalesce(name, "default"), "def")',
            {"name": None}
        )
        assert result is True

    def test_exists_check_with_null_property(self):
        assert eval_expr('exists(obj.prop)', {"obj": {"prop": None}}) is False
        assert eval_expr('exists(obj.prop)', {"obj": {"prop": ""}}) is True

    def test_ternary_with_null_check(self):
        result = eval_expr(
            'exists(name) ? starts_with(name, "a") : false',
            {"name": None}
        )
        assert result is False

        result = eval_expr(
            'exists(name) ? starts_with(name, "a") : false',
            {"name": "alice"}
        )
        assert result is True

    def test_null_safe_chain_with_coalesce(self):
        result = eval_expr(
            'len(coalesce(items, []))',
            {"items": None}
        )
        assert result == 0

        result = eval_expr(
            'len(coalesce(items, []))',
            {"items": [1, 2, 3]}
        )
        assert result == 3

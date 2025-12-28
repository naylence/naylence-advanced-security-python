"""
Tests for expression evaluator.

Ported from TypeScript test suite.
"""

# pyright: reportArgumentType=false

import pytest

from naylence.fame.expr import (
    EvaluationContext,
    ExprValue,
    FunctionRegistry,
    evaluate,
    evaluate_as_boolean,
    parse,
)


def eval_expr(
    expression: str,
    bindings: dict[str, ExprValue] | None = None,
    functions: FunctionRegistry | None = None,
) -> ExprValue:
    """Helper to evaluate an expression and return the value."""
    bindings = bindings or {}
    ast = parse(expression)
    context = EvaluationContext(
        bindings=bindings,
        source=expression,
        functions=functions,
    )
    result = evaluate(ast, context)
    if not result.success:
        raise RuntimeError(result.error)
    return result.value


def eval_bool(
    expression: str,
    bindings: dict[str, ExprValue] | None = None,
    functions: FunctionRegistry | None = None,
) -> bool:
    """Helper to evaluate an expression as boolean."""
    bindings = bindings or {}
    ast = parse(expression)
    context = EvaluationContext(
        bindings=bindings,
        source=expression,
        functions=functions,
    )
    value, error = evaluate_as_boolean(ast, context)
    if error:
        raise RuntimeError(error)
    return value


class TestLiterals:
    """Tests for literal evaluation."""

    def test_evaluates_string_literal(self):
        assert eval_expr('"hello"') == "hello"

    def test_evaluates_number_literal(self):
        assert eval_expr("42") == 42

    def test_evaluates_decimal_literal(self):
        assert eval_expr("3.14") == pytest.approx(3.14)

    def test_evaluates_true(self):
        assert eval_expr("true") is True

    def test_evaluates_false(self):
        assert eval_expr("false") is False

    def test_evaluates_null(self):
        assert eval_expr("null") is None

    def test_evaluates_empty_array(self):
        assert eval_expr("[]") == []

    def test_evaluates_array_with_elements(self):
        assert eval_expr("[1, 2, 3]") == [1, 2, 3]


class TestIdentifiers:
    """Tests for identifier evaluation."""

    def test_evaluates_bound_identifier(self):
        assert eval_expr("x", {"x": 42}) == 42

    def test_evaluates_unbound_identifier_as_null(self):
        assert eval_expr("unknown") is None


class TestMemberAccess:
    """Tests for member access evaluation."""

    def test_accesses_object_property(self):
        assert eval_expr("obj.prop", {"obj": {"prop": "value"}}) == "value"

    def test_accesses_nested_property(self):
        bindings = {"a": {"b": {"c": 123}}}
        assert eval_expr("a.b.c", bindings) == 123

    def test_returns_null_for_missing_property(self):
        assert eval_expr("obj.missing", {"obj": {}}) is None

    def test_returns_null_for_null_object(self):
        assert eval_expr("x.prop", {"x": None}) is None

    def test_returns_null_for_primitive(self):
        assert eval_expr("x.prop", {"x": "string"}) is None


class TestIndexAccess:
    """Tests for index access evaluation."""

    def test_accesses_array_by_index(self):
        assert eval_expr("arr[1]", {"arr": ["a", "b", "c"]}) == "b"

    def test_accesses_object_by_string_key(self):
        assert eval_expr('obj["key"]', {"obj": {"key": "value"}}) == "value"

    def test_returns_null_for_out_of_bounds(self):
        assert eval_expr("arr[10]", {"arr": [1, 2, 3]}) is None

    def test_returns_null_for_negative_index(self):
        assert eval_expr("arr[-1]", {"arr": [1, 2, 3]}) is None

    def test_returns_null_for_missing_key(self):
        assert eval_expr('obj["missing"]', {"obj": {}}) is None

    def test_returns_null_for_null_object(self):
        assert eval_expr("x[0]", {"x": None}) is None


class TestUnaryOperators:
    """Tests for unary operator evaluation."""

    def test_negates_boolean_with_not(self):
        assert eval_expr("!true") is False
        assert eval_expr("!false") is True

    def test_negates_number_with_minus(self):
        assert eval_expr("-5") == -5
        assert eval_expr("--5") == 5

    def test_throws_on_not_with_non_boolean(self):
        with pytest.raises(RuntimeError, match="boolean"):
            eval_expr("!5")

    def test_throws_on_minus_with_non_number(self):
        with pytest.raises(RuntimeError, match="number"):
            eval_expr('-"str"')


class TestArithmeticOperators:
    """Tests for arithmetic operator evaluation."""

    def test_adds_numbers(self):
        assert eval_expr("2 + 3") == 5

    def test_concatenates_strings(self):
        assert eval_expr('"a" + "b"') == "ab"

    def test_subtracts_numbers(self):
        assert eval_expr("5 - 3") == 2

    def test_multiplies_numbers(self):
        assert eval_expr("4 * 5") == 20

    def test_divides_numbers(self):
        assert eval_expr("10 / 4") == 2.5

    def test_computes_modulo(self):
        assert eval_expr("10 % 3") == 1

    def test_throws_on_division_by_zero(self):
        with pytest.raises(RuntimeError, match="zero"):
            eval_expr("5 / 0")

    def test_throws_on_modulo_by_zero(self):
        with pytest.raises(RuntimeError, match="zero"):
            eval_expr("5 % 0")


class TestComparisonOperators:
    """Tests for comparison operator evaluation."""

    def test_less_than(self):
        assert eval_expr("1 < 2") is True
        assert eval_expr("2 < 1") is False
        assert eval_expr("1 < 1") is False

    def test_less_than_or_equal(self):
        assert eval_expr("1 <= 2") is True
        assert eval_expr("1 <= 1") is True
        assert eval_expr("2 <= 1") is False

    def test_greater_than(self):
        assert eval_expr("2 > 1") is True
        assert eval_expr("1 > 2") is False
        assert eval_expr("1 > 1") is False

    def test_greater_than_or_equal(self):
        assert eval_expr("2 >= 1") is True
        assert eval_expr("1 >= 1") is True
        assert eval_expr("1 >= 2") is False

    def test_string_comparison(self):
        assert eval_expr('"a" < "b"') is True
        assert eval_expr('"b" < "a"') is False

    def test_equality(self):
        assert eval_expr("1 == 1") is True
        assert eval_expr("1 == 2") is False
        assert eval_expr('"a" == "a"') is True
        assert eval_expr("true == true") is True

    def test_inequality(self):
        assert eval_expr("1 != 2") is True
        assert eval_expr("1 != 1") is False


class TestLogicalOperators:
    """Tests for logical operator evaluation."""

    def test_logical_and(self):
        assert eval_expr("true && true") is True
        assert eval_expr("true && false") is False
        assert eval_expr("false && true") is False
        assert eval_expr("false && false") is False

    def test_logical_or(self):
        assert eval_expr("true || true") is True
        assert eval_expr("true || false") is True
        assert eval_expr("false || true") is True
        assert eval_expr("false || false") is False

    def test_short_circuit_and(self):
        # Should not evaluate right side if left is false
        assert eval_expr("false && undefined.prop") is False

    def test_short_circuit_or(self):
        # Should not evaluate right side if left is true
        assert eval_expr("true || undefined.prop") is True


class TestMembershipOperators:
    """Tests for membership operator evaluation."""

    def test_in_array(self):
        assert eval_expr("1 in [1, 2, 3]") is True
        assert eval_expr("4 in [1, 2, 3]") is False

    def test_in_string(self):
        assert eval_expr('"el" in "hello"') is True
        assert eval_expr('"xy" in "hello"') is False

    def test_not_in_array(self):
        assert eval_expr("4 not in [1, 2, 3]") is True
        assert eval_expr("1 not in [1, 2, 3]") is False

    def test_in_object_keys(self):
        # Object literals aren't supported, use bindings instead
        assert eval_expr('"key" in obj', {"obj": {"key": "value"}}) is True
        assert eval_expr('"missing" in obj', {"obj": {"key": "value"}}) is False


class TestTernaryOperator:
    """Tests for ternary operator evaluation."""

    def test_returns_consequent_when_true(self):
        assert eval_expr('true ? "yes" : "no"') == "yes"

    def test_returns_alternate_when_false(self):
        assert eval_expr('false ? "yes" : "no"') == "no"

    def test_evaluates_with_complex_condition(self):
        assert eval_expr('1 < 2 ? "less" : "greater"') == "less"


class TestBuiltinFunctions:
    """Tests for built-in function evaluation."""

    def test_lower(self):
        assert eval_expr('lower("HELLO")') == "hello"

    def test_upper(self):
        assert eval_expr('upper("hello")') == "HELLO"

    def test_starts_with(self):
        assert eval_expr('starts_with("hello", "hel")') is True
        assert eval_expr('starts_with("hello", "bye")') is False

    def test_ends_with(self):
        assert eval_expr('ends_with("hello", "llo")') is True
        assert eval_expr('ends_with("hello", "bye")') is False

    def test_contains(self):
        assert eval_expr('contains("hello", "ell")') is True
        assert eval_expr('contains("hello", "xyz")') is False

    def test_trim(self):
        assert eval_expr('trim("  hello  ")') == "hello"

    def test_len_string(self):
        assert eval_expr('len("hello")') == 5

    def test_len_array(self):
        assert eval_expr("len([1, 2, 3])") == 3

    def test_exists(self):
        assert eval_expr("exists(x)", {"x": "value"}) is True
        assert eval_expr("exists(missing)") is False

    def test_coalesce(self):
        assert eval_expr('coalesce(null, "default")') == "default"
        assert eval_expr('coalesce("value", "default")') == "value"

    def test_split(self):
        assert eval_expr('split("a,b,c", ",")') == ["a", "b", "c"]

    def test_glob_match(self):
        assert eval_expr('glob_match("foo.bar", "foo.*")') is True
        assert eval_expr('glob_match("foo.bar", "baz.*")') is False

    def test_regex_match(self):
        assert eval_expr('regex_match("hello123", "[a-z]+[0-9]+")') is True
        assert eval_expr('regex_match("hello", "[0-9]+")') is False


class TestNullHandling:
    """Tests for null handling in evaluation."""

    def test_null_equality(self):
        assert eval_expr("null == null") is True
        assert eval_expr("null != null") is False

    def test_null_safe_member_access(self):
        assert eval_expr("x.y.z", {"x": None}) is None

    def test_predicate_functions_return_false_for_null(self):
        assert eval_expr("starts_with(null, \"x\")") is False
        assert eval_expr("ends_with(null, \"x\")") is False
        assert eval_expr("contains(null, \"x\")") is False

    def test_trim_returns_empty_for_null(self):
        assert eval_expr("trim(null)") == ""


class TestEvaluateAsBoolean:
    """Tests for evaluate_as_boolean function."""

    def test_returns_true_for_true_expression(self):
        assert eval_bool("true") is True

    def test_returns_false_for_false_expression(self):
        assert eval_bool("false") is False

    def test_throws_for_non_boolean(self):
        with pytest.raises(RuntimeError, match="boolean"):
            eval_bool("42")

    def test_evaluates_comparison(self):
        assert eval_bool("1 < 2") is True
        assert eval_bool("1 > 2") is False

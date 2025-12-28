"""
Tests for generic built-in functions (exists, coalesce, trim).
"""

import pytest

from naylence.fame.expr import (
    EvaluationContext,
    ExprValue,
    evaluate,
    evaluate_as_boolean,
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


def eval_bool(
    expression: str,
    bindings: dict[str, ExprValue] | None = None,
) -> bool:
    """Helper to evaluate an expression as boolean and return the value."""
    bindings = bindings or {}
    ast = parse(expression)
    context = EvaluationContext(
        bindings=bindings,
        source=expression,
    )
    value, error = evaluate_as_boolean(ast, context)
    if error:
        raise RuntimeError(error)
    return value


class TestExistsBasicBehavior:
    """Tests for exists builtin basic behavior."""

    def test_returns_false_for_null(self):
        assert eval_expr("exists(null)") is False

    def test_returns_true_for_string(self):
        assert eval_expr('exists("x")') is True

    def test_returns_true_for_empty_string(self):
        assert eval_expr('exists("")') is True

    def test_returns_true_for_number_zero(self):
        assert eval_expr("exists(0)") is True

    def test_returns_true_for_positive_number(self):
        assert eval_expr("exists(42)") is True

    def test_returns_true_for_boolean_false(self):
        assert eval_expr("exists(false)") is True

    def test_returns_true_for_boolean_true(self):
        assert eval_expr("exists(true)") is True

    def test_returns_true_for_empty_array(self):
        assert eval_expr("exists(arr)", {"arr": []}) is True

    def test_returns_true_for_non_empty_array(self):
        assert eval_expr("exists(arr)", {"arr": [1, 2, 3]}) is True

    def test_returns_true_for_empty_object(self):
        assert eval_expr("exists(obj)", {"obj": {}}) is True

    def test_returns_true_for_non_empty_object(self):
        assert eval_expr("exists(obj)", {"obj": {"a": 1}}) is True


class TestExistsMissingBindings:
    """Tests for exists with missing bindings."""

    def test_returns_false_for_missing_binding(self):
        assert eval_expr("exists(missing_binding)", {}) is False

    def test_returns_false_for_missing_property(self):
        assert eval_expr("exists(obj.missing)", {"obj": {}}) is False

    def test_returns_false_for_nested_missing_property(self):
        assert eval_expr("exists(claims.user.sub)", {"claims": {}}) is False

    def test_returns_true_for_present_property(self):
        assert eval_expr("exists(obj.prop)", {"obj": {"prop": "value"}}) is True


class TestExistsArgumentValidation:
    """Tests for exists argument validation."""

    def test_throws_for_zero_arguments(self):
        with pytest.raises(RuntimeError, match="expected 1 argument"):
            eval_expr("exists()")

    def test_throws_for_two_arguments(self):
        with pytest.raises(RuntimeError, match="expected 1 argument"):
            eval_expr("exists(1, 2)")


class TestCoalesceBasicBehavior:
    """Tests for coalesce builtin basic behavior."""

    def test_returns_second_arg_when_first_is_null(self):
        assert eval_expr('coalesce(null, "b")') == "b"

    def test_returns_first_arg_when_first_is_not_null(self):
        assert eval_expr('coalesce("a", "b")') == "a"

    def test_returns_first_arg_when_it_is_zero(self):
        assert eval_expr("coalesce(0, 1)") == 0

    def test_returns_first_arg_when_it_is_false(self):
        assert eval_expr("coalesce(false, true)") is False

    def test_returns_first_arg_when_it_is_empty_string(self):
        assert eval_expr('coalesce("", "default")') == ""

    def test_returns_first_arg_when_it_is_empty_array(self):
        result = eval_expr("coalesce(a, b)", {"a": [], "b": [1]})
        assert result == []

    def test_returns_first_arg_when_it_is_empty_object(self):
        result = eval_expr("coalesce(a, b)", {"a": {}, "b": {"x": 1}})
        assert result == {}

    def test_returns_second_arg_when_both_are_null(self):
        assert eval_expr("coalesce(null, null)") is None

    def test_returns_non_null_second_arg_when_first_is_null(self):
        assert eval_expr("coalesce(null, 42)") == 42


class TestCoalesceMissingBindings:
    """Tests for coalesce with missing bindings."""

    def test_returns_second_arg_when_first_is_missing_binding(self):
        assert eval_expr('coalesce(missing, "default")', {}) == "default"

    def test_returns_second_arg_when_first_is_missing_property(self):
        assert eval_expr('coalesce(obj.missing, "default")', {"obj": {}}) == "default"

    def test_returns_first_arg_when_present(self):
        result = eval_expr('coalesce(obj.prop, "default")', {"obj": {"prop": "value"}})
        assert result == "value"


class TestCoalesceArgumentValidation:
    """Tests for coalesce argument validation."""

    def test_throws_for_zero_arguments(self):
        with pytest.raises(RuntimeError, match="expected 2 argument"):
            eval_expr("coalesce()")

    def test_throws_for_one_argument(self):
        with pytest.raises(RuntimeError, match="expected 2 argument"):
            eval_expr("coalesce(1)")

    def test_throws_for_three_arguments(self):
        with pytest.raises(RuntimeError, match="expected 2 argument"):
            eval_expr("coalesce(1, 2, 3)")


class TestTrimBasicBehavior:
    """Tests for trim builtin basic behavior."""

    def test_trims_whitespace_from_both_ends(self):
        assert eval_expr('trim("  hi  ")') == "hi"

    def test_preserves_empty_string(self):
        assert eval_expr('trim("")') == ""

    def test_returns_empty_string_for_null(self):
        assert eval_expr("trim(null)") == ""

    def test_trims_string_with_only_whitespace(self):
        assert eval_expr('trim("   ")') == ""

    def test_trims_leading_whitespace(self):
        assert eval_expr('trim("  hello")') == "hello"

    def test_trims_trailing_whitespace(self):
        assert eval_expr('trim("hello  ")') == "hello"

    def test_preserves_internal_whitespace(self):
        assert eval_expr('trim("  hello world  ")') == "hello world"

    def test_trims_tabs_and_newlines(self):
        assert eval_expr('trim("\\t\\nhello\\n\\t")') == "hello"

    def test_handles_string_with_no_whitespace(self):
        assert eval_expr('trim("hello")') == "hello"


class TestTrimMissingBindings:
    """Tests for trim with missing bindings."""

    def test_returns_empty_string_for_missing_binding(self):
        assert eval_expr("trim(missing)", {}) == ""

    def test_returns_empty_string_for_missing_property(self):
        assert eval_expr("trim(obj.missing)", {"obj": {}}) == ""

    def test_trims_present_property(self):
        assert eval_expr("trim(obj.prop)", {"obj": {"prop": "  value  "}}) == "value"


class TestTrimTypeValidation:
    """Tests for trim type validation."""

    def test_throws_for_number(self):
        with pytest.raises(RuntimeError, match="string"):
            eval_expr("trim(123)")

    def test_throws_for_boolean(self):
        with pytest.raises(RuntimeError, match="string"):
            eval_expr("trim(true)")

    def test_throws_for_array(self):
        with pytest.raises(RuntimeError, match="string"):
            eval_expr("trim(arr)", {"arr": []})

    def test_throws_for_object(self):
        with pytest.raises(RuntimeError, match="string"):
            eval_expr("trim(obj)", {"obj": {}})


class TestTrimArgumentValidation:
    """Tests for trim argument validation."""

    def test_throws_for_zero_arguments(self):
        with pytest.raises(RuntimeError, match="expected 1 argument"):
            eval_expr("trim()")

    def test_throws_for_two_arguments(self):
        with pytest.raises(RuntimeError, match="expected 1 argument"):
            eval_expr('trim("a", "b")')


class TestIntegrationExistsWithOtherPredicates:
    """Integration tests for exists with other predicates."""

    def test_exists_and_starts_with_with_missing_binding_returns_false(self):
        result = eval_bool(
            'exists(claims.sub) && starts_with(claims.sub, "node-")',
            {"claims": {}},
        )
        assert result is False

    def test_exists_and_starts_with_with_null_returns_false(self):
        result = eval_bool(
            'exists(claims.sub) && starts_with(claims.sub, "node-")',
            {"claims": {"sub": None}},
        )
        assert result is False

    def test_exists_and_starts_with_with_present_value_returns_true(self):
        result = eval_bool(
            'exists(claims.sub) && starts_with(claims.sub, "node-")',
            {"claims": {"sub": "node-123"}},
        )
        assert result is True

    def test_exists_and_starts_with_with_non_matching_value_returns_false(self):
        result = eval_bool(
            'exists(claims.sub) && starts_with(claims.sub, "node-")',
            {"claims": {"sub": "user-123"}},
        )
        assert result is False


class TestIntegrationCoalesceWithTrimAndStartsWith:
    """Integration tests for coalesce with trim and starts_with."""

    def test_handles_missing_property_with_default(self):
        result = eval_bool(
            'starts_with(trim(coalesce(claims.sub, "")), "node-")',
            {"claims": {}},
        )
        assert result is False

    def test_handles_null_property_with_default(self):
        result = eval_bool(
            'starts_with(trim(coalesce(claims.sub, "")), "node-")',
            {"claims": {"sub": None}},
        )
        assert result is False

    def test_handles_present_property_with_whitespace(self):
        result = eval_bool(
            'starts_with(trim(coalesce(claims.sub, "")), "node-")',
            {"claims": {"sub": "  node-123  "}},
        )
        assert result is True

    def test_handles_present_property_without_match(self):
        result = eval_bool(
            'starts_with(trim(coalesce(claims.sub, "")), "node-")',
            {"claims": {"sub": "user-123"}},
        )
        assert result is False

    def test_trims_default_value_too(self):
        result = eval_bool(
            'starts_with(trim(coalesce(claims.sub, "  default  ")), "def")',
            {"claims": {}},
        )
        assert result is True


class TestIntegrationCoalesceChaining:
    """Integration tests for coalesce chaining."""

    def test_can_chain_coalesce_with_exists_check(self):
        result = eval_bool(
            "exists(coalesce(claims.primary, claims.fallback))",
            {"claims": {"fallback": "value"}},
        )
        assert result is True

    def test_returns_false_when_both_coalesce_args_are_null(self):
        result = eval_bool(
            "exists(coalesce(claims.primary, claims.fallback))",
            {"claims": {"primary": None, "fallback": None}},
        )
        assert result is False


class TestIntegrationTrimWithCoalesceForSafeStringOperations:
    """Integration tests for trim with coalesce for safe string operations."""

    def test_safely_trims_potentially_missing_string(self):
        assert eval_expr('trim(coalesce(obj.str, ""))', {"obj": {}}) == ""

    def test_trims_existing_string(self):
        result = eval_expr('trim(coalesce(obj.str, ""))', {"obj": {"str": "  value  "}})
        assert result == "value"

    def test_uses_default_when_value_is_null(self):
        result = eval_expr(
            'trim(coalesce(obj.str, "default"))',
            {"obj": {"str": None}},
        )
        assert result == "default"


class TestIntegrationComplexCompositions:
    """Integration tests for complex builtin compositions."""

    def test_exists_guards_against_null_in_complex_expression(self):
        result = eval_expr(
            'exists(claims.email) ? contains(claims.email, "@") : false',
            {"claims": {}},
        )
        assert result is False

    def test_coalesce_provides_safe_defaults_in_expressions(self):
        result = eval_expr(
            'len(coalesce(claims.name, ""))',
            {"claims": {}},
        )
        assert result == 0

    def test_trim_normalizes_user_input_in_expressions(self):
        result = eval_expr(
            'len(trim(coalesce(claims.name, "")))',
            {"claims": {"name": "   "}},
        )
        assert result == 0


class TestParameterizedExists:
    """Parameterized tests for exists."""

    @pytest.mark.parametrize(
        "expr,bindings,expected",
        [
            ("exists(null)", {}, False),
            ('exists("x")', {}, True),
            ("exists(0)", {}, True),
            ("exists(false)", {}, True),
            ("exists(x)", {}, False),
            ("exists(x)", {"x": None}, False),
            ("exists(x)", {"x": ""}, True),
            ("exists(x)", {"x": 0}, True),
        ],
    )
    def test_exists_parameterized(self, expr, bindings, expected):
        assert eval_expr(expr, bindings) == expected


class TestParameterizedCoalesce:
    """Parameterized tests for coalesce."""

    @pytest.mark.parametrize(
        "expr,bindings,expected",
        [
            ('coalesce(null, "b")', {}, "b"),
            ('coalesce("a", "b")', {}, "a"),
            ("coalesce(0, 1)", {}, 0),
            ("coalesce(false, true)", {}, False),
            ('coalesce(x, "def")', {}, "def"),
            ('coalesce(x, "def")', {"x": None}, "def"),
            ('coalesce(x, "def")', {"x": "val"}, "val"),
        ],
    )
    def test_coalesce_parameterized(self, expr, bindings, expected):
        assert eval_expr(expr, bindings) == expected


class TestParameterizedTrim:
    """Parameterized tests for trim."""

    @pytest.mark.parametrize(
        "expr,bindings,expected",
        [
            ('trim("  hi  ")', {}, "hi"),
            ('trim("")', {}, ""),
            ("trim(null)", {}, ""),
            ('trim("   ")', {}, ""),
            ("trim(x)", {}, ""),
            ("trim(x)", {"x": None}, ""),
            ("trim(x)", {"x": "  val  "}, "val"),
        ],
    )
    def test_trim_parameterized(self, expr, bindings, expected):
        assert eval_expr(expr, bindings) == expected

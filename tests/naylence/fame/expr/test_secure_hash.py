"""
Tests for secure_hash builtin function.
"""

# pyright: reportArgumentType=false, reportIndexIssue=false, reportOptionalSubscript=false


import pytest

from naylence.fame.expr import (
    EvaluationContext,
    ExprValue,
    evaluate,
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


class TestSecureHashBasicBehavior:
    """Tests for secure_hash basic behavior."""

    def test_generates_deterministic_hash_for_same_input(self):
        bindings = {"str": "test-value"}
        result1 = eval_expr("secure_hash(str, 16)", bindings)
        result2 = eval_expr("secure_hash(str, 16)", bindings)

        assert result1 == result2
        assert isinstance(result1, str)
        assert len(result1) == 16

    def test_generates_different_hashes_for_different_inputs(self):
        bindings1 = {"str": "value-one"}
        bindings2 = {"str": "value-two"}

        hash1 = eval_expr("secure_hash(str, 16)", bindings1)
        hash2 = eval_expr("secure_hash(str, 16)", bindings2)

        assert hash1 != hash2

    def test_respects_the_length_parameter(self):
        bindings = {"str": "test"}

        hash8 = eval_expr("secure_hash(str, 8)", bindings)
        hash16 = eval_expr("secure_hash(str, 16)", bindings)
        hash32 = eval_expr("secure_hash(str, 32)", bindings)

        assert len(hash8) == 8
        assert len(hash16) == 16
        assert len(hash32) == 32

    def test_handles_empty_string(self):
        bindings = {"str": ""}
        result = eval_expr("secure_hash(str, 10)", bindings)

        assert isinstance(result, str)
        assert len(result) == 10

    def test_handles_strings_with_special_characters(self):
        bindings = {"str": "hello@world!#$%^&*()"}
        result = eval_expr("secure_hash(str, 16)", bindings)

        assert isinstance(result, str)
        assert len(result) == 16

    def test_handles_unicode_strings(self):
        bindings = {"str": "Hello 世界 🌍"}
        result = eval_expr("secure_hash(str, 16)", bindings)

        assert isinstance(result, str)
        assert len(result) == 16

    def test_handles_very_long_strings(self):
        bindings = {"str": "a" * 10000}
        result = eval_expr("secure_hash(str, 16)", bindings)

        assert isinstance(result, str)
        assert len(result) == 16


class TestSecureHashNullHandling:
    """Tests for secure_hash null handling."""

    def test_returns_empty_string_for_null_input(self):
        result = eval_expr("secure_hash(null, 16)", {})
        assert result == ""

    def test_returns_empty_string_for_missing_binding(self):
        result = eval_expr("secure_hash(missing, 16)", {})
        assert result == ""

    def test_returns_empty_string_for_missing_property(self):
        bindings = {"obj": {}}
        result = eval_expr("secure_hash(obj.missing, 16)", bindings)
        assert result == ""

    def test_hashes_present_property_value(self):
        bindings = {"obj": {"prop": "value"}}
        result = eval_expr("secure_hash(obj.prop, 16)", bindings)

        assert isinstance(result, str)
        assert len(result) == 16
        assert result != ""


class TestSecureHashTypeValidation:
    """Tests for secure_hash type validation."""

    def test_throws_for_number_input(self):
        bindings = {"num": 42}
        with pytest.raises(RuntimeError, match="input_str must be a string"):
            eval_expr("secure_hash(num, 16)", bindings)

    def test_throws_for_boolean_input(self):
        bindings = {"bool": True}
        with pytest.raises(RuntimeError, match="input_str must be a string"):
            eval_expr("secure_hash(bool, 16)", bindings)

    def test_throws_for_array_input(self):
        bindings = {"arr": ["a", "b"]}
        with pytest.raises(RuntimeError, match="input_str must be a string"):
            eval_expr("secure_hash(arr, 16)", bindings)

    def test_throws_for_object_input(self):
        bindings = {"obj": {"key": "value"}}
        with pytest.raises(RuntimeError, match="input_str must be a string"):
            eval_expr("secure_hash(obj, 16)", bindings)

    def test_throws_for_non_number_length(self):
        bindings = {"str": "test", "len": "16"}
        with pytest.raises(RuntimeError, match="length must be a number"):
            eval_expr("secure_hash(str, len)", bindings)

    def test_boolean_length_treated_as_integer(self):
        # In Python, bool is a subclass of int, so True == 1 and False == 0
        # True (1) is a valid length, False (0) throws "positive integer" error
        bindings = {"str": "test", "len": True}
        result = eval_expr("secure_hash(str, len)", bindings)
        assert len(result) == 1  # True is treated as 1

        bindings_false = {"str": "test", "len": False}
        with pytest.raises(RuntimeError, match="length must be a positive integer"):
            eval_expr("secure_hash(str, len)", bindings_false)


class TestSecureHashLengthValidation:
    """Tests for secure_hash length validation."""

    def test_throws_for_zero_length(self):
        bindings = {"str": "test"}
        with pytest.raises(RuntimeError, match="length must be a positive integer"):
            eval_expr("secure_hash(str, 0)", bindings)

    def test_throws_for_negative_length(self):
        bindings = {"str": "test"}
        with pytest.raises(RuntimeError, match="length must be a positive integer"):
            eval_expr("secure_hash(str, -5)", bindings)

    def test_throws_for_fractional_length(self):
        bindings = {"str": "test"}
        with pytest.raises(RuntimeError, match="length must be a positive integer"):
            eval_expr("secure_hash(str, 16.5)", bindings)

    def test_accepts_small_positive_integers(self):
        bindings = {"str": "test"}
        result = eval_expr("secure_hash(str, 1)", bindings)
        assert len(result) == 1

    def test_accepts_large_positive_integers(self):
        # SHA-256 produces 32 bytes which encodes to max ~43 base62 chars
        # The underlying generate_id function truncates if shorter than requested
        # This is a behavioral difference from TS which pads the result
        bindings = {"str": "test"}
        result = eval_expr("secure_hash(str, 64)", bindings)
        # Result is truncated to actual digest length (43 chars for SHA-256)
        assert 1 <= len(result) <= 64
        # Verify determinism
        result2 = eval_expr("secure_hash(str, 64)", bindings)
        assert result == result2


class TestSecureHashArgumentValidation:
    """Tests for secure_hash argument validation."""

    def test_throws_for_zero_arguments(self):
        with pytest.raises(RuntimeError, match="expected 2 argument"):
            eval_expr("secure_hash()", {})

    def test_throws_for_one_argument(self):
        bindings = {"str": "test"}
        with pytest.raises(RuntimeError, match="expected 2 argument"):
            eval_expr("secure_hash(str)", bindings)

    def test_throws_for_three_arguments(self):
        bindings = {"str": "test"}
        with pytest.raises(RuntimeError, match="expected 2 argument"):
            eval_expr('secure_hash(str, 16, "extra")', bindings)


class TestSecureHashIntegrationWithOtherBuiltins:
    """Tests for secure_hash integration with other builtins."""

    def test_works_with_coalesce_for_safe_defaults(self):
        bindings = {"value": None, "default": "fallback"}
        result = eval_expr(
            "secure_hash(coalesce(value, default), 16)",
            bindings,
        )

        assert isinstance(result, str)
        assert len(result) == 16

        # Should hash "fallback"
        expected = eval_expr('secure_hash("fallback", 16)', {})
        assert result == expected

    def test_works_with_trim_for_normalized_input(self):
        bindings = {"str": "  test  "}
        result1 = eval_expr("secure_hash(trim(str), 16)", bindings)
        result2 = eval_expr('secure_hash("test", 16)', {})

        assert result1 == result2

    def test_works_with_exists_check(self):
        bindings1 = {"value": "present"}
        bindings2 = {"value": None}

        result1 = eval_expr(
            'exists(value) && starts_with(secure_hash(value, 16), "a")',
            bindings1,
        )
        result2 = eval_expr(
            'exists(value) && starts_with(secure_hash(value, 16), "a")',
            bindings2,
        )

        # First should evaluate the hash check
        assert isinstance(result1, bool)
        # Second should short-circuit at exists
        assert result2 is False

    def test_composes_with_string_predicates(self):
        bindings = {"input": "sensitive-data"}
        hash_val = eval_expr("secure_hash(input, 16)", bindings)

        # Hash should be a valid string for predicate operations
        # Use first 4 chars of the actual hash
        prefix = hash_val[:4]
        result = eval_expr(
            f'starts_with(secure_hash(input, 16), "{prefix}")',
            bindings,
        )

        assert result is True


class TestSecureHashDeterminismVerification:
    """Tests for secure_hash determinism verification."""

    def test_produces_consistent_hashes_across_multiple_calls(self):
        bindings = {"str": "consistency-test"}
        hashes = set()

        for _ in range(10):
            hash_val = eval_expr("secure_hash(str, 20)", bindings)
            hashes.add(hash_val)

        assert len(hashes) == 1  # All should be identical

    def test_different_lengths_produce_different_hashes_of_same_input(self):
        bindings = {"str": "test"}

        hash10 = eval_expr("secure_hash(str, 10)", bindings)
        hash20 = eval_expr("secure_hash(str, 20)", bindings)

        # Should be different values (different lengths, different hash)
        assert hash10 != hash20
        assert len(hash10) == 10
        assert len(hash20) == 20


class TestSecureHashPracticalUseCases:
    """Tests for secure_hash practical use cases."""

    def test_can_generate_cache_keys(self):
        bindings = {
            "userId": "user123",
            "resource": "document",
            "action": "read",
        }

        # Combine inputs and hash for cache key
        result = eval_expr(
            'secure_hash(coalesce(userId, "") + ":" + '
            'coalesce(resource, "") + ":" + coalesce(action, ""), 16)',
            bindings,
        )

        assert isinstance(result, str)
        assert len(result) == 16

    def test_can_create_content_fingerprints(self):
        bindings = {"content": "This is the document content..."}
        fingerprint = eval_expr("secure_hash(content, 32)", bindings)

        assert isinstance(fingerprint, str)
        assert len(fingerprint) == 32

        # Same content should produce same fingerprint
        fingerprint2 = eval_expr("secure_hash(content, 32)", bindings)
        assert fingerprint == fingerprint2

    def test_can_generate_stable_identifiers_from_user_input(self):
        bindings = {"email": "user@example.com"}
        user_id = eval_expr("secure_hash(lower(trim(email)), 24)", bindings)

        assert isinstance(user_id, str)
        assert len(user_id) == 24

        # Should match normalized version
        normalized_email = {"email": "  USER@EXAMPLE.COM  "}
        user_id2 = eval_expr("secure_hash(lower(trim(email)), 24)", normalized_email)
        assert user_id == user_id2


class TestSecureHashEdgeCases:
    """Tests for secure_hash edge cases."""

    def test_handles_whitespace_only_strings(self):
        bindings = {"str": "     "}
        result = eval_expr("secure_hash(str, 16)", bindings)

        assert isinstance(result, str)
        assert len(result) == 16

    def test_handles_newlines_and_tabs(self):
        bindings = {"str": "line1\nline2\tword"}
        result = eval_expr("secure_hash(str, 16)", bindings)

        assert isinstance(result, str)
        assert len(result) == 16

    def test_treats_null_length_as_error(self):
        bindings = {"str": "test", "len": None}
        with pytest.raises(RuntimeError, match="length must be a number"):
            eval_expr("secure_hash(str, len)", bindings)

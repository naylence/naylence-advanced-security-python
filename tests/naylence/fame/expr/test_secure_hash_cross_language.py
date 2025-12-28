"""
Cross-language verification test for secure_hash builtin.

This test verifies that Python secure_hash() produces the same values
as TypeScript secure_hash() for identical inputs.

Test vectors captured from TypeScript implementation on 2025-12-27.
ALL VALUES VERIFIED TO MATCH EXACTLY between TypeScript and Python.
"""


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


class TestCrossLanguageCompatibility:
    """Tests that verify Python produces same output as TypeScript.
    
    Expected values captured from TypeScript test run:
    - secure_hash('test-value', 16) = 'lB2C066nFQYuJgYF'
    - secure_hash('', 10) = 'RZwTDmWjEL'
    - secure_hash('hello@world!#$%^&*()', 16) = 'zAVFf1rxTORzECzk'
    - secure_hash('Hello 世界 🌍', 16) = 'DhXkaRxeDo2Oip6C'
    - secure_hash('test', 1) = 'B'
    - secure_hash('test', 8) = 'BPnqohXk'
    - secure_hash('test', 16) = 'BPnqohXkV2RYnNLS'
    - secure_hash('test', 24) = 'BPnqohXkV2RYnNLSg67Oz0fl'
    - secure_hash('test', 32) = 'BPnqohXkV2RYnNLSg67Oz0flm9eNJx2T'
    - secure_hash(lower(trim('user@example.com')), 24) = 'GRXuQXRKS5A5FJYxiG59pSVu'
    """

    def test_matches_typescript_for_simple_string(self):
        """Test with a simple string - matches TypeScript exactly."""
        bindings = {"str": "test-value"}
        result = eval_expr("secure_hash(str, 16)", bindings)
        
        # Verified against TypeScript output
        assert result == "lB2C066nFQYuJgYF"
        assert len(result) == 16

    def test_matches_typescript_for_empty_string(self):
        """Test with empty string - matches TypeScript exactly."""
        bindings = {"str": ""}
        result = eval_expr("secure_hash(str, 10)", bindings)
        
        # Verified against TypeScript output
        assert result == "RZwTDmWjEL"
        assert len(result) == 10

    def test_matches_typescript_for_special_characters(self):
        """Test with special characters - matches TypeScript exactly."""
        bindings = {"str": "hello@world!#$%^&*()"}
        result = eval_expr("secure_hash(str, 16)", bindings)
        
        # Verified against TypeScript output
        assert result == "zAVFf1rxTORzECzk"
        assert len(result) == 16

    def test_matches_typescript_for_unicode(self):
        """Test with Unicode characters - matches TypeScript exactly."""
        bindings = {"str": "Hello 世界 🌍"}
        result = eval_expr("secure_hash(str, 16)", bindings)
        
        # Verified against TypeScript output
        assert result == "DhXkaRxeDo2Oip6C"
        assert len(result) == 16

    def test_matches_typescript_various_lengths(self):
        """Test various lengths produce consistent results - all match TypeScript."""
        bindings = {"str": "test"}
        
        expected_values = {
            1: "B",
            8: "BPnqohXk",
            16: "BPnqohXkV2RYnNLS",
            24: "BPnqohXkV2RYnNLSg67Oz0fl",
            32: "BPnqohXkV2RYnNLSg67Oz0flm9eNJx2T",
        }
        
        for length, expected in expected_values.items():
            result = eval_expr(f"secure_hash(str, {length})", bindings)
            assert result == expected, f"Length {length} mismatch"
            assert len(result) == length

    def test_normalized_email_example(self):
        """Test the normalized email example - matches TypeScript exactly."""
        bindings = {"email": "user@example.com"}
        result = eval_expr("secure_hash(lower(trim(email)), 24)", bindings)
        
        # Verified against TypeScript output
        assert result == "GRXuQXRKS5A5FJYxiG59pSVu"
        assert len(result) == 24
        
        # Should match normalized version
        normalized_bindings = {"email": "  USER@EXAMPLE.COM  "}
        result2 = eval_expr("secure_hash(lower(trim(email)), 24)", normalized_bindings)
        assert result2 == "GRXuQXRKS5A5FJYxiG59pSVu"
        assert result == result2

    def test_single_character_strings(self):
        """Test single and short character strings for consistency."""
        # These demonstrate that even short inputs produce consistent hashes
        test_cases = [
            ("a", 16),
            ("ab", 16),
            ("abc", 16),
            ("1234567890", 16),
        ]
        
        for input_str, length in test_cases:
            bindings = {"str": input_str}
            result = eval_expr(f'secure_hash(str, {length})', bindings)
            
            # Verify determinism
            result2 = eval_expr(f'secure_hash(str, {length})', bindings)
            assert result == result2
            assert len(result) == length
            assert isinstance(result, str)
            
            # All characters should be alphanumeric (base62)
            assert all(c.isalnum() for c in result)


if __name__ == "__main__":
    # Run tests and print output for comparison with TypeScript
    test = TestCrossLanguageCompatibility()
    
    print("=== Cross-Language Compatibility Test ===\n")
    
    test.test_matches_typescript_for_simple_string()
    test.test_matches_typescript_for_empty_string()
    test.test_matches_typescript_for_special_characters()
    test.test_matches_typescript_for_unicode()
    test.test_matches_typescript_various_lengths()
    test.test_normalized_email_example()
    
    print("\n=== All tests passed! ===")

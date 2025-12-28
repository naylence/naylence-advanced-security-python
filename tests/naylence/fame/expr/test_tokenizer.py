"""
Tests for expression tokenizer.

Ported from TypeScript test suite.
"""

import pytest

from naylence.fame.expr import TokenizerError, tokenize
from naylence.fame.expr.tokenizer import TokenType


class TestLiterals:
    """Tests for literal tokenization."""

    def test_tokenizes_string_literals_with_double_quotes(self):
        tokens = tokenize('"hello"')
        assert len(tokens) == 2
        assert tokens[0].type == TokenType.STRING
        assert tokens[0].value == "hello"
        assert tokens[0].position == 0
        assert tokens[1].type == TokenType.EOF

    def test_tokenizes_string_literals_with_single_quotes(self):
        tokens = tokenize("'world'")
        assert tokens[0].type == TokenType.STRING
        assert tokens[0].value == "world"
        assert tokens[0].position == 0

    def test_tokenizes_escape_sequences_in_strings(self):
        tokens = tokenize('"line1\\nline2\\ttab"')
        assert tokens[0].value == "line1\nline2\ttab"

    def test_tokenizes_escaped_quotes_in_strings(self):
        tokens = tokenize('"say \\"hello\\""')
        assert tokens[0].value == 'say "hello"'

    def test_throws_on_unterminated_string(self):
        with pytest.raises(TokenizerError):
            tokenize('"unterminated')

    def test_tokenizes_integer_literals(self):
        tokens = tokenize("42")
        assert tokens[0].type == TokenType.NUMBER
        assert tokens[0].value == "42"
        assert tokens[0].position == 0

    def test_tokenizes_decimal_literals(self):
        tokens = tokenize("3.14159")
        assert tokens[0].type == TokenType.NUMBER
        assert tokens[0].value == "3.14159"
        assert tokens[0].position == 0

    def test_tokenizes_scientific_notation(self):
        tokens = tokenize("1.5e10")
        assert tokens[0].type == TokenType.NUMBER
        assert tokens[0].value == "1.5e10"
        assert tokens[0].position == 0

    def test_tokenizes_negative_exponent(self):
        tokens = tokenize("2.5E-3")
        assert tokens[0].type == TokenType.NUMBER
        assert tokens[0].value == "2.5E-3"
        assert tokens[0].position == 0

    def test_tokenizes_boolean_true(self):
        tokens = tokenize("true")
        assert tokens[0].type == TokenType.TRUE
        assert tokens[0].value == "true"
        assert tokens[0].position == 0

    def test_tokenizes_boolean_false(self):
        tokens = tokenize("false")
        assert tokens[0].type == TokenType.FALSE
        assert tokens[0].value == "false"
        assert tokens[0].position == 0

    def test_tokenizes_null(self):
        tokens = tokenize("null")
        assert tokens[0].type == TokenType.NULL
        assert tokens[0].value == "null"
        assert tokens[0].position == 0


class TestIdentifiers:
    """Tests for identifier tokenization."""

    def test_tokenizes_simple_identifiers(self):
        tokens = tokenize("foo")
        assert tokens[0].type == TokenType.IDENTIFIER
        assert tokens[0].value == "foo"
        assert tokens[0].position == 0

    def test_tokenizes_identifiers_with_underscores(self):
        tokens = tokenize("_private_var")
        assert tokens[0].value == "_private_var"

    def test_tokenizes_identifiers_with_numbers(self):
        tokens = tokenize("var123")
        assert tokens[0].value == "var123"


class TestOperators:
    """Tests for operator tokenization."""

    def test_tokenizes_comparison_operators(self):
        tokens = tokenize("< <= > >= == !=")
        types = [t.type for t in tokens[:-1]]
        expected = [
            TokenType.LT,
            TokenType.LE,
            TokenType.GT,
            TokenType.GE,
            TokenType.EQ,
            TokenType.NE,
        ]
        assert types == expected

    def test_tokenizes_logical_operators(self):
        tokens = tokenize("&& || !")
        types = [t.type for t in tokens[:-1]]
        assert types == [TokenType.AND, TokenType.OR, TokenType.NOT]

    def test_tokenizes_arithmetic_operators(self):
        tokens = tokenize("+ - * / %")
        types = [t.type for t in tokens[:-1]]
        expected = [
            TokenType.PLUS,
            TokenType.MINUS,
            TokenType.STAR,
            TokenType.SLASH,
            TokenType.PERCENT,
        ]
        assert types == expected

    def test_tokenizes_ternary_operators(self):
        tokens = tokenize("? :")
        types = [t.type for t in tokens[:-1]]
        assert types == [TokenType.QUESTION, TokenType.COLON]

    def test_tokenizes_in_keyword(self):
        tokens = tokenize("x in list")
        assert tokens[1].type == TokenType.IN

    def test_tokenizes_not_in_as_single_token(self):
        tokens = tokenize("x not in list")
        assert tokens[1].type == TokenType.NOT_IN
        assert tokens[1].value == "not in"


class TestDelimiters:
    """Tests for delimiter tokenization."""

    def test_tokenizes_parentheses(self):
        tokens = tokenize("()")
        types = [t.type for t in tokens[:-1]]
        assert types == [TokenType.LPAREN, TokenType.RPAREN]

    def test_tokenizes_brackets(self):
        tokens = tokenize("[]")
        types = [t.type for t in tokens[:-1]]
        assert types == [TokenType.LBRACKET, TokenType.RBRACKET]

    def test_tokenizes_dot_and_comma(self):
        tokens = tokenize(".,")
        types = [t.type for t in tokens[:-1]]
        assert types == [TokenType.DOT, TokenType.COMMA]


class TestComplexExpressions:
    """Tests for complex expression tokenization."""

    def test_tokenizes_member_access(self):
        tokens = tokenize("claims.sub")
        types = [t.type for t in tokens[:-1]]
        expected = [TokenType.IDENTIFIER, TokenType.DOT, TokenType.IDENTIFIER]
        assert types == expected

    def test_tokenizes_function_call(self):
        tokens = tokenize('has_scope("admin")')
        types = [t.type for t in tokens[:-1]]
        expected = [
            TokenType.IDENTIFIER,
            TokenType.LPAREN,
            TokenType.STRING,
            TokenType.RPAREN,
        ]
        assert types == expected

    def test_tokenizes_index_access(self):
        tokens = tokenize("arr[0]")
        types = [t.type for t in tokens[:-1]]
        expected = [
            TokenType.IDENTIFIER,
            TokenType.LBRACKET,
            TokenType.NUMBER,
            TokenType.RBRACKET,
        ]
        assert types == expected

    def test_tokenizes_binary_expression(self):
        tokens = tokenize("a + b * c")
        types = [t.type for t in tokens[:-1]]
        expected = [
            TokenType.IDENTIFIER,
            TokenType.PLUS,
            TokenType.IDENTIFIER,
            TokenType.STAR,
            TokenType.IDENTIFIER,
        ]
        assert types == expected

    def test_tokenizes_comparison_expression(self):
        tokens = tokenize("x > 10 && y < 20")
        types = [t.type for t in tokens[:-1]]
        expected = [
            TokenType.IDENTIFIER,
            TokenType.GT,
            TokenType.NUMBER,
            TokenType.AND,
            TokenType.IDENTIFIER,
            TokenType.LT,
            TokenType.NUMBER,
        ]
        assert types == expected


class TestWhitespaceHandling:
    """Tests for whitespace handling."""

    def test_ignores_spaces(self):
        tokens = tokenize("  a  +  b  ")
        types = [t.type for t in tokens[:-1]]
        assert types == [TokenType.IDENTIFIER, TokenType.PLUS, TokenType.IDENTIFIER]

    def test_ignores_tabs(self):
        tokens = tokenize("\ta\t+\tb\t")
        types = [t.type for t in tokens[:-1]]
        assert types == [TokenType.IDENTIFIER, TokenType.PLUS, TokenType.IDENTIFIER]

    def test_ignores_newlines(self):
        tokens = tokenize("a\n+\nb")
        types = [t.type for t in tokens[:-1]]
        assert types == [TokenType.IDENTIFIER, TokenType.PLUS, TokenType.IDENTIFIER]


class TestErrorCases:
    """Tests for error handling."""

    def test_throws_on_invalid_character(self):
        with pytest.raises(TokenizerError):
            tokenize("a @ b")

    def test_throws_on_unterminated_single_quote_string(self):
        with pytest.raises(TokenizerError):
            tokenize("'unterminated")

    def test_error_includes_context(self):
        """Check error message contains useful information."""
        try:
            tokenize("abc @ def")
            pytest.fail("Expected TokenizerError")
        except TokenizerError as e:
            # Error should mention the unexpected character
            assert "@" in str(e)

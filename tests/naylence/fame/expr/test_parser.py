"""
Tests for expression parser.

Ported from TypeScript test suite.
"""

# pyright: reportAttributeAccessIssue=false


import pytest

from naylence.fame.expr import ParseError, parse


class TestLiterals:
    """Tests for literal parsing."""

    def test_parses_string_literal(self):
        ast = parse('"hello"')
        assert ast.type == "StringLiteral"
        assert ast.position == 0
        assert ast.value == "hello"

    def test_parses_number_literal(self):
        ast = parse("42")
        assert ast.type == "NumberLiteral"
        assert ast.position == 0
        assert ast.value == 42

    def test_parses_decimal_number(self):
        ast = parse("3.14")
        assert ast.type == "NumberLiteral"
        assert ast.position == 0
        assert ast.value == pytest.approx(3.14)

    def test_parses_true(self):
        ast = parse("true")
        assert ast.type == "BooleanLiteral"
        assert ast.position == 0
        assert ast.value is True

    def test_parses_false(self):
        ast = parse("false")
        assert ast.type == "BooleanLiteral"
        assert ast.position == 0
        assert ast.value is False

    def test_parses_null(self):
        ast = parse("null")
        assert ast.type == "NullLiteral"
        assert ast.position == 0

    def test_parses_empty_array(self):
        ast = parse("[]")
        assert ast.type == "ArrayLiteral"
        assert ast.position == 0
        assert ast.elements == ()  # Python AST uses tuples for immutability

    def test_parses_array_with_elements(self):
        ast = parse('["a", "b", "c"]')
        assert ast.type == "ArrayLiteral"
        assert len(ast.elements) == 3


class TestIdentifiers:
    """Tests for identifier parsing."""

    def test_parses_simple_identifier(self):
        ast = parse("foo")
        assert ast.type == "Identifier"
        assert ast.position == 0
        assert ast.name == "foo"


class TestMemberAccess:
    """Tests for member access parsing."""

    def test_parses_single_member_access(self):
        ast = parse("claims.sub")
        assert ast.type == "MemberAccess"
        assert ast.property == "sub"
        assert ast.object.type == "Identifier"
        assert ast.object.name == "claims"

    def test_parses_chained_member_access(self):
        ast = parse("envelope.frame.type")
        assert ast.type == "MemberAccess"
        assert ast.property == "type"
        assert ast.object.type == "MemberAccess"


class TestIndexAccess:
    """Tests for index access parsing."""

    def test_parses_numeric_index(self):
        ast = parse("arr[0]")
        assert ast.type == "IndexAccess"
        assert ast.index.type == "NumberLiteral"

    def test_parses_string_index(self):
        ast = parse('obj["key"]')
        assert ast.type == "IndexAccess"
        assert ast.index.type == "StringLiteral"


class TestFunctionCalls:
    """Tests for function call parsing."""

    def test_parses_function_with_no_args(self):
        ast = parse("now()")
        assert ast.type == "FunctionCall"
        assert ast.name == "now"
        assert ast.args == ()  # Python AST uses tuples for immutability

    def test_parses_function_with_one_arg(self):
        ast = parse('has_scope("admin")')
        assert ast.type == "FunctionCall"
        assert ast.name == "has_scope"
        assert len(ast.args) == 1

    def test_parses_function_with_multiple_args(self):
        ast = parse('starts_with(name, "prefix")')
        assert ast.type == "FunctionCall"
        assert ast.name == "starts_with"
        assert len(ast.args) == 2


class TestUnaryOperators:
    """Tests for unary operator parsing."""

    def test_parses_logical_not(self):
        ast = parse("!flag")
        assert ast.type == "UnaryOp"
        assert ast.operator == "!"
        assert ast.operand.type == "Identifier"
        assert ast.operand.name == "flag"

    def test_parses_negation(self):
        ast = parse("-5")
        assert ast.type == "UnaryOp"
        assert ast.operator == "-"
        assert ast.operand.type == "NumberLiteral"
        assert ast.operand.value == 5

    def test_parses_double_negation(self):
        ast = parse("!!flag")
        assert ast.type == "UnaryOp"
        assert ast.operand.type == "UnaryOp"


class TestBinaryOperators:
    """Tests for binary operator parsing."""

    def test_parses_addition(self):
        ast = parse("a + b")
        assert ast.type == "BinaryOp"
        assert ast.operator == "+"

    def test_parses_subtraction(self):
        ast = parse("a - b")
        assert ast.type == "BinaryOp"
        assert ast.operator == "-"

    def test_parses_multiplication(self):
        ast = parse("a * b")
        assert ast.type == "BinaryOp"
        assert ast.operator == "*"

    def test_parses_division(self):
        ast = parse("a / b")
        assert ast.type == "BinaryOp"
        assert ast.operator == "/"

    def test_parses_modulo(self):
        ast = parse("a % b")
        assert ast.type == "BinaryOp"
        assert ast.operator == "%"

    def test_parses_comparison_operators(self):
        for op in ["<", "<=", ">", ">=", "==", "!="]:
            ast = parse(f"a {op} b")
            assert ast.type == "BinaryOp"
            assert ast.operator == op

    def test_parses_logical_and(self):
        ast = parse("a && b")
        assert ast.type == "BinaryOp"
        assert ast.operator == "&&"

    def test_parses_logical_or(self):
        ast = parse("a || b")
        assert ast.type == "BinaryOp"
        assert ast.operator == "||"

    def test_parses_in_operator(self):
        ast = parse("x in list")
        assert ast.type == "BinaryOp"
        assert ast.operator == "in"

    def test_parses_not_in_operator(self):
        ast = parse("x not in list")
        assert ast.type == "BinaryOp"
        assert ast.operator == "not in"


class TestOperatorPrecedence:
    """Tests for operator precedence."""

    def test_multiplication_before_addition(self):
        ast = parse("a + b * c")
        assert ast.type == "BinaryOp"
        assert ast.operator == "+"
        assert ast.right.type == "BinaryOp"
        assert ast.right.operator == "*"

    def test_parentheses_override_precedence(self):
        ast = parse("(a + b) * c")
        assert ast.type == "BinaryOp"
        assert ast.operator == "*"
        assert ast.left.type == "BinaryOp"
        assert ast.left.operator == "+"

    def test_and_before_or(self):
        ast = parse("a || b && c")
        assert ast.type == "BinaryOp"
        assert ast.operator == "||"
        assert ast.right.type == "BinaryOp"
        assert ast.right.operator == "&&"

    def test_comparison_before_logical(self):
        ast = parse("a > b && c < d")
        assert ast.type == "BinaryOp"
        assert ast.operator == "&&"
        assert ast.left.operator == ">"
        assert ast.right.operator == "<"


class TestTernaryOperator:
    """Tests for ternary operator parsing."""

    def test_parses_simple_ternary(self):
        ast = parse("a ? b : c")
        assert ast.type == "TernaryOp"
        assert ast.condition.name == "a"
        assert ast.consequent.name == "b"
        assert ast.alternate.name == "c"

    def test_parses_nested_ternary(self):
        ast = parse("a ? b : c ? d : e")
        assert ast.type == "TernaryOp"
        assert ast.alternate.type == "TernaryOp"


class TestComplexExpressions:
    """Tests for complex expression parsing."""

    def test_parses_function_call_with_member_access(self):
        ast = parse("starts_with(claims.sub, \"admin\")")
        assert ast.type == "FunctionCall"
        assert ast.args[0].type == "MemberAccess"

    def test_parses_chained_function_calls(self):
        ast = parse('lower(trim(name))')
        assert ast.type == "FunctionCall"
        assert ast.args[0].type == "FunctionCall"

    def test_parses_complex_condition(self):
        ast = parse('claims.role == "admin" && envelope.to != null')
        assert ast.type == "BinaryOp"
        assert ast.operator == "&&"


class TestErrorHandling:
    """Tests for error handling."""

    def test_throws_on_empty_input(self):
        with pytest.raises(ParseError):
            parse("")

    def test_throws_on_unclosed_parenthesis(self):
        with pytest.raises(ParseError):
            parse("(a + b")

    def test_throws_on_missing_operand(self):
        with pytest.raises(ParseError):
            parse("a +")

    def test_throws_on_invalid_token_sequence(self):
        with pytest.raises(ParseError):
            parse("a b")

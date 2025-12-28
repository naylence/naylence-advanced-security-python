"""
Parser for the expression language.

Parses a stream of tokens into an Abstract Syntax Tree (AST).
Uses recursive descent parsing with operator precedence.

Precedence (lowest to highest):
1. Ternary: ? :
2. Logical OR: ||
3. Logical AND: &&
4. Membership: in, not in
5. Equality: ==, !=
6. Comparison: <, <=, >, >=
7. Additive: +, -
8. Multiplicative: *, /, %
9. Unary: !, -
10. Postfix: . [] ()
11. Primary: literals, identifiers, parentheses
"""

from typing import List

from .ast import (
    ArrayLiteralNode,
    AstNode,
    BinaryOperator,
    BinaryOpNode,
    BooleanLiteralNode,
    FunctionCallNode,
    IdentifierNode,
    IndexAccessNode,
    MemberAccessNode,
    NullLiteralNode,
    NumberLiteralNode,
    StringLiteralNode,
    TernaryOpNode,
    UnaryOperator,
    UnaryOpNode,
    calculate_ast_depth,
    count_ast_nodes,
)
from .errors import ParseError
from .limits import (
    DEFAULT_EXPRESSION_LIMITS,
    ExpressionLimits,
    check_array_length,
    check_ast_depth,
    check_ast_node_count,
    check_function_arg_count,
)
from .tokenizer import Token, TokenType, tokenize


class Parser:
    """Parser for expression strings."""

    def __init__(
        self,
        tokens: List[Token],
        source: str,
        limits: ExpressionLimits = DEFAULT_EXPRESSION_LIMITS,
    ):
        self._tokens = tokens
        self._source = source
        self._limits = limits
        self._current = 0

    def parse(self) -> AstNode:
        """Parses the token stream into an AST."""
        ast = self._parse_ternary()

        if not self._is_at_end():
            token = self._peek()
            raise ParseError(
                f"Unexpected token: {token.value or token.type.value}",
                token.position,
                self._source,
            )

        # Validate AST limits
        node_count = count_ast_nodes(ast)
        check_ast_node_count(node_count, self._limits)

        depth = calculate_ast_depth(ast)
        check_ast_depth(depth, self._limits)

        return ast

    # ============================================================
    # Token Helpers
    # ============================================================

    def _is_at_end(self) -> bool:
        return self._peek().type == TokenType.EOF

    def _peek(self) -> Token:
        return self._tokens[self._current]

    def _previous(self) -> Token:
        return self._tokens[self._current - 1]

    def _advance(self) -> Token:
        if not self._is_at_end():
            self._current += 1
        return self._previous()

    def _check(self, token_type: TokenType) -> bool:
        if self._is_at_end():
            return False
        return self._peek().type == token_type

    def _match(self, *types: TokenType) -> bool:
        for token_type in types:
            if self._check(token_type):
                self._advance()
                return True
        return False

    def _consume(self, token_type: TokenType, message: str) -> Token:
        if self._check(token_type):
            return self._advance()
        token = self._peek()
        raise ParseError(message, token.position, self._source)

    # ============================================================
    # Expression Parsing (by precedence, lowest to highest)
    # ============================================================

    def _parse_ternary(self) -> AstNode:
        """Parses ternary expressions: condition ? consequent : alternate"""
        position = self._peek().position
        node = self._parse_or()

        if self._match(TokenType.QUESTION):
            consequent = self._parse_ternary()
            self._consume(TokenType.COLON, "Expected ':' in ternary expression")
            alternate = self._parse_ternary()

            node = TernaryOpNode(
                position=position,
                condition=node,
                consequent=consequent,
                alternate=alternate,
            )

        return node

    def _parse_or(self) -> AstNode:
        """Parses logical OR: ||"""
        node = self._parse_and()

        while self._match(TokenType.OR):
            position = self._previous().position
            right = self._parse_and()
            node = BinaryOpNode(
                position=position,
                operator="||",
                left=node,
                right=right,
            )

        return node

    def _parse_and(self) -> AstNode:
        """Parses logical AND: &&"""
        node = self._parse_equality()

        while self._match(TokenType.AND):
            position = self._previous().position
            right = self._parse_equality()
            node = BinaryOpNode(
                position=position,
                operator="&&",
                left=node,
                right=right,
            )

        return node

    def _parse_equality(self) -> AstNode:
        """Parses equality: ==, !="""
        node = self._parse_membership()

        while self._match(TokenType.EQ, TokenType.NE):
            operator: BinaryOperator = "==" if self._previous().type == TokenType.EQ else "!="
            position = self._previous().position
            right = self._parse_membership()
            node = BinaryOpNode(
                position=position,
                operator=operator,
                left=node,
                right=right,
            )

        return node

    def _parse_membership(self) -> AstNode:
        """Parses membership: in, not in"""
        node = self._parse_comparison()

        while self._match(TokenType.IN, TokenType.NOT_IN):
            operator: BinaryOperator = "in" if self._previous().type == TokenType.IN else "not in"
            position = self._previous().position
            right = self._parse_comparison()
            node = BinaryOpNode(
                position=position,
                operator=operator,
                left=node,
                right=right,
            )

        return node

    def _parse_comparison(self) -> AstNode:
        """Parses comparison: <, <=, >, >="""
        node = self._parse_additive()

        while self._match(TokenType.LT, TokenType.LE, TokenType.GT, TokenType.GE):
            token = self._previous()
            operator_map = {
                TokenType.LT: "<",
                TokenType.LE: "<=",
                TokenType.GT: ">",
                TokenType.GE: ">=",
            }
            operator: BinaryOperator = operator_map[token.type]
            position = token.position
            right = self._parse_additive()
            node = BinaryOpNode(
                position=position,
                operator=operator,
                left=node,
                right=right,
            )

        return node

    def _parse_additive(self) -> AstNode:
        """Parses additive: +, -"""
        node = self._parse_multiplicative()

        while self._match(TokenType.PLUS, TokenType.MINUS):
            operator: BinaryOperator = "+" if self._previous().type == TokenType.PLUS else "-"
            position = self._previous().position
            right = self._parse_multiplicative()
            node = BinaryOpNode(
                position=position,
                operator=operator,
                left=node,
                right=right,
            )

        return node

    def _parse_multiplicative(self) -> AstNode:
        """Parses multiplicative: *, /, %"""
        node = self._parse_unary()

        while self._match(TokenType.STAR, TokenType.SLASH, TokenType.PERCENT):
            token = self._previous()
            operator_map = {
                TokenType.STAR: "*",
                TokenType.SLASH: "/",
                TokenType.PERCENT: "%",
            }
            operator: BinaryOperator = operator_map[token.type]
            position = token.position
            right = self._parse_unary()
            node = BinaryOpNode(
                position=position,
                operator=operator,
                left=node,
                right=right,
            )

        return node

    def _parse_unary(self) -> AstNode:
        """Parses unary: !, -"""
        if self._match(TokenType.NOT, TokenType.MINUS):
            token = self._previous()
            operator: UnaryOperator = "!" if token.type == TokenType.NOT else "-"
            position = token.position
            operand = self._parse_unary()
            return UnaryOpNode(
                position=position,
                operator=operator,
                operand=operand,
            )

        return self._parse_postfix()

    def _parse_postfix(self) -> AstNode:
        """Parses postfix: . [] ()"""
        node = self._parse_primary()

        while True:
            if self._match(TokenType.DOT):
                position = self._previous().position
                prop_token = self._consume(
                    TokenType.IDENTIFIER, "Expected property name after '.'"
                )
                node = MemberAccessNode(
                    position=position,
                    object=node,
                    property=prop_token.value,
                )
            elif self._match(TokenType.LBRACKET):
                position = self._previous().position
                index = self._parse_ternary()
                self._consume(TokenType.RBRACKET, "Expected ']' after index")
                node = IndexAccessNode(
                    position=position,
                    object=node,
                    index=index,
                )
            elif self._match(TokenType.LPAREN):
                # Function call - node must be an identifier
                if not isinstance(node, IdentifierNode):
                    raise ParseError(
                        "Only named functions can be called",
                        node.position,
                        self._source,
                    )
                position = self._previous().position
                args = self._parse_argument_list()
                check_function_arg_count(len(args), self._limits)
                node = FunctionCallNode(
                    position=position,
                    name=node.name,
                    args=tuple(args),
                )
            else:
                break

        return node

    def _parse_argument_list(self) -> List[AstNode]:
        """Parses function argument list (already consumed opening paren)."""
        args: List[AstNode] = []

        if not self._check(TokenType.RPAREN):
            args.append(self._parse_ternary())
            while self._match(TokenType.COMMA):
                args.append(self._parse_ternary())

        self._consume(TokenType.RPAREN, "Expected ')' after function arguments")
        return args

    def _parse_primary(self) -> AstNode:
        """Parses primary expressions: literals, identifiers, parentheses, arrays."""
        token = self._peek()
        position = token.position

        # Boolean literals
        if self._match(TokenType.TRUE):
            return BooleanLiteralNode(position=position, value=True)
        if self._match(TokenType.FALSE):
            return BooleanLiteralNode(position=position, value=False)

        # Null literal
        if self._match(TokenType.NULL):
            return NullLiteralNode(position=position)

        # String literal
        if self._match(TokenType.STRING):
            return StringLiteralNode(position=position, value=self._previous().value)

        # Number literal
        if self._match(TokenType.NUMBER):
            value = float(self._previous().value)
            if not (-float("inf") < value < float("inf")):
                raise ParseError("Invalid number", position, self._source)
            return NumberLiteralNode(position=position, value=value)

        # Identifier
        if self._match(TokenType.IDENTIFIER):
            return IdentifierNode(position=position, name=self._previous().value)

        # Parenthesized expression
        if self._match(TokenType.LPAREN):
            expr = self._parse_ternary()
            self._consume(TokenType.RPAREN, "Expected ')' after expression")
            return expr

        # Array literal
        if self._match(TokenType.LBRACKET):
            elements: List[AstNode] = []

            if not self._check(TokenType.RBRACKET):
                elements.append(self._parse_ternary())
                while self._match(TokenType.COMMA):
                    elements.append(self._parse_ternary())

            self._consume(TokenType.RBRACKET, "Expected ']' after array elements")
            check_array_length(len(elements), self._limits)

            return ArrayLiteralNode(position=position, elements=tuple(elements))

        raise ParseError(
            f"Unexpected token: {token.value or token.type.value}",
            position,
            self._source,
        )


def parse(
    source: str, limits: ExpressionLimits = DEFAULT_EXPRESSION_LIMITS
) -> AstNode:
    """
    Parses an expression string into an AST.

    Args:
        source: The expression string to parse
        limits: Optional expression limits

    Returns:
        The parsed AST

    Raises:
        TokenizerError: If tokenization fails
        ParseError: If parsing fails
    """
    tokens = tokenize(source, limits)
    parser = Parser(tokens, source, limits)
    return parser.parse()

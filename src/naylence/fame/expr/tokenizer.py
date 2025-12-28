"""
Tokenizer (lexer) for the expression language.

Converts expression strings into a stream of tokens for the parser.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

from .errors import TokenizerError
from .limits import ExpressionLimits, check_expression_length


class TokenType(Enum):
    """Token types produced by the tokenizer."""

    # Literals
    STRING = "STRING"
    NUMBER = "NUMBER"
    TRUE = "TRUE"
    FALSE = "FALSE"
    NULL = "NULL"

    # Identifiers
    IDENTIFIER = "IDENTIFIER"

    # Operators
    PLUS = "PLUS"
    MINUS = "MINUS"
    STAR = "STAR"
    SLASH = "SLASH"
    PERCENT = "PERCENT"
    LT = "LT"
    LE = "LE"
    GT = "GT"
    GE = "GE"
    EQ = "EQ"
    NE = "NE"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    IN = "IN"
    NOT_IN = "NOT_IN"
    QUESTION = "QUESTION"
    COLON = "COLON"

    # Delimiters
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    LBRACKET = "LBRACKET"
    RBRACKET = "RBRACKET"
    DOT = "DOT"
    COMMA = "COMMA"

    # Special
    EOF = "EOF"


@dataclass
class Token:
    """A token produced by the tokenizer."""

    type: TokenType
    value: str
    position: int


# Keywords recognized by the tokenizer
KEYWORDS: Dict[str, TokenType] = {
    "true": TokenType.TRUE,
    "false": TokenType.FALSE,
    "null": TokenType.NULL,
    "in": TokenType.IN,
    "not": TokenType.NOT,
}


def _is_digit(ch: str) -> bool:
    """Checks if a character is a digit."""
    return "0" <= ch <= "9"


def _is_identifier_start(ch: str) -> bool:
    """Checks if a character can start an identifier."""
    return ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ch == "_"


def _is_identifier_part(ch: str) -> bool:
    """Checks if a character can continue an identifier."""
    return _is_identifier_start(ch) or _is_digit(ch)


def _is_whitespace(ch: str) -> bool:
    """Checks if a character is whitespace."""
    return ch in (" ", "\t", "\n", "\r")


class Tokenizer:
    """Tokenizer for expression strings."""

    def __init__(self, source: str, limits: Optional[ExpressionLimits] = None):
        self._source = source
        self._limits = limits
        self._position = 0
        self._tokens: List[Token] = []

    def tokenize(self) -> List[Token]:
        """Tokenizes the source expression and returns all tokens."""
        check_expression_length(self._source, self._limits)

        while not self._is_at_end():
            self._scan_token()

        self._tokens.append(Token(TokenType.EOF, "", self._position))
        return self._tokens

    def _is_at_end(self) -> bool:
        return self._position >= len(self._source)

    def _peek(self) -> str:
        if self._is_at_end():
            return "\0"
        return self._source[self._position]

    def _peek_next(self) -> str:
        if self._position + 1 >= len(self._source):
            return "\0"
        return self._source[self._position + 1]

    def _advance(self) -> str:
        ch = self._source[self._position]
        self._position += 1
        return ch

    def _add_token(self, token_type: TokenType, value: str, position: int) -> None:
        self._tokens.append(Token(token_type, value, position))

    def _scan_token(self) -> None:
        ch = self._advance()
        start_position = self._position - 1

        # Skip whitespace
        if _is_whitespace(ch):
            return

        # Single-character tokens
        single_char_tokens = {
            "(": TokenType.LPAREN,
            ")": TokenType.RPAREN,
            "[": TokenType.LBRACKET,
            "]": TokenType.RBRACKET,
            ".": TokenType.DOT,
            ",": TokenType.COMMA,
            "+": TokenType.PLUS,
            "-": TokenType.MINUS,
            "*": TokenType.STAR,
            "/": TokenType.SLASH,
            "%": TokenType.PERCENT,
            "?": TokenType.QUESTION,
            ":": TokenType.COLON,
        }

        if ch in single_char_tokens:
            self._add_token(single_char_tokens[ch], ch, start_position)
            return

        # Two-character operators
        if ch == "<":
            if self._peek() == "=":
                self._advance()
                self._add_token(TokenType.LE, "<=", start_position)
            else:
                self._add_token(TokenType.LT, "<", start_position)
            return

        if ch == ">":
            if self._peek() == "=":
                self._advance()
                self._add_token(TokenType.GE, ">=", start_position)
            else:
                self._add_token(TokenType.GT, ">", start_position)
            return

        if ch == "=":
            if self._peek() == "=":
                self._advance()
                self._add_token(TokenType.EQ, "==", start_position)
                return
            raise TokenizerError(
                "Unexpected '='. Did you mean '=='?", start_position, self._source
            )

        if ch == "!":
            if self._peek() == "=":
                self._advance()
                self._add_token(TokenType.NE, "!=", start_position)
            else:
                self._add_token(TokenType.NOT, "!", start_position)
            return

        if ch == "&":
            if self._peek() == "&":
                self._advance()
                self._add_token(TokenType.AND, "&&", start_position)
                return
            raise TokenizerError(
                "Unexpected '&'. Did you mean '&&'?", start_position, self._source
            )

        if ch == "|":
            if self._peek() == "|":
                self._advance()
                self._add_token(TokenType.OR, "||", start_position)
                return
            raise TokenizerError(
                "Unexpected '|'. Did you mean '||'?", start_position, self._source
            )

        # String literals
        if ch == '"' or ch == "'":
            self._scan_string(ch, start_position)
            return

        # Number literals
        if _is_digit(ch):
            self._scan_number(start_position)
            return

        # Identifiers and keywords
        if _is_identifier_start(ch):
            self._scan_identifier(start_position)
            return

        raise TokenizerError(
            f"Unexpected character: '{ch}'", start_position, self._source
        )

    def _scan_string(self, quote: str, start_position: int) -> None:
        value = ""

        while not self._is_at_end() and self._peek() != quote:
            ch = self._advance()

            if ch == "\\":
                # Escape sequence
                if self._is_at_end():
                    raise TokenizerError(
                        "Unterminated string", start_position, self._source
                    )
                escaped = self._advance()
                escape_map = {
                    "n": "\n",
                    "r": "\r",
                    "t": "\t",
                    "\\": "\\",
                    '"': '"',
                    "'": "'",
                }
                if escaped in escape_map:
                    value += escape_map[escaped]
                else:
                    raise TokenizerError(
                        f"Invalid escape sequence: \\{escaped}",
                        self._position - 2,
                        self._source,
                    )
            elif ch in ("\n", "\r"):
                raise TokenizerError(
                    "Unterminated string (newline in string literal)",
                    start_position,
                    self._source,
                )
            else:
                value += ch

        if self._is_at_end():
            raise TokenizerError("Unterminated string", start_position, self._source)

        # Consume closing quote
        self._advance()

        self._add_token(TokenType.STRING, value, start_position)

    def _scan_number(self, start_position: int) -> None:
        # Back up to include the first digit
        self._position -= 1

        value = ""

        # Integer part
        while _is_digit(self._peek()):
            value += self._advance()

        # Fractional part
        if self._peek() == "." and _is_digit(self._peek_next()):
            value += self._advance()  # consume '.'
            while _is_digit(self._peek()):
                value += self._advance()

        # Exponent part
        if self._peek() in ("e", "E"):
            value += self._advance()
            if self._peek() in ("+", "-"):
                value += self._advance()
            if not _is_digit(self._peek()):
                raise TokenizerError(
                    "Invalid number: expected exponent digits",
                    start_position,
                    self._source,
                )
            while _is_digit(self._peek()):
                value += self._advance()

        self._add_token(TokenType.NUMBER, value, start_position)

    def _scan_identifier(self, start_position: int) -> None:
        # Back up to include the first character
        self._position -= 1

        value = ""

        while _is_identifier_part(self._peek()):
            value += self._advance()

        # Check for "not in" compound keyword
        value_lower = value.lower()
        if value_lower == "not":
            # Check if followed by whitespace and "in"
            saved_position = self._position

            # Skip whitespace
            while _is_whitespace(self._peek()):
                self._advance()

            # Check for "in"
            next_char = self._peek()
            next_next = self._peek_next()
            after_in = (
                self._source[self._position + 2]
                if self._position + 2 < len(self._source)
                else "\0"
            )

            if next_char == "i" and next_next == "n" and not _is_identifier_part(after_in):
                self._advance()  # consume 'i'
                self._advance()  # consume 'n'
                self._add_token(TokenType.NOT_IN, "not in", start_position)
                return

            # Not "not in", restore position
            self._position = saved_position

        # Check for keyword
        keyword_type = KEYWORDS.get(value_lower)
        if keyword_type:
            self._add_token(keyword_type, value, start_position)
        else:
            self._add_token(TokenType.IDENTIFIER, value, start_position)


def tokenize(source: str, limits: Optional[ExpressionLimits] = None) -> List[Token]:
    """
    Tokenizes an expression string into tokens.

    Args:
        source: The expression string to tokenize
        limits: Optional expression limits

    Returns:
        List of tokens

    Raises:
        TokenizerError: If the expression contains invalid tokens
    """
    tokenizer = Tokenizer(source, limits)
    return tokenizer.tokenize()

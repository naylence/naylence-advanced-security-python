"""
Error types for the expression evaluation engine.

All expression errors extend ExpressionError for consistent handling.
"""

from typing import Optional


class ExpressionError(Exception):
    """
    Base error class for all expression-related errors.
    """

    def __init__(
        self,
        message: str,
        position: Optional[int] = None,
        expression: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.position = position
        self.expression = expression

    def format_with_context(self) -> str:
        """
        Returns a formatted error message with position context.
        """
        if self.expression is None or self.position is None:
            return self.message

        pointer = " " * self.position + "^"
        return f"{self.message}\n  {self.expression}\n  {pointer}"


class TokenizerError(ExpressionError):
    """
    Error thrown during tokenization (lexical analysis).
    """

    pass


class ParseError(ExpressionError):
    """
    Error thrown during parsing (syntax analysis).
    """

    pass


class EvaluationError(ExpressionError):
    """
    Error thrown during evaluation (runtime error).
    """

    def __init__(
        self,
        message: str,
        position: Optional[int] = None,
        expression: Optional[str] = None,
        path: Optional[str] = None,
    ):
        super().__init__(message, position, expression)
        self.path = path


class TypeError(EvaluationError):
    """
    Error thrown for type mismatches during evaluation.
    """

    def __init__(
        self,
        expected: str,
        actual: str,
        position: Optional[int] = None,
        expression: Optional[str] = None,
    ):
        message = f"Type error: expected {expected}, got {actual}"
        super().__init__(message, position, expression)
        self.expected = expected
        self.actual = actual


class LimitExceededError(ExpressionError):
    """
    Error thrown when expression limits are exceeded.
    """

    def __init__(self, limit_name: str, limit: int, actual: int):
        message = f"Limit exceeded: {limit_name} (limit: {limit}, actual: {actual})"
        super().__init__(message)
        self.limit_name = limit_name
        self.limit = limit
        self.actual = actual


class BuiltinError(EvaluationError):
    """
    Error thrown when a built-in function encounters an error.
    """

    def __init__(
        self,
        function_name: str,
        message: str,
        position: Optional[int] = None,
        expression: Optional[str] = None,
    ):
        full_message = f"{function_name}: {message}"
        super().__init__(full_message, position, expression)
        self.function_name = function_name

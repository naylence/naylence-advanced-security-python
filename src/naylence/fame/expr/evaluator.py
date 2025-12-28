"""
Expression evaluator.

Evaluates an AST against a set of variable bindings and returns a value.

Null handling semantics:
- None values are the canonical null value throughout evaluation.
- Missing identifiers evaluate to None.
- Member access on None or non-dict returns None.
- Missing properties return None.
"""

from dataclasses import dataclass
from typing import Mapping, Optional, Tuple, cast

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
    NumberLiteralNode,
    StringLiteralNode,
    TernaryOpNode,
    UnaryOperator,
    UnaryOpNode,
)
from .builtins import (
    BUILTIN_FUNCTIONS,
    BuiltinContext,
    ExprValue,
    FunctionRegistry,
    call_builtin,
    get_type_name,
    normalize_js_value,
)
from .errors import EvaluationError
from .errors import TypeError as ExprTypeError
from .limits import DEFAULT_EXPRESSION_LIMITS, ExpressionLimits


@dataclass
class EvaluationContext:
    """Evaluation context with variable bindings."""

    bindings: Mapping[str, ExprValue]
    """Variable bindings available to expressions."""

    limits: Optional[ExpressionLimits] = None
    """Expression limits."""

    source: Optional[str] = None
    """Source expression for error reporting."""

    functions: Optional[FunctionRegistry] = None
    """Function registry for built-ins and injected helpers."""


@dataclass
class EvaluationResult:
    """Result of expression evaluation with trace information."""

    value: ExprValue
    """The evaluated value."""

    success: bool
    """Whether evaluation succeeded."""

    error: Optional[str] = None
    """Error message if evaluation failed."""


class Evaluator:
    """Evaluates an AST node and returns the result."""

    def __init__(self, context: EvaluationContext):
        self._context = context
        self._limits = context.limits or DEFAULT_EXPRESSION_LIMITS
        self._source = context.source or ""
        self._functions = context.functions or BUILTIN_FUNCTIONS
        self._member_access_depth = 0

    def evaluate(self, node: AstNode) -> ExprValue:
        """Evaluates an AST node and returns the value."""
        node_type = node.type

        if node_type == "StringLiteral":
            return cast(StringLiteralNode, node).value

        if node_type == "NumberLiteral":
            return cast(NumberLiteralNode, node).value

        if node_type == "BooleanLiteral":
            return cast(BooleanLiteralNode, node).value

        if node_type == "NullLiteral":
            return None

        if node_type == "ArrayLiteral":
            return [self.evaluate(e) for e in cast(ArrayLiteralNode, node).elements]

        if node_type == "Identifier":
            n = cast(IdentifierNode, node)
            return self._evaluate_identifier(n.name, n.position)

        if node_type == "MemberAccess":
            return self._evaluate_member_access(cast(MemberAccessNode, node))

        if node_type == "IndexAccess":
            return self._evaluate_index_access(cast(IndexAccessNode, node))

        if node_type == "FunctionCall":
            return self._evaluate_function_call(cast(FunctionCallNode, node))

        if node_type == "UnaryOp":
            n = cast(UnaryOpNode, node)
            return self._evaluate_unary_op(n.operator, n.operand, n.position)

        if node_type == "BinaryOp":
            n = cast(BinaryOpNode, node)
            return self._evaluate_binary_op(
                n.operator, n.left, n.right, n.position
            )

        if node_type == "TernaryOp":
            ternary_node = cast(TernaryOpNode, node)
            return self._evaluate_ternary_op(
                ternary_node.condition,
                ternary_node.consequent,
                ternary_node.alternate,
                ternary_node.position
            )

        # Should never happen, but handle gracefully
        return None

    def evaluate_as_boolean(self, node: AstNode) -> bool:
        """Evaluates as boolean with strict type checking."""
        value = self.evaluate(node)
        if not isinstance(value, bool):
            raise ExprTypeError("boolean", get_type_name(value), node.position, self._source)
        return value

    def _evaluate_identifier(self, name: str, _position: int) -> ExprValue:
        """Evaluates an identifier reference."""
        # Check if it's a top-level binding
        if name in self._context.bindings:
            # Normalize the value to ensure consistent types
            return normalize_js_value(self._context.bindings[name])

        # Unknown identifier evaluates to None (missing field)
        return None

    def _evaluate_member_access(self, node: MemberAccessNode) -> ExprValue:
        """Evaluates member access (obj.property)."""
        # Check member access depth
        self._member_access_depth += 1
        if self._member_access_depth > self._limits.max_member_access_depth:
            raise EvaluationError(
                f"Member access depth {self._member_access_depth} exceeds limit of "
                f"{self._limits.max_member_access_depth}",
                node.position,
                self._source,
            )

        try:
            obj = self.evaluate(node.object)

            # Null-safe member access: None.foo -> None
            if obj is None:
                return None

            # Must be a dict-like object (not primitive, not list)
            if not isinstance(obj, dict):
                # Type mismatch during access returns None (not error)
                return None

            if node.property in obj:
                # Normalize the value
                return normalize_js_value(obj[node.property])

            # Missing property evaluates to None
            return None
        finally:
            self._member_access_depth -= 1

    def _evaluate_index_access(self, node: IndexAccessNode) -> ExprValue:
        """Evaluates index access (obj[index])."""
        obj = self.evaluate(node.object)
        index = self.evaluate(node.index)

        # Null-safe index access: None[0] -> None
        if obj is None:
            return None

        # Array access with numeric index
        if isinstance(obj, list | tuple):
            if not isinstance(index, int | float):
                raise ExprTypeError(
                    "number", get_type_name(index), node.position, self._source
                )
            int_index = int(index)
            if int_index < 0 or int_index >= len(obj):
                # Out of bounds evaluates to None
                return None
            # Normalize array element
            return normalize_js_value(obj[int_index])

        # Object access with string key
        if isinstance(obj, dict):
            if not isinstance(index, str):
                raise ExprTypeError(
                    "string", get_type_name(index), node.position, self._source
                )
            if index in obj:
                # Normalize the value
                return normalize_js_value(obj[index])
            # Missing key evaluates to None
            return None

        # Type mismatch during access returns None
        return None

    def _evaluate_function_call(self, node: FunctionCallNode) -> ExprValue:
        """Evaluates a function call."""
        # Evaluate arguments
        args = [self.evaluate(arg) for arg in node.args]

        builtin_context = BuiltinContext(
            limits=self._limits,
            position=node.position,
            source=self._source,
        )

        return call_builtin(node.name, args, builtin_context, self._functions)

    def _evaluate_unary_op(
        self, operator: UnaryOperator, operand: AstNode, position: int
    ) -> ExprValue:
        """Evaluates a unary operation."""
        value = self.evaluate(operand)

        if operator == "!":
            if not isinstance(value, bool):
                raise ExprTypeError(
                    "boolean", get_type_name(value), position, self._source
                )
            return not value

        if operator == "-":
            if not isinstance(value, int | float):
                raise ExprTypeError(
                    "number", get_type_name(value), position, self._source
                )
            return -value

        # Should never happen
        return None

    def _evaluate_binary_op(
        self,
        operator: BinaryOperator,
        left: AstNode,
        right: AstNode,
        position: int,
    ) -> ExprValue:
        """Evaluates a binary operation."""
        # Short-circuit evaluation for logical operators
        if operator == "&&":
            left_value = self.evaluate(left)
            if not isinstance(left_value, bool):
                raise ExprTypeError(
                    "boolean", get_type_name(left_value), left.position, self._source
                )
            if not left_value:
                return False

            right_value = self.evaluate(right)
            if not isinstance(right_value, bool):
                raise ExprTypeError(
                    "boolean", get_type_name(right_value), right.position, self._source
                )
            return right_value

        if operator == "||":
            left_value = self.evaluate(left)
            if not isinstance(left_value, bool):
                raise ExprTypeError(
                    "boolean", get_type_name(left_value), left.position, self._source
                )
            if left_value:
                return True

            right_value = self.evaluate(right)
            if not isinstance(right_value, bool):
                raise ExprTypeError(
                    "boolean", get_type_name(right_value), right.position, self._source
                )
            return right_value

        # Eager evaluation for other operators
        left_value = self.evaluate(left)
        right_value = self.evaluate(right)

        # Arithmetic operators
        if operator == "+":
            if isinstance(left_value, str) and isinstance(right_value, str):
                return left_value + right_value
            if isinstance(left_value, int | float) and isinstance(
                right_value, int | float
            ):
                return left_value + right_value
            raise EvaluationError(
                f"Cannot add {get_type_name(left_value)} and "
                f"{get_type_name(right_value)}",
                position,
                self._source,
            )

        if operator == "-":
            if not isinstance(left_value, int | float) or not isinstance(
                right_value, int | float
            ):
                raise EvaluationError(
                    f"Cannot subtract {get_type_name(left_value)} and "
                    f"{get_type_name(right_value)}",
                    position,
                    self._source,
                )
            return left_value - right_value

        if operator == "*":
            if not isinstance(left_value, int | float) or not isinstance(
                right_value, int | float
            ):
                raise EvaluationError(
                    f"Cannot multiply {get_type_name(left_value)} and "
                    f"{get_type_name(right_value)}",
                    position,
                    self._source,
                )
            return left_value * right_value

        if operator == "/":
            if not isinstance(left_value, int | float) or not isinstance(
                right_value, int | float
            ):
                raise EvaluationError(
                    f"Cannot divide {get_type_name(left_value)} and "
                    f"{get_type_name(right_value)}",
                    position,
                    self._source,
                )
            if right_value == 0:
                raise EvaluationError("Division by zero", position, self._source)
            return left_value / right_value

        if operator == "%":
            if not isinstance(left_value, int | float) or not isinstance(
                right_value, int | float
            ):
                raise EvaluationError(
                    f"Cannot compute modulo of {get_type_name(left_value)} and "
                    f"{get_type_name(right_value)}",
                    position,
                    self._source,
                )
            if right_value == 0:
                raise EvaluationError("Modulo by zero", position, self._source)
            return left_value % right_value

        # Comparison operators
        if operator in ("<", "<=", ">", ">="):
            return self._evaluate_comparison(
                operator, left_value, right_value, position
            )

        # Equality operators
        if operator == "==":
            return self._values_equal(left_value, right_value)

        if operator == "!=":
            return not self._values_equal(left_value, right_value)

        # Membership operators
        if operator == "in":
            return self._evaluate_in(left_value, right_value, position)

        if operator == "not in":
            return not self._evaluate_in(left_value, right_value, position)

        # Should never happen
        return None

    def _evaluate_comparison(
        self,
        operator: str,
        left: ExprValue,
        right: ExprValue,
        position: int,
    ) -> bool:
        """Evaluates a comparison operation."""
        # Numbers
        if isinstance(left, int | float) and isinstance(right, int | float):
            if operator == "<":
                return left < right
            if operator == "<=":
                return left <= right
            if operator == ">":
                return left > right
            if operator == ">=":
                return left >= right

        # Strings
        if isinstance(left, str) and isinstance(right, str):
            if operator == "<":
                return left < right
            if operator == "<=":
                return left <= right
            if operator == ">":
                return left > right
            if operator == ">=":
                return left >= right

        raise EvaluationError(
            f"Cannot compare {get_type_name(left)} and "
            f"{get_type_name(right)} with {operator}",
            position,
            self._source,
        )

    def _evaluate_in(
        self, left: ExprValue, right: ExprValue, position: int
    ) -> bool:
        """Evaluates an 'in' membership operation."""
        # String in string (substring check)
        if isinstance(left, str) and isinstance(right, str):
            return left in right

        # Value in array
        if isinstance(right, list | tuple):
            return any(self._values_equal(left, item) for item in right)

        # Key in object
        if isinstance(right, dict):
            if not isinstance(left, str):
                raise EvaluationError(
                    f"Cannot check if {get_type_name(left)} is a key in object "
                    "(expected string)",
                    position,
                    self._source,
                )
            return left in right

        raise EvaluationError(
            f"Cannot check membership: {get_type_name(left)} in "
            f"{get_type_name(right)}",
            position,
            self._source,
        )

    def _evaluate_ternary_op(
        self,
        condition: AstNode,
        consequent: AstNode,
        alternate: AstNode,
        _position: int,
    ) -> ExprValue:
        """Evaluates a ternary conditional operation."""
        cond_value = self.evaluate(condition)

        if not isinstance(cond_value, bool):
            raise ExprTypeError(
                "boolean",
                get_type_name(cond_value),
                condition.position,
                self._source,
            )

        return self.evaluate(consequent) if cond_value else self.evaluate(alternate)

    def _values_equal(self, a: ExprValue, b: ExprValue) -> bool:
        """Deep equality check for expression values."""
        # Identical primitives or same reference
        if a is b:
            return True

        # Type mismatch (allow int/float comparison)
        if not isinstance(a, type(b)):
            # Special case: numbers can be compared across int/float
            if isinstance(a, int | float) and isinstance(b, int | float):
                return a == b
            return False

        # None check (both must be None if one is)
        if a is None or b is None:
            return False

        # Lists
        if isinstance(a, list | tuple) and isinstance(b, list | tuple):
            if len(a) != len(b):
                return False
            for i in range(len(a)):
                if not self._values_equal(a[i], b[i]):
                    return False
            return True

        # Dicts
        if isinstance(a, dict) and isinstance(b, dict):
            a_keys = set(a.keys())
            b_keys = set(b.keys())
            if a_keys != b_keys:
                return False
            for key in a_keys:
                if not self._values_equal(a[key], b[key]):
                    return False
            return True

        # Primitive comparison
        return a == b


def evaluate(ast: AstNode, context: EvaluationContext) -> EvaluationResult:
    """
    Evaluates an AST against a context and returns the result.

    Args:
        ast: The AST to evaluate
        context: The evaluation context with bindings

    Returns:
        The evaluation result with value and success status
    """
    try:
        evaluator = Evaluator(context)
        value = evaluator.evaluate(ast)
        return EvaluationResult(value=value, success=True)
    except Exception as error:
        message = str(error)
        return EvaluationResult(value=None, success=False, error=message)


def evaluate_as_boolean(
    ast: AstNode, context: EvaluationContext
) -> Tuple[bool, Optional[str]]:
    """
    Evaluates an AST as a boolean condition.

    Args:
        ast: The AST to evaluate
        context: The evaluation context with bindings

    Returns:
        Tuple of (value, error_message). Value is False if evaluation fails.
    """
    try:
        evaluator = Evaluator(context)
        value = evaluator.evaluate_as_boolean(ast)
        return (value, None)
    except Exception as error:
        message = str(error)
        return (False, message)

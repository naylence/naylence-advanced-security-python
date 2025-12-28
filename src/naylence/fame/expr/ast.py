"""
Abstract Syntax Tree (AST) node types for the expression language.

The AST is produced by the parser and consumed by the evaluator.
"""

from abc import ABC
from dataclasses import dataclass
from typing import Literal, Sequence, Union

# ============================================================
# Operator Types
# ============================================================

UnaryOperator = Literal["!", "-"]

BinaryOperator = Literal[
    "*",
    "/",
    "%",
    "+",
    "-",
    "<",
    "<=",
    ">",
    ">=",
    "==",
    "!=",
    "in",
    "not in",
    "&&",
    "||",
]


# ============================================================
# AST Node Types
# ============================================================


@dataclass(frozen=True)
class AstNodeBase(ABC):
    """Base class for all AST nodes."""

    position: int
    """Position in source expression (for error reporting)."""


@dataclass(frozen=True)
class StringLiteralNode(AstNodeBase):
    """String literal node."""

    value: str

    @property
    def type(self) -> Literal["StringLiteral"]:
        return "StringLiteral"


@dataclass(frozen=True)
class NumberLiteralNode(AstNodeBase):
    """Number literal node."""

    value: float

    @property
    def type(self) -> Literal["NumberLiteral"]:
        return "NumberLiteral"


@dataclass(frozen=True)
class BooleanLiteralNode(AstNodeBase):
    """Boolean literal node."""

    value: bool

    @property
    def type(self) -> Literal["BooleanLiteral"]:
        return "BooleanLiteral"


@dataclass(frozen=True)
class NullLiteralNode(AstNodeBase):
    """Null literal node."""

    @property
    def type(self) -> Literal["NullLiteral"]:
        return "NullLiteral"


@dataclass(frozen=True)
class ArrayLiteralNode(AstNodeBase):
    """Array literal node."""

    elements: Sequence["AstNode"]

    @property
    def type(self) -> Literal["ArrayLiteral"]:
        return "ArrayLiteral"


@dataclass(frozen=True)
class IdentifierNode(AstNodeBase):
    """Identifier node."""

    name: str

    @property
    def type(self) -> Literal["Identifier"]:
        return "Identifier"


@dataclass(frozen=True)
class MemberAccessNode(AstNodeBase):
    """Member access node (e.g., obj.property)."""

    object: "AstNode"
    property: str

    @property
    def type(self) -> Literal["MemberAccess"]:
        return "MemberAccess"


@dataclass(frozen=True)
class IndexAccessNode(AstNodeBase):
    """Index access node (e.g., arr[0])."""

    object: "AstNode"
    index: "AstNode"

    @property
    def type(self) -> Literal["IndexAccess"]:
        return "IndexAccess"


@dataclass(frozen=True)
class FunctionCallNode(AstNodeBase):
    """Function call node."""

    name: str
    args: Sequence["AstNode"]

    @property
    def type(self) -> Literal["FunctionCall"]:
        return "FunctionCall"


@dataclass(frozen=True)
class UnaryOpNode(AstNodeBase):
    """Unary operator node."""

    operator: UnaryOperator
    operand: "AstNode"

    @property
    def type(self) -> Literal["UnaryOp"]:
        return "UnaryOp"


@dataclass(frozen=True)
class BinaryOpNode(AstNodeBase):
    """Binary operator node."""

    operator: BinaryOperator
    left: "AstNode"
    right: "AstNode"

    @property
    def type(self) -> Literal["BinaryOp"]:
        return "BinaryOp"


@dataclass(frozen=True)
class TernaryOpNode(AstNodeBase):
    """Ternary operator node (condition ? consequent : alternate)."""

    condition: "AstNode"
    consequent: "AstNode"
    alternate: "AstNode"

    @property
    def type(self) -> Literal["TernaryOp"]:
        return "TernaryOp"


# Union type for all AST nodes
AstNode = Union[
    StringLiteralNode,
    NumberLiteralNode,
    BooleanLiteralNode,
    NullLiteralNode,
    ArrayLiteralNode,
    IdentifierNode,
    MemberAccessNode,
    IndexAccessNode,
    FunctionCallNode,
    UnaryOpNode,
    BinaryOpNode,
    TernaryOpNode,
]


# ============================================================
# AST Utilities
# ============================================================


def count_ast_nodes(node: AstNode) -> int:
    """Counts the total number of nodes in an AST."""
    count = 1

    if node.type in ("StringLiteral", "NumberLiteral", "BooleanLiteral", "NullLiteral", "Identifier"):
        return count

    if node.type == "ArrayLiteral":
        node = node  # type: ArrayLiteralNode
        for element in node.elements:
            count += count_ast_nodes(element)
        return count

    if node.type == "MemberAccess":
        node = node  # type: MemberAccessNode
        return count + count_ast_nodes(node.object)

    if node.type == "IndexAccess":
        node = node  # type: IndexAccessNode
        return count + count_ast_nodes(node.object) + count_ast_nodes(node.index)

    if node.type == "FunctionCall":
        node = node  # type: FunctionCallNode
        for arg in node.args:
            count += count_ast_nodes(arg)
        return count

    if node.type == "UnaryOp":
        node = node  # type: UnaryOpNode
        return count + count_ast_nodes(node.operand)

    if node.type == "BinaryOp":
        node = node  # type: BinaryOpNode
        return count + count_ast_nodes(node.left) + count_ast_nodes(node.right)

    if node.type == "TernaryOp":
        node = node  # type: TernaryOpNode
        return (
            count
            + count_ast_nodes(node.condition)
            + count_ast_nodes(node.consequent)
            + count_ast_nodes(node.alternate)
        )

    return count


def calculate_ast_depth(node: AstNode) -> int:
    """Calculates the maximum depth of an AST."""
    if node.type in ("StringLiteral", "NumberLiteral", "BooleanLiteral", "NullLiteral", "Identifier"):
        return 1

    if node.type == "ArrayLiteral":
        node = node  # type: ArrayLiteralNode
        max_child_depth = 0
        for element in node.elements:
            max_child_depth = max(max_child_depth, calculate_ast_depth(element))
        return 1 + max_child_depth

    if node.type == "MemberAccess":
        node = node  # type: MemberAccessNode
        return 1 + calculate_ast_depth(node.object)

    if node.type == "IndexAccess":
        node = node  # type: IndexAccessNode
        return 1 + max(calculate_ast_depth(node.object), calculate_ast_depth(node.index))

    if node.type == "FunctionCall":
        node = node  # type: FunctionCallNode
        max_arg_depth = 0
        for arg in node.args:
            max_arg_depth = max(max_arg_depth, calculate_ast_depth(arg))
        return 1 + max_arg_depth

    if node.type == "UnaryOp":
        node = node  # type: UnaryOpNode
        return 1 + calculate_ast_depth(node.operand)

    if node.type == "BinaryOp":
        node = node  # type: BinaryOpNode
        return 1 + max(calculate_ast_depth(node.left), calculate_ast_depth(node.right))

    if node.type == "TernaryOp":
        node = node  # type: TernaryOpNode
        return 1 + max(
            calculate_ast_depth(node.condition),
            calculate_ast_depth(node.consequent),
            calculate_ast_depth(node.alternate),
        )

    return 1


def ast_to_string(node: AstNode, indent: int = 0) -> str:
    """Returns a human-readable representation of an AST node for debugging."""
    prefix = "  " * indent

    if node.type == "StringLiteral":
        node = node  # type: StringLiteralNode
        return f'{prefix}String: "{node.value}"'

    if node.type == "NumberLiteral":
        node = node  # type: NumberLiteralNode
        return f"{prefix}Number: {node.value}"

    if node.type == "BooleanLiteral":
        node = node  # type: BooleanLiteralNode
        return f"{prefix}Boolean: {node.value}"

    if node.type == "NullLiteral":
        return f"{prefix}Null"

    if node.type == "ArrayLiteral":
        node = node  # type: ArrayLiteralNode
        elements_str = "\n".join(ast_to_string(e, indent + 1) for e in node.elements)
        return f"{prefix}Array:\n{elements_str}"

    if node.type == "Identifier":
        node = node  # type: IdentifierNode
        return f"{prefix}Identifier: {node.name}"

    if node.type == "MemberAccess":
        node = node  # type: MemberAccessNode
        return f"{prefix}MemberAccess: .{node.property}\n{ast_to_string(node.object, indent + 1)}"

    if node.type == "IndexAccess":
        node = node  # type: IndexAccessNode
        return (
            f"{prefix}IndexAccess:\n"
            f"{prefix}  object:\n{ast_to_string(node.object, indent + 2)}\n"
            f"{prefix}  index:\n{ast_to_string(node.index, indent + 2)}"
        )

    if node.type == "FunctionCall":
        node = node  # type: FunctionCallNode
        args_str = "\n".join(ast_to_string(a, indent + 1) for a in node.args)
        return f"{prefix}FunctionCall: {node.name}\n{args_str}"

    if node.type == "UnaryOp":
        node = node  # type: UnaryOpNode
        return f"{prefix}UnaryOp: {node.operator}\n{ast_to_string(node.operand, indent + 1)}"

    if node.type == "BinaryOp":
        node = node  # type: BinaryOpNode
        return (
            f"{prefix}BinaryOp: {node.operator}\n"
            f"{ast_to_string(node.left, indent + 1)}\n"
            f"{ast_to_string(node.right, indent + 1)}"
        )

    if node.type == "TernaryOp":
        node = node  # type: TernaryOpNode
        return (
            f"{prefix}TernaryOp:\n"
            f"{prefix}  condition:\n{ast_to_string(node.condition, indent + 2)}\n"
            f"{prefix}  consequent:\n{ast_to_string(node.consequent, indent + 2)}\n"
            f"{prefix}  alternate:\n{ast_to_string(node.alternate, indent + 2)}"
        )

    return f"{prefix}Unknown: {node}"

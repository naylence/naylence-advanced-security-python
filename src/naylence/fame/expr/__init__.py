"""
Generic expression engine.

This module provides a deterministic, side-effect-free expression
evaluation engine with injectable built-in functions.
"""

# Core types and utilities
from .ast import (
    ArrayLiteralNode,
    AstNode,
    AstNodeBase,
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
    ast_to_string,
    calculate_ast_depth,
    count_ast_nodes,
)

# Builtins
from .builtins import (
    BUILTIN_FUNCTIONS,
    BuiltinContext,
    BuiltinFunction,
    ExprValue,
    FunctionRegistry,
    call_builtin,
    get_type_name,
    is_builtin_function,
    normalize_js_value,
)
from .errors import (
    BuiltinError,
    EvaluationError,
    ExpressionError,
    LimitExceededError,
    ParseError,
    TokenizerError,
    TypeError,
)

# Evaluator
from .evaluator import (
    EvaluationContext,
    EvaluationResult,
    Evaluator,
    evaluate,
    evaluate_as_boolean,
)
from .limits import (
    DEFAULT_EXPRESSION_LIMITS,
    ExpressionLimits,
    check_array_length,
    check_ast_depth,
    check_ast_node_count,
    check_expression_length,
    check_function_arg_count,
    check_glob_pattern_length,
    check_regex_pattern_length,
)

# Parser
from .parser import (
    Parser,
    parse,
)

# Tokenizer
from .tokenizer import (
    Token,
    Tokenizer,
    TokenType,
    tokenize,
)

__all__ = [
    # AST types
    "AstNode",
    "AstNodeBase",
    "StringLiteralNode",
    "NumberLiteralNode",
    "BooleanLiteralNode",
    "NullLiteralNode",
    "ArrayLiteralNode",
    "IdentifierNode",
    "MemberAccessNode",
    "IndexAccessNode",
    "FunctionCallNode",
    "UnaryOpNode",
    "BinaryOpNode",
    "TernaryOpNode",
    "UnaryOperator",
    "BinaryOperator",
    "count_ast_nodes",
    "calculate_ast_depth",
    "ast_to_string",
    # Errors
    "ExpressionError",
    "TokenizerError",
    "ParseError",
    "EvaluationError",
    "TypeError",
    "LimitExceededError",
    "BuiltinError",
    # Limits
    "ExpressionLimits",
    "DEFAULT_EXPRESSION_LIMITS",
    "check_expression_length",
    "check_ast_depth",
    "check_ast_node_count",
    "check_regex_pattern_length",
    "check_glob_pattern_length",
    "check_array_length",
    "check_function_arg_count",
    # Tokenizer
    "Token",
    "TokenType",
    "Tokenizer",
    "tokenize",
    # Parser
    "Parser",
    "parse",
    # Evaluator
    "EvaluationContext",
    "EvaluationResult",
    "Evaluator",
    "evaluate",
    "evaluate_as_boolean",
    # Builtins
    "ExprValue",
    "BuiltinFunction",
    "BuiltinContext",
    "FunctionRegistry",
    "BUILTIN_FUNCTIONS",
    "call_builtin",
    "is_builtin_function",
    "get_type_name",
    "normalize_js_value",
]

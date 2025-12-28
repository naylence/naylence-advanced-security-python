"""
Built-in functions for the expression language.

All built-in functions are pure and deterministic.

Null handling semantics:
- None (Python's null) is the canonical null value.
- Predicate-style builtins (starts_with, ends_with, contains, glob_match,
  regex_match, etc.) return False when passed None for required args
  instead of throwing an error.
- Wrong non-null types still raise BuiltinError to surface real bugs.
- Non-predicate operations (arithmetic, comparisons) remain strict.
"""

import re
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Union

from naylence.fame.core.util.id_generator import generate_id

from .errors import BuiltinError, EvaluationError
from .limits import ExpressionLimits, check_glob_pattern_length, check_regex_pattern_length

# Runtime value types for the expression language.
#
# Note: None is the canonical null value in Python.
ExprValue = Union[
    str,
    float,
    int,
    bool,
    None,
    Sequence["ExprValue"],
    Mapping[str, "ExprValue"],
]


class BuiltinContext:
    """Context passed to built-in functions."""

    def __init__(
        self,
        limits: ExpressionLimits,
        position: int,
        source: str,
    ):
        self.limits = limits
        self.position = position
        self.source = source


# Signature of a built-in function.
BuiltinFunction = Callable[[Sequence[ExprValue], BuiltinContext], ExprValue]

# Function registry for built-in and injected functions.
FunctionRegistry = Dict[str, BuiltinFunction]


def normalize_js_value(value: Any) -> ExprValue:
    """
    Normalizes a Python value to an ExprValue.

    Rules:
    - None -> None
    - bool/int/float/str -> returned as-is
    - list -> elements are recursively normalized
    - dict -> returned as-is (reads will normalize on access)
    - other types (function, etc.) -> None

    This ensures consistency in the expression value model.
    """
    if value is None:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, int | float):
        return value

    if isinstance(value, str):
        return value

    if isinstance(value, list | tuple):
        return [normalize_js_value(element) for element in value]

    if isinstance(value, dict):
        # Return the dict as-is; reads will normalize on access
        return value

    # Function, class, etc. -> None
    return None


def get_type_name(value: ExprValue) -> str:
    """Gets the type name of a value for error messages."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int | float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list | tuple):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _assert_string(value: ExprValue, arg_name: str, function_name: str) -> str:
    """Asserts that a value is a string."""
    if not isinstance(value, str):
        raise BuiltinError(
            function_name, f"{arg_name} must be a string, got {get_type_name(value)}"
        )
    return value


def _is_null(value: ExprValue) -> bool:
    """Checks if a value is null (for null-tolerant predicates)."""
    return value is None


def _assert_string_or_null(
    value: ExprValue, arg_name: str, function_name: str
) -> Optional[str]:
    """
    Asserts that a non-null value is a string (for null-tolerant predicates).
    Returns None if the value is null (indicating predicate should return False).
    Raises BuiltinError if the value is non-null but not a string.
    """
    if _is_null(value):
        return None
    if not isinstance(value, str):
        raise BuiltinError(
            function_name, f"{arg_name} must be a string, got {get_type_name(value)}"
        )
    return value


def _get_arg(args: Sequence[ExprValue], index: int, function_name: str) -> ExprValue:
    """Gets an argument by index, throwing if not present."""
    if index >= len(args):
        raise BuiltinError(function_name, f"missing argument at index {index}")
    return args[index]


def _assert_arg_count(
    args: Sequence[ExprValue], expected: int, function_name: str
) -> None:
    """Asserts argument count."""
    if len(args) != expected:
        raise BuiltinError(
            function_name, f"expected {expected} argument(s), got {len(args)}"
        )


def _assert_arg_count_range(
    args: Sequence[ExprValue], min_count: int, max_count: int, function_name: str
) -> None:
    """Asserts argument count range."""
    if len(args) < min_count or len(args) > max_count:
        raise BuiltinError(
            function_name,
            f"expected {min_count}-{max_count} argument(s), got {len(args)}",
        )


# ============================================================
# String Helpers
# ============================================================


def _lower(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
    """lower(s: string) -> string - Returns the lowercase version of the string."""
    _assert_arg_count(args, 1, "lower")
    s = _get_arg(args, 0, "lower")
    _assert_string(s, "s", "lower")
    return s.lower()


def _upper(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
    """upper(s: string) -> string - Returns the uppercase version of the string."""
    _assert_arg_count(args, 1, "upper")
    s = _get_arg(args, 0, "upper")
    _assert_string(s, "s", "upper")
    return s.upper()


def _starts_with(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
    """
    starts_with(s: string, prefix: string) -> bool

    Returns True if the string starts with the prefix.
    Null-tolerant: returns False if either argument is null.
    """
    _assert_arg_count(args, 2, "starts_with")
    s = _get_arg(args, 0, "starts_with")
    prefix = _get_arg(args, 1, "starts_with")

    # Null-tolerant: return False if either arg is null
    s_str = _assert_string_or_null(s, "s", "starts_with")
    if s_str is None:
        return False
    prefix_str = _assert_string_or_null(prefix, "prefix", "starts_with")
    if prefix_str is None:
        return False

    return s_str.startswith(prefix_str)


def _ends_with(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
    """
    ends_with(s: string, suffix: string) -> bool

    Returns True if the string ends with the suffix.
    Null-tolerant: returns False if either argument is null.
    """
    _assert_arg_count(args, 2, "ends_with")
    s = _get_arg(args, 0, "ends_with")
    suffix = _get_arg(args, 1, "ends_with")

    # Null-tolerant: return False if either arg is null
    s_str = _assert_string_or_null(s, "s", "ends_with")
    if s_str is None:
        return False
    suffix_str = _assert_string_or_null(suffix, "suffix", "ends_with")
    if suffix_str is None:
        return False

    return s_str.endswith(suffix_str)


def _contains(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
    """
    contains(s: string, substring: string) -> bool

    Returns True if the string contains the substring.
    Null-tolerant: returns False if either argument is null.
    """
    _assert_arg_count(args, 2, "contains")
    s = _get_arg(args, 0, "contains")
    substring = _get_arg(args, 1, "contains")

    # Null-tolerant: return False if either arg is null
    s_str = _assert_string_or_null(s, "s", "contains")
    if s_str is None:
        return False
    substring_str = _assert_string_or_null(substring, "substring", "contains")
    if substring_str is None:
        return False

    return substring_str in s_str


def _split(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
    """split(s: string, separator: string) -> string[] - Splits the string by the separator."""
    _assert_arg_count_range(args, 1, 2, "split")
    s = _get_arg(args, 0, "split")
    _assert_string(s, "s", "split")

    separator = args[1] if len(args) >= 2 else " "
    _assert_string(separator, "separator", "split")

    return s.split(separator)


def _trim(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
    """
    trim(s: string) -> string

    Trims whitespace from both ends of a string.
    Returns an empty string if s is null (for convenient composition).
    Throws BuiltinError if s is non-null but not a string.
    """
    _assert_arg_count(args, 1, "trim")
    s = _get_arg(args, 0, "trim")

    # Null-friendly: return empty string for null
    if s is None:
        return ""

    # Strict type check for non-null values
    if not isinstance(s, str):
        raise BuiltinError("trim", f"s must be a string, got {get_type_name(s)}")

    return s.strip()


# ============================================================
# Collection Helpers
# ============================================================


def _len(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
    """len(x: string | array) -> number - Returns the length of a string or array."""
    _assert_arg_count(args, 1, "len")
    x = _get_arg(args, 0, "len")

    if isinstance(x, str):
        return len(x)

    if isinstance(x, list | tuple):
        return len(x)

    raise BuiltinError("len", f"expected string or array, got {get_type_name(x)}")


# ============================================================
# Generic Helpers
# ============================================================


def _exists(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
    """
    exists(x: any) -> bool

    Returns True if the value is not null.
    Missing bindings and missing properties evaluate to null, so this
    can be used to check for presence.
    """
    _assert_arg_count(args, 1, "exists")
    x = _get_arg(args, 0, "exists")
    return x is not None


def _coalesce(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
    """
    coalesce(a: any, b: any) -> any

    Returns a if it is not null, otherwise returns b.
    This is useful for providing default values.
    """
    _assert_arg_count(args, 2, "coalesce")
    a = _get_arg(args, 0, "coalesce")
    b = _get_arg(args, 1, "coalesce")
    return a if a is not None else b


def _secure_hash(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
    """
    secure_hash(input_str: string, length: number) -> string

    Generates a deterministic secure hash/fingerprint of the input string.
    Uses SHA-256 hashing to create a stable identifier of the specified length.
    Returns base62-encoded string (alphanumeric, case-sensitive).
    Automatically rehashes if result contains blacklisted words.
    Returns empty string if input_str is null (for convenient composition).
    Throws BuiltinError if input_str is non-null but not a string, or if length is invalid.
    """
    _assert_arg_count(args, 2, "secure_hash")
    input_str = _get_arg(args, 0, "secure_hash")
    length = _get_arg(args, 1, "secure_hash")

    # Null-friendly: return empty string for null input
    if input_str is None:
        return ""

    # Strict type check for input_str
    if not isinstance(input_str, str):
        raise BuiltinError(
            "secure_hash", f"input_str must be a string, got {get_type_name(input_str)}"
        )

    # Strict type check for length
    if not isinstance(length, int | float):
        raise BuiltinError(
            "secure_hash", f"length must be a number, got {get_type_name(length)}"
        )

    # Validate length is a positive integer
    if not (isinstance(length, int) or length == int(length)) or int(length) <= 0:
        raise BuiltinError(
            "secure_hash", f"length must be a positive integer, got {length}"
        )

    length_int = int(length)

    # Use generate_id from naylence.fame.core with fingerprint mode
    # This provides SHA-256 hashing, base62 encoding, and profanity filtering
    return generate_id(
        length=length_int,
        mode="fingerprint",
        material=input_str,
        hash_alg="sha256",
    )


# ============================================================
# Pattern Helpers
# ============================================================


def _escape_regex(s: str) -> str:
    """Escapes special regex characters in a string."""
    return re.escape(s)


def _glob_to_regex(glob: str) -> str:
    """Converts a glob pattern to a regex pattern."""
    parts: List[str] = []
    i = 0

    while i < len(glob):
        ch = glob[i]
        if ch == "*":
            if i + 1 < len(glob) and glob[i + 1] == "*":
                # `**` matches any characters
                parts.append(".*")
                i += 2
            else:
                # `*` matches any characters except dots
                parts.append("[^.]*")
                i += 1
        elif ch == "?":
            # `?` matches a single character
            parts.append("[^.]")
            i += 1
        else:
            parts.append(re.escape(ch))
            i += 1

    return "".join(parts)


def _glob_match(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
    """
    glob_match(value: string, pattern: string) -> bool

    Returns True if the value matches the glob pattern.
    Glob syntax: * (single segment), ** (any depth), ? (single char)
    Null-tolerant: returns False if either argument is null.
    """
    _assert_arg_count(args, 2, "glob_match")
    value = _get_arg(args, 0, "glob_match")
    pattern = _get_arg(args, 1, "glob_match")

    # Null-tolerant: return False if either arg is null
    value_str = _assert_string_or_null(value, "value", "glob_match")
    if value_str is None:
        return False
    pattern_str = _assert_string_or_null(pattern, "pattern", "glob_match")
    if pattern_str is None:
        return False

    # Validate pattern length
    check_glob_pattern_length(pattern_str, ctx.limits)

    # Convert glob to regex
    regex_pattern = f"^{_glob_to_regex(pattern_str)}$"

    try:
        regex = re.compile(regex_pattern)
        return bool(regex.match(value_str))
    except re.error:
        raise BuiltinError("glob_match", f"invalid glob pattern: {pattern_str}")


def _is_safe_regex(pattern: str) -> bool:
    """
    Detects potentially catastrophic regex patterns.

    This is a best-effort heuristic check for common ReDoS patterns.
    """
    # Check for obvious catastrophic patterns:
    # - Nested quantifiers: (a+)+, (a*)*
    # - Overlapping alternation with quantifiers: (a|a)+

    # Simple heuristic: reject patterns with nested quantifiers
    nested_quantifiers = re.compile(r"([+*?]|\{\d+,?\d*\})\s*\)\s*([+*?]|\{\d+,?\d*\})")
    if nested_quantifiers.search(pattern):
        return False

    # Reject patterns with excessive backtracking potential
    excessive_backtracking = re.compile(r"(\.\*){3,}|(\.\+){3,}")
    if excessive_backtracking.search(pattern):
        return False

    return True


def _regex_match(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
    """
    regex_match(value: string, pattern: string) -> bool

    Returns True if the value matches the regex pattern.
    The pattern is anchored (full match).
    Null-tolerant: returns False if either argument is null.
    """
    _assert_arg_count(args, 2, "regex_match")
    value = _get_arg(args, 0, "regex_match")
    pattern = _get_arg(args, 1, "regex_match")

    # Null-tolerant: return False if either arg is null
    value_str = _assert_string_or_null(value, "value", "regex_match")
    if value_str is None:
        return False
    pattern_str = _assert_string_or_null(pattern, "pattern", "regex_match")
    if pattern_str is None:
        return False

    # Validate pattern length
    check_regex_pattern_length(pattern_str, ctx.limits)

    # Check for potentially unsafe patterns
    if not _is_safe_regex(pattern_str):
        raise BuiltinError(
            "regex_match", f"pattern may cause excessive backtracking: {pattern_str}"
        )

    # Anchor the pattern for full match
    if pattern_str.startswith("^") or pattern_str.endswith("$"):
        anchored_pattern = pattern_str
    else:
        anchored_pattern = f"^(?:{pattern_str})$"

    try:
        regex = re.compile(anchored_pattern)
        return bool(regex.match(value_str))
    except re.error as e:
        raise BuiltinError(
            "regex_match", f"invalid regex pattern: {pattern_str} - {str(e)}"
        )


# ============================================================
# Registry
# ============================================================

# Registry of all built-in functions.
BUILTIN_FUNCTIONS: FunctionRegistry = {
    # String helpers
    "lower": _lower,
    "upper": _upper,
    "starts_with": _starts_with,
    "ends_with": _ends_with,
    "contains": _contains,
    "split": _split,
    "trim": _trim,
    # Collection helpers
    "len": _len,
    # Generic helpers
    "exists": _exists,
    "coalesce": _coalesce,
    "secure_hash": _secure_hash,
    # Pattern helpers
    "glob_match": _glob_match,
    "regex_match": _regex_match,
}


def call_builtin(
    name: str,
    args: Sequence[ExprValue],
    context: BuiltinContext,
    functions: Optional[FunctionRegistry] = None,
) -> ExprValue:
    """
    Calls a built-in function by name.

    Args:
        name: The function name
        args: The function arguments
        context: The evaluation context
        functions: Optional function registry (defaults to BUILTIN_FUNCTIONS)

    Returns:
        The function result

    Raises:
        BuiltinError: If the function doesn't exist or fails
    """
    functions = functions or BUILTIN_FUNCTIONS
    fn = functions.get(name)
    if fn is None:
        raise EvaluationError(
            f"Unknown function: {name}", context.position, context.source
        )
    return fn(args, context)


def is_builtin_function(
    name: str, functions: Optional[FunctionRegistry] = None
) -> bool:
    """Checks if a name is a built-in function."""
    functions = functions or BUILTIN_FUNCTIONS
    return name in functions

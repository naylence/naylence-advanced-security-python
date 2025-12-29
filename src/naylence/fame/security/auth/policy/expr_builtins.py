"""
Authorization-specific expression built-ins.

Null handling semantics:
- Scope predicate builtins (has_scope, has_any_scope, has_all_scopes)
  return False when passed None for required args.
- Security predicate builtins (is_signed, is_encrypted, is_encrypted_at_least)
  return False when the envelope lacks the required security posture.
- Wrong non-null types still raise BuiltinError to surface real bugs.
"""

from typing import Any, List, Literal, Optional, Sequence, TypedDict, Union

from naylence.fame.expr.builtins import (
    BUILTIN_FUNCTIONS,
    BuiltinContext,
    ExprValue,
    FunctionRegistry,
    get_type_name,
)
from naylence.fame.expr.errors import BuiltinError

# Encryption level type for normalized security posture
EncryptionLevel = Literal["plaintext", "channel", "sealed", "unknown"]


# Valid encryption levels for is_encrypted_at_least comparisons
VALID_ENCRYPTION_LEVELS: tuple[str, ...] = ("plaintext", "channel", "sealed")


# Encryption level ordering for comparison (higher number = stronger encryption)
ENCRYPTION_LEVEL_ORDER: dict[str, int] = {
    "plaintext": 0,
    "channel": 1,
    "sealed": 2,
}


def normalize_encryption_level_from_alg(alg: Optional[str]) -> EncryptionLevel:
    """
    Normalizes an encryption algorithm string to an EncryptionLevel.

    Mapping rules:
    - None => "plaintext" (no encryption present)
    - alg contains "-channel" => "channel" (e.g., "chacha20-poly1305-channel")
    - alg contains "-sealed" => "sealed" (explicit sealed marker)
    - alg matches ECDH-ES pattern with AEAD cipher => "sealed" (e.g., "ECDH-ES+A256GCM")
    - otherwise => "unknown"

    Currently supported algorithms:
    - Channel: "chacha20-poly1305-channel"
    - Sealed: "ECDH-ES+A256GCM"

    This helper is centralized to ensure consistent mapping across TS and Python.
    """
    if alg is None:
        return "plaintext"

    alg_lower = alg.lower()

    # Check for channel encryption (e.g., "chacha20-poly1305-channel")
    # Must check before other patterns since channel suffix is explicit
    if "-channel" in alg_lower:
        return "channel"

    # Check for explicit sealed marker
    if "-sealed" in alg_lower:
        return "sealed"

    # ECDH-ES key agreement with AEAD cipher => sealed encryption
    # Pattern: "ECDH-ES+A256GCM", "ECDH-ES+A128GCM", etc.
    if alg_lower.startswith("ecdh-es") and "+a" in alg_lower:
        return "sealed"

    return "unknown"


class SignatureBindings(TypedDict):
    """Signature metadata bindings."""

    present: bool
    kid: Optional[str]


class EncryptionBindings(TypedDict):
    """Encryption metadata bindings."""

    present: bool
    alg: Optional[str]
    kid: Optional[str]
    level: EncryptionLevel


class SecurityBindings(TypedDict):
    """Security metadata bindings exposed to expressions."""

    sig: SignatureBindings
    enc: EncryptionBindings


def create_security_bindings(
    sec: Optional[dict[str, Any]] = None,
) -> SecurityBindings:
    """
    Creates security bindings from an envelope's sec header.
    Exposes only metadata, never raw values like sig.val or enc.val.

    Args:
        sec: The envelope.sec dict, may contain 'sig' and 'enc' sub-dicts.

    Returns:
        SecurityBindings with normalized metadata for expression evaluation.
    """
    sig_present = sec is not None and sec.get("sig") is not None
    enc_present = sec is not None and sec.get("enc") is not None

    sig_data = sec.get("sig", {}) if sec else {}
    enc_data = sec.get("enc", {}) if sec else {}

    return {
        "sig": {
            "present": sig_present,
            "kid": sig_data.get("kid") if sig_data else None,
        },
        "enc": {
            "present": enc_present,
            "alg": enc_data.get("alg") if enc_data else None,
            "kid": enc_data.get("kid") if enc_data else None,
            "level": (
                normalize_encryption_level_from_alg(enc_data.get("alg"))
                if enc_present
                else "plaintext"
            ),
        },
    }


def _is_null(value: ExprValue) -> bool:
    """Checks if a value is null."""
    return value is None


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


def _assert_string_or_null(
    value: ExprValue, arg_name: str, function_name: str
) -> Optional[str]:
    """
    Asserts that a non-null value is a string (for null-tolerant predicates).
    Returns None if the value is null (indicating predicate should return false).
    Throws BuiltinError if the value is non-null but not a string.
    """
    if _is_null(value):
        return None
    if not isinstance(value, str):
        raise BuiltinError(
            function_name, f"{arg_name} must be a string, got {get_type_name(value)}"
        )
    return value


def _assert_string_array_or_null(
    value: ExprValue, arg_name: str, function_name: str
) -> Optional[List[str]]:
    """
    Asserts that a non-null value is an array of strings (for null-tolerant predicates).
    Returns None if the value is null (indicating predicate should return false).
    Throws BuiltinError if the value is non-null but not a string array.
    """
    if _is_null(value):
        return None
    if not isinstance(value, list | tuple):
        raise BuiltinError(
            function_name,
            f"{arg_name} must be an array of strings, got {get_type_name(value)}",
        )
    result: List[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str):
            raise BuiltinError(
                function_name,
                f"{arg_name}[{i}] must be a string, got {get_type_name(item)}",
            )
        result.append(item)
    return result


class AuthFunctionRegistryOptions(TypedDict, total=False):
    """Options for creating an auth function registry."""

    granted_scopes: Sequence[str]
    """Granted scopes for scope checking builtins."""

    security_bindings: SecurityBindings
    """Security bindings for security posture builtins."""


def create_auth_function_registry(
    granted_scopes_or_options: Union[
        Optional[Sequence[str]], AuthFunctionRegistryOptions
    ] = None,
) -> FunctionRegistry:
    """
    Creates a function registry with auth helpers installed.

    This registry extends the base builtins with:
    - Scope builtins: has_scope, has_any_scope, has_all_scopes
    - Security builtins: is_signed, encryption_level, is_encrypted, is_encrypted_at_least

    Args:
        granted_scopes_or_options: Either a list of granted scopes (backwards compat)
            or an options dict with granted_scopes and security_bindings.

    Returns:
        A function registry including all built-in functions plus auth helpers.
    """
    # Handle both old signature (list) and new signature (options dict)
    if isinstance(granted_scopes_or_options, dict):
        options: AuthFunctionRegistryOptions = granted_scopes_or_options
        scopes = list(options.get("granted_scopes", []))
        sec_bindings: SecurityBindings = options.get(
            "security_bindings",
            {
                "sig": {"present": False, "kid": None},
                "enc": {"present": False, "alg": None, "kid": None, "level": "plaintext"},
            },
        )
    else:
        scopes = list(granted_scopes_or_options) if granted_scopes_or_options else []
        sec_bindings = {
            "sig": {"present": False, "kid": None},
            "enc": {"present": False, "alg": None, "kid": None, "level": "plaintext"},
        }

    def matches_scope(scope: str) -> bool:
        """Checks if any granted scope matches a pattern (exact match for now)."""
        return scope in scopes

    def has_scope(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
        """
        has_scope(scope: string) -> bool

        Returns True if the scope is in the granted scopes.
        Null-tolerant: returns False if scope is null.
        """
        _assert_arg_count(args, 1, "has_scope")
        scope = _get_arg(args, 0, "has_scope")
        # Null-tolerant: return False if scope is null
        scope_str = _assert_string_or_null(scope, "scope", "has_scope")
        if scope_str is None:
            return False
        return matches_scope(scope_str)

    def has_any_scope(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
        """
        has_any_scope(scopes: string[]) -> bool

        Returns True if any scope in the array is in the granted scopes.
        Null-tolerant: returns False if scopes is null.
        """
        _assert_arg_count(args, 1, "has_any_scope")
        values = _get_arg(args, 0, "has_any_scope")
        # Null-tolerant: return False if scopes is null
        values_list = _assert_string_array_or_null(values, "scopes", "has_any_scope")
        if values_list is None:
            return False
        if len(values_list) == 0:
            return False
        return any(matches_scope(scope) for scope in values_list)

    def has_all_scopes(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
        """
        has_all_scopes(scopes: string[]) -> bool

        Returns True if all scopes in the array are in the granted scopes.
        Null-tolerant: returns False if scopes is null.
        """
        _assert_arg_count(args, 1, "has_all_scopes")
        values = _get_arg(args, 0, "has_all_scopes")
        # Null-tolerant: return False if scopes is null
        values_list = _assert_string_array_or_null(values, "scopes", "has_all_scopes")
        if values_list is None:
            return False
        if len(values_list) == 0:
            return True
        return all(matches_scope(scope) for scope in values_list)

    # ============================================================
    # Security posture builtins
    # ============================================================

    def is_signed(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
        """
        is_signed() -> bool

        Returns True if the envelope has a signature present.
        No arguments required.
        """
        _assert_arg_count(args, 0, "is_signed")
        return sec_bindings["sig"]["present"]

    def encryption_level_fn(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
        """
        encryption_level() -> string

        Returns the normalized encryption level: "plaintext" | "channel" | "sealed" | "unknown"
        No arguments required.
        """
        _assert_arg_count(args, 0, "encryption_level")
        return sec_bindings["enc"]["level"]

    def is_encrypted(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
        """
        is_encrypted() -> bool

        Returns True if the encryption level is not "plaintext".
        This means the envelope has some form of encryption (channel, sealed, or unknown).
        No arguments required.
        """
        _assert_arg_count(args, 0, "is_encrypted")
        return sec_bindings["enc"]["level"] != "plaintext"

    def is_encrypted_at_least(args: Sequence[ExprValue], ctx: BuiltinContext) -> ExprValue:
        """
        is_encrypted_at_least(level: string) -> bool

        Returns True if the envelope's encryption level meets or exceeds the required level.

        Level ordering: plaintext < channel < sealed

        Special handling:
        - "unknown" encryption level does NOT satisfy "channel" or "sealed" (conservative)
        - "plaintext" is always satisfied (any envelope meets at least plaintext)
        - null argument => False (predicate-style)
        - invalid level string => BuiltinError
        """
        _assert_arg_count(args, 1, "is_encrypted_at_least")
        required_level = _get_arg(args, 0, "is_encrypted_at_least")

        # Null-tolerant: return False if level is null
        required_level_str = _assert_string_or_null(
            required_level, "level", "is_encrypted_at_least"
        )
        if required_level_str is None:
            return False

        # Validate required level
        if required_level_str not in VALID_ENCRYPTION_LEVELS:
            raise BuiltinError(
                "is_encrypted_at_least",
                f"level must be one of: {', '.join(VALID_ENCRYPTION_LEVELS)}; "
                f'got "{required_level_str}"',
            )

        current_level = sec_bindings["enc"]["level"]
        required_order = ENCRYPTION_LEVEL_ORDER.get(required_level_str, 0)
        current_order = ENCRYPTION_LEVEL_ORDER.get(current_level)

        # If current level is "unknown", it only satisfies "plaintext"
        if current_order is None:
            # "unknown" is treated as NOT meeting channel/sealed requirements
            return required_order == 0  # Only plaintext is satisfied by unknown

        return current_order >= required_order

    # Create new registry with all built-in functions plus auth helpers
    registry: FunctionRegistry = {
        **BUILTIN_FUNCTIONS,
        # Scope builtins
        "has_scope": has_scope,
        "has_any_scope": has_any_scope,
        "has_all_scopes": has_all_scopes,
        # Security posture builtins
        "is_signed": is_signed,
        "encryption_level": encryption_level_fn,
        "is_encrypted": is_encrypted,
        "is_encrypted_at_least": is_encrypted_at_least,
    }

    return registry

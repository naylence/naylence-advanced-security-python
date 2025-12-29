"""
Tests for authorization-specific expression built-ins.
"""

import pytest

from naylence.fame.expr import (
    EvaluationContext,
    ExprValue,
    evaluate,
    evaluate_as_boolean,
    parse,
)
from naylence.fame.security.auth.policy.expr_builtins import (
    SecurityBindings,
    create_auth_function_registry,
    create_security_bindings,
    normalize_encryption_level_from_alg,
)


def eval_bool(
    expression: str,
    bindings: dict[str, ExprValue] = None,
    granted_scopes: list[str] = None,
) -> bool:
    """Helper to evaluate an expression as boolean and return the value."""
    bindings = bindings or {}
    granted_scopes = granted_scopes or []
    ast = parse(expression)
    context = EvaluationContext(
        bindings=bindings,
        source=expression,
        functions=create_auth_function_registry(granted_scopes),
    )
    value, error = evaluate_as_boolean(ast, context)
    if error:
        raise RuntimeError(error)
    return value


def eval_bool_result(
    expression: str,
    bindings: dict[str, ExprValue] = None,
    granted_scopes: list[str] = None,
) -> tuple[bool, str | None]:
    """Helper to evaluate an expression as boolean and return (value, error)."""
    bindings = bindings or {}
    granted_scopes = granted_scopes or []
    ast = parse(expression)
    context = EvaluationContext(
        bindings=bindings,
        source=expression,
        functions=create_auth_function_registry(granted_scopes),
    )
    return evaluate_as_boolean(ast, context)


def eval_expr(
    expression: str,
    bindings: dict[str, ExprValue] = None,
    granted_scopes: list[str] = None,
) -> ExprValue:
    """Helper to evaluate an expression and return the value."""
    bindings = bindings or {}
    granted_scopes = granted_scopes or []
    ast = parse(expression)
    context = EvaluationContext(
        bindings=bindings,
        source=expression,
        functions=create_auth_function_registry(granted_scopes),
    )
    result = evaluate(ast, context)
    if not result.success:
        raise RuntimeError(result.error)
    return result.value


class TestHasScope:
    """Tests for has_scope builtin."""

    def test_returns_true_for_granted_scope(self):
        assert eval_bool('has_scope("admin")', {}, ["admin", "write"]) is True

    def test_returns_false_for_missing_scope(self):
        assert eval_bool('has_scope("admin")', {}, ["read"]) is False

    def test_returns_false_for_empty_granted_scopes(self):
        assert eval_bool('has_scope("admin")', {}, []) is False


class TestHasAnyScope:
    """Tests for has_any_scope builtin."""

    def test_returns_true_if_any_scope_is_granted(self):
        result = eval_bool('has_any_scope(["admin", "write"])', {}, ["write"])
        assert result is True

    def test_returns_false_if_no_scope_is_granted(self):
        result = eval_bool('has_any_scope(["admin", "write"])', {}, ["read"])
        assert result is False

    def test_returns_false_for_empty_input_array(self):
        assert eval_bool("has_any_scope([])", {}, ["admin"]) is False


class TestHasAllScopes:
    """Tests for has_all_scopes builtin."""

    def test_returns_true_if_all_scopes_are_granted(self):
        result = eval_bool(
            'has_all_scopes(["read", "write"])',
            {},
            ["read", "write", "admin"],
        )
        assert result is True

    def test_returns_false_if_not_all_scopes_are_granted(self):
        result = eval_bool('has_all_scopes(["read", "write"])', {}, ["read"])
        assert result is False

    def test_returns_true_for_empty_input_array(self):
        # Vacuously true
        assert eval_bool("has_all_scopes([])", {}, ["admin"]) is True


class TestHasScopeWithNull:
    """Tests for has_scope with null values."""

    def test_returns_false_when_scope_arg_is_null(self):
        assert eval_expr("has_scope(null)", {}, ["admin"]) is False

    def test_returns_false_when_scope_arg_is_missing_property(self):
        assert eval_expr("has_scope(obj.missing)", {"obj": {}}, ["admin"]) is False

    def test_throws_for_wrong_type_number(self):
        with pytest.raises(RuntimeError, match="string"):
            eval_expr("has_scope(42)", {}, [])

    def test_throws_for_wrong_type_array(self):
        with pytest.raises(RuntimeError, match="string"):
            eval_expr("has_scope(arr)", {"arr": []}, [])


class TestHasAnyScopeWithNull:
    """Tests for has_any_scope with null values."""

    def test_returns_false_when_scopes_arg_is_null(self):
        assert eval_expr("has_any_scope(null)", {}, ["admin"]) is False

    def test_returns_false_when_scopes_arg_is_missing_property(self):
        assert eval_expr("has_any_scope(obj.missing)", {"obj": {}}, ["admin"]) is False

    def test_throws_for_wrong_type_string(self):
        with pytest.raises(RuntimeError, match="array"):
            eval_expr('has_any_scope("admin")', {}, [])

    def test_throws_for_wrong_type_number(self):
        with pytest.raises(RuntimeError, match="array"):
            eval_expr("has_any_scope(123)", {}, [])


class TestHasAllScopesWithNull:
    """Tests for has_all_scopes with null values."""

    def test_returns_false_when_scopes_arg_is_null(self):
        assert eval_expr("has_all_scopes(null)", {}, ["admin"]) is False

    def test_returns_false_when_scopes_arg_is_missing_property(self):
        assert eval_expr("has_all_scopes(obj.missing)", {"obj": {}}, ["admin"]) is False

    def test_throws_for_wrong_type_object(self):
        with pytest.raises(RuntimeError, match="array"):
            eval_expr("has_all_scopes(obj)", {"obj": {}}, [])

    def test_throws_for_array_containing_non_strings(self):
        with pytest.raises(RuntimeError, match="string"):
            eval_expr("has_all_scopes(arr)", {"arr": ["valid", 123]}, [])


class TestAuthBuiltinsEvaluateAsBooleanBehavior:
    """Tests for auth builtins with evaluate_as_boolean behavior."""

    def test_returns_value_false_with_no_error_for_null_scope(self):
        value, error = eval_bool_result("has_scope(null)", {}, ["admin"])
        assert value is False
        assert error is None

    def test_returns_value_false_with_no_error_for_null_scopes_array(self):
        value, error = eval_bool_result("has_any_scope(null)", {}, ["admin"])
        assert value is False
        assert error is None

    def test_returns_value_false_with_error_for_wrong_type(self):
        value, error = eval_bool_result("has_scope(42)", {}, [])
        assert value is False
        assert error is not None
        assert "string" in error

    def test_returns_value_true_with_no_error_for_valid_scope_match(self):
        value, error = eval_bool_result('has_scope("admin")', {}, ["admin"])
        assert value is True
        assert error is None

    def test_handles_complex_expression_with_null_scope_propagation(self):
        value, error = eval_bool_result(
            'has_scope(claims.requiredScope) && has_any_scope(["admin"])',
            {"claims": {"requiredScope": None}},
            ["admin"],
        )
        # has_scope returns False due to null, && short-circuits
        assert value is False
        assert error is None


class TestParameterizedAuthBuiltinNullTolerance:
    """Parameterized tests for auth builtin null tolerance."""

    @pytest.mark.parametrize(
        "expr,bindings,scopes,expected_value,should_error",
        [
            ("has_scope(null)", {}, ["admin"], False, False),
            ("has_scope(x)", {"x": None}, ["admin"], False, False),
            ("has_scope(x.y)", {"x": {}}, ["admin"], False, False),
            ("has_scope(42)", {}, [], False, True),
            ('has_scope("admin")', {}, ["admin"], True, False),
            ('has_scope("admin")', {}, ["read"], False, False),
            ("has_any_scope(null)", {}, ["admin"], False, False),
            ("has_any_scope(x)", {"x": None}, ["admin"], False, False),
            ('has_any_scope("str")', {}, [], False, True),
            ('has_any_scope(["admin"])', {}, ["admin"], True, False),
            ('has_any_scope(["admin"])', {}, ["read"], False, False),
            ("has_all_scopes(null)", {}, ["admin"], False, False),
            ("has_all_scopes(x)", {"x": None}, ["admin"], False, False),
            ("has_all_scopes(123)", {}, [], False, True),
            ('has_all_scopes(["a", "b"])', {}, ["a", "b", "c"], True, False),
            ('has_all_scopes(["a", "b"])', {}, ["a"], False, False),
        ],
    )
    def test_auth_predicate(self, expr, bindings, scopes, expected_value, should_error):
        value, error = eval_bool_result(expr, bindings, scopes)
        assert value == expected_value
        if should_error:
            assert error is not None
        else:
            assert error is None


# ============================================================
# Security posture helper and builtin tests
# ============================================================


def eval_with_security(
    expression: str,
    security_bindings: SecurityBindings,
    bindings: dict[str, ExprValue] = None,
    granted_scopes: list[str] = None,
) -> ExprValue:
    """Helper to evaluate an expression with security bindings."""
    bindings = bindings or {}
    granted_scopes = granted_scopes or []
    ast = parse(expression)
    context = EvaluationContext(
        bindings=bindings,
        source=expression,
        functions=create_auth_function_registry({
            "granted_scopes": granted_scopes,
            "security_bindings": security_bindings,
        }),
    )
    result = evaluate(ast, context)
    if not result.success:
        raise RuntimeError(result.error)
    return result.value


def eval_bool_with_security(
    expression: str,
    security_bindings: SecurityBindings,
    bindings: dict[str, ExprValue] = None,
    granted_scopes: list[str] = None,
) -> tuple[bool, str | None]:
    """Helper to evaluate as boolean with security bindings."""
    bindings = bindings or {}
    granted_scopes = granted_scopes or []
    ast = parse(expression)
    context = EvaluationContext(
        bindings=bindings,
        source=expression,
        functions=create_auth_function_registry({
            "granted_scopes": granted_scopes,
            "security_bindings": security_bindings,
        }),
    )
    return evaluate_as_boolean(ast, context)


class TestNormalizeEncryptionLevelFromAlg:
    """Tests for normalize_encryption_level_from_alg helper."""

    class TestPlaintextCases:
        """Tests for plaintext encryption level."""

        def test_returns_plaintext_for_none(self):
            assert normalize_encryption_level_from_alg(None) == "plaintext"

    class TestSealedEncryptionCases:
        """Tests for sealed encryption level."""

        def test_returns_sealed_for_ecdh_es_a256gcm(self):
            assert normalize_encryption_level_from_alg("ECDH-ES+A256GCM") == "sealed"

        def test_returns_sealed_for_ecdh_es_a128gcm(self):
            assert normalize_encryption_level_from_alg("ECDH-ES+A128GCM") == "sealed"

        def test_returns_sealed_for_alg_containing_sealed(self):
            assert normalize_encryption_level_from_alg("custom-algo-sealed") == "sealed"

        def test_is_case_insensitive_for_ecdh_es_pattern(self):
            assert normalize_encryption_level_from_alg("ecdh-es+a256gcm") == "sealed"
            assert normalize_encryption_level_from_alg("ECDH-ES+A128GCM") == "sealed"

    class TestChannelEncryptionCases:
        """Tests for channel encryption level."""

        def test_returns_channel_for_chacha20_poly1305_channel(self):
            result = normalize_encryption_level_from_alg("chacha20-poly1305-channel")
            assert result == "channel"

        def test_returns_channel_for_any_alg_containing_channel(self):
            result = normalize_encryption_level_from_alg("aes256-gcm-channel")
            assert result == "channel"

        def test_is_case_insensitive_for_channel_detection(self):
            result = normalize_encryption_level_from_alg("CHACHA20-POLY1305-CHANNEL")
            assert result == "channel"
            result2 = normalize_encryption_level_from_alg("ChaCha20-Poly1305-Channel")
            assert result2 == "channel"

    class TestUnknownEncryptionCases:
        """Tests for unknown encryption level."""

        def test_returns_unknown_for_unrecognized_algorithm(self):
            assert normalize_encryption_level_from_alg("custom-algo") == "unknown"

        def test_returns_unknown_for_empty_string(self):
            assert normalize_encryption_level_from_alg("") == "unknown"

        def test_returns_unknown_for_standalone_cipher_without_key_agreement(self):
            # A256GCM alone without ECDH-ES prefix is unknown
            assert normalize_encryption_level_from_alg("A256GCM") == "unknown"

        def test_returns_unknown_for_chacha20_without_channel_suffix(self):
            # ChaCha20 alone could be channel or sealed, so unknown
            assert normalize_encryption_level_from_alg("ChaCha20-Poly1305") == "unknown"


class TestCreateSecurityBindings:
    """Tests for create_security_bindings helper."""

    class TestNoSecHeader:
        """Tests for no security header."""

        def test_returns_sig_present_false_for_none_sec(self):
            bindings = create_security_bindings(None)
            assert bindings["sig"]["present"] is False
            assert bindings["sig"]["kid"] is None

        def test_returns_enc_level_plaintext_for_none_sec(self):
            bindings = create_security_bindings(None)
            assert bindings["enc"]["present"] is False
            assert bindings["enc"]["level"] == "plaintext"
            assert bindings["enc"]["alg"] is None
            assert bindings["enc"]["kid"] is None

    class TestSignaturePresent:
        """Tests for signature metadata."""

        def test_returns_sig_present_true_when_sig_exists(self):
            bindings = create_security_bindings({"sig": {}})
            assert bindings["sig"]["present"] is True

        def test_extracts_sig_kid_when_present(self):
            bindings = create_security_bindings({"sig": {"kid": "key-123"}})
            assert bindings["sig"]["kid"] == "key-123"

        def test_returns_sig_kid_none_when_not_present(self):
            bindings = create_security_bindings({"sig": {}})
            assert bindings["sig"]["kid"] is None

    class TestEncryptionPresent:
        """Tests for encryption metadata."""

        def test_returns_enc_present_true_when_enc_exists(self):
            bindings = create_security_bindings({"enc": {}})
            assert bindings["enc"]["present"] is True

        def test_extracts_enc_alg_when_present(self):
            bindings = create_security_bindings({"enc": {"alg": "A256GCM"}})
            assert bindings["enc"]["alg"] == "A256GCM"

        def test_extracts_enc_kid_when_present(self):
            bindings = create_security_bindings({"enc": {"kid": "enc-key-456"}})
            assert bindings["enc"]["kid"] == "enc-key-456"

        def test_normalizes_enc_level_to_sealed_for_ecdh_es_a256gcm(self):
            bindings = create_security_bindings({"enc": {"alg": "ECDH-ES+A256GCM"}})
            assert bindings["enc"]["level"] == "sealed"

        def test_normalizes_enc_level_to_channel_for_chacha20_poly1305_channel(self):
            bindings = create_security_bindings(
                {"enc": {"alg": "chacha20-poly1305-channel"}}
            )
            assert bindings["enc"]["level"] == "channel"

        def test_normalizes_enc_level_to_unknown_for_unrecognized_alg(self):
            bindings = create_security_bindings({"enc": {"alg": "custom-algo"}})
            assert bindings["enc"]["level"] == "unknown"

    class TestBothSigAndEncPresent:
        """Tests for both signature and encryption."""

        def test_handles_both_sig_and_enc_with_full_metadata(self):
            bindings = create_security_bindings({
                "sig": {"kid": "sig-key"},
                "enc": {"alg": "ECDH-ES+A256GCM", "kid": "enc-key"},
            })
            assert bindings["sig"]["present"] is True
            assert bindings["sig"]["kid"] == "sig-key"
            assert bindings["enc"]["present"] is True
            assert bindings["enc"]["alg"] == "ECDH-ES+A256GCM"
            assert bindings["enc"]["kid"] == "enc-key"
            assert bindings["enc"]["level"] == "sealed"


class TestSecurityPostureBuiltins:
    """Tests for security posture builtins."""

    class TestIsSigned:
        """Tests for is_signed() builtin."""

        def test_returns_false_when_no_signature_present(self):
            sec = create_security_bindings(None)
            result = eval_with_security("is_signed()", sec)
            assert result is False

        def test_returns_true_when_signature_is_present(self):
            sec = create_security_bindings({"sig": {"kid": "key-1"}})
            result = eval_with_security("is_signed()", sec)
            assert result is True

        def test_returns_true_when_signature_exists_without_kid(self):
            sec = create_security_bindings({"sig": {}})
            result = eval_with_security("is_signed()", sec)
            assert result is True

        def test_throws_error_when_called_with_arguments(self):
            sec = create_security_bindings({"sig": {}})
            with pytest.raises(RuntimeError, match="expected 0 argument"):
                eval_with_security('is_signed("arg")', sec)

    class TestEncryptionLevel:
        """Tests for encryption_level() builtin."""

        def test_returns_plaintext_when_no_encryption(self):
            sec = create_security_bindings(None)
            result = eval_with_security("encryption_level()", sec)
            assert result == "plaintext"

        def test_returns_sealed_for_a256gcm_encryption(self):
            sec = create_security_bindings({"enc": {"alg": "ECDH-ES+A256GCM"}})
            result = eval_with_security("encryption_level()", sec)
            assert result == "sealed"

        def test_returns_channel_for_channel_encryption(self):
            sec = create_security_bindings({"enc": {"alg": "chacha20-poly1305-channel"}})
            result = eval_with_security("encryption_level()", sec)
            assert result == "channel"

        def test_returns_unknown_for_unrecognized_encryption(self):
            sec = create_security_bindings({"enc": {"alg": "custom-algo"}})
            result = eval_with_security("encryption_level()", sec)
            assert result == "unknown"

        def test_throws_error_when_called_with_arguments(self):
            sec = create_security_bindings(None)
            with pytest.raises(RuntimeError, match="expected 0 argument"):
                eval_with_security('encryption_level("arg")', sec)

    class TestIsEncrypted:
        """Tests for is_encrypted() builtin."""

        def test_returns_false_when_level_is_plaintext(self):
            sec = create_security_bindings(None)
            result = eval_with_security("is_encrypted()", sec)
            assert result is False

        def test_returns_true_when_level_is_sealed(self):
            sec = create_security_bindings({"enc": {"alg": "ECDH-ES+A256GCM"}})
            result = eval_with_security("is_encrypted()", sec)
            assert result is True

        def test_returns_true_when_level_is_channel(self):
            sec = create_security_bindings({"enc": {"alg": "chacha20-poly1305-channel"}})
            result = eval_with_security("is_encrypted()", sec)
            assert result is True

        def test_returns_true_when_level_is_unknown(self):
            sec = create_security_bindings({"enc": {"alg": "custom-algo"}})
            result = eval_with_security("is_encrypted()", sec)
            assert result is True

        def test_throws_error_when_called_with_arguments(self):
            sec = create_security_bindings(None)
            with pytest.raises(RuntimeError, match="expected 0 argument"):
                eval_with_security('is_encrypted("arg")', sec)

    class TestIsEncryptedAtLeast:
        """Tests for is_encrypted_at_least(level) builtin."""

        class TestWithPlaintextEnvelope:
            """Tests with plaintext envelope."""

            def test_returns_true_for_plaintext_requirement(self):
                sec = create_security_bindings(None)
                result = eval_with_security('is_encrypted_at_least("plaintext")', sec)
                assert result is True

            def test_returns_false_for_channel_requirement(self):
                sec = create_security_bindings(None)
                result = eval_with_security('is_encrypted_at_least("channel")', sec)
                assert result is False

            def test_returns_false_for_sealed_requirement(self):
                sec = create_security_bindings(None)
                result = eval_with_security('is_encrypted_at_least("sealed")', sec)
                assert result is False

        class TestWithChannelEncryptedEnvelope:
            """Tests with channel-encrypted envelope."""

            def test_returns_true_for_plaintext_requirement(self):
                sec = create_security_bindings(
                    {"enc": {"alg": "chacha20-poly1305-channel"}}
                )
                result = eval_with_security('is_encrypted_at_least("plaintext")', sec)
                assert result is True

            def test_returns_true_for_channel_requirement(self):
                sec = create_security_bindings(
                    {"enc": {"alg": "chacha20-poly1305-channel"}}
                )
                result = eval_with_security('is_encrypted_at_least("channel")', sec)
                assert result is True

            def test_returns_false_for_sealed_requirement(self):
                sec = create_security_bindings(
                    {"enc": {"alg": "chacha20-poly1305-channel"}}
                )
                result = eval_with_security('is_encrypted_at_least("sealed")', sec)
                assert result is False

        class TestWithSealedEncryptedEnvelope:
            """Tests with sealed-encrypted envelope."""

            def test_returns_true_for_plaintext_requirement(self):
                sec = create_security_bindings({"enc": {"alg": "ECDH-ES+A256GCM"}})
                result = eval_with_security('is_encrypted_at_least("plaintext")', sec)
                assert result is True

            def test_returns_true_for_channel_requirement(self):
                sec = create_security_bindings({"enc": {"alg": "ECDH-ES+A256GCM"}})
                result = eval_with_security('is_encrypted_at_least("channel")', sec)
                assert result is True

            def test_returns_true_for_sealed_requirement(self):
                sec = create_security_bindings({"enc": {"alg": "ECDH-ES+A256GCM"}})
                result = eval_with_security('is_encrypted_at_least("sealed")', sec)
                assert result is True

        class TestWithUnknownEncryptedEnvelope:
            """Tests with unknown-encrypted envelope."""

            def test_returns_true_for_plaintext_requirement(self):
                sec = create_security_bindings({"enc": {"alg": "custom-algo"}})
                result = eval_with_security('is_encrypted_at_least("plaintext")', sec)
                assert result is True

            def test_returns_false_for_channel_requirement_conservative(self):
                sec = create_security_bindings({"enc": {"alg": "custom-algo"}})
                result = eval_with_security('is_encrypted_at_least("channel")', sec)
                assert result is False

            def test_returns_false_for_sealed_requirement_conservative(self):
                sec = create_security_bindings({"enc": {"alg": "custom-algo"}})
                result = eval_with_security('is_encrypted_at_least("sealed")', sec)
                assert result is False

        class TestErrorCases:
            """Tests for error cases."""

            def test_returns_false_for_null_argument_null_tolerant(self):
                sec = create_security_bindings(None)
                value, error = eval_bool_with_security(
                    "is_encrypted_at_least(null)", sec
                )
                assert value is False
                assert error is None

            def test_returns_false_for_missing_property_null_tolerant(self):
                sec = create_security_bindings(None)
                value, error = eval_bool_with_security(
                    "is_encrypted_at_least(obj.missing)", sec, {"obj": {}}
                )
                assert value is False
                assert error is None

            def test_throws_error_for_invalid_level_string(self):
                sec = create_security_bindings(None)
                with pytest.raises(RuntimeError, match="must be one of.*plaintext"):
                    eval_with_security('is_encrypted_at_least("invalid")', sec)

            def test_throws_error_for_wrong_type_number(self):
                sec = create_security_bindings(None)
                with pytest.raises(RuntimeError, match="must be a string"):
                    eval_with_security("is_encrypted_at_least(42)", sec)

            def test_throws_error_for_wrong_type_array(self):
                sec = create_security_bindings(None)
                with pytest.raises(RuntimeError, match="must be a string"):
                    eval_with_security('is_encrypted_at_least(["sealed"])', sec)

            def test_throws_error_when_called_with_no_arguments(self):
                sec = create_security_bindings(None)
                with pytest.raises(RuntimeError, match="expected 1 argument"):
                    eval_with_security("is_encrypted_at_least()", sec)

            def test_throws_error_when_called_with_multiple_arguments(self):
                sec = create_security_bindings(None)
                with pytest.raises(RuntimeError, match="expected 1 argument"):
                    eval_with_security('is_encrypted_at_least("sealed", "extra")', sec)


class TestSecurityBuiltinsCombinedWithScopeBuiltins:
    """Tests for combining security builtins with scope builtins."""

    def test_allows_combining_is_signed_and_has_scope(self):
        sec = create_security_bindings({"sig": {"kid": "key-1"}})
        value, error = eval_bool_with_security(
            'is_signed() && has_scope("admin")',
            sec,
            {},
            ["admin"],
        )
        assert value is True
        assert error is None

    def test_fails_when_signature_missing_even_with_scope(self):
        sec = create_security_bindings(None)
        value, error = eval_bool_with_security(
            'is_signed() && has_scope("admin")',
            sec,
            {},
            ["admin"],
        )
        assert value is False
        assert error is None

    def test_allows_complex_security_policy_expression(self):
        sec = create_security_bindings({
            "sig": {"kid": "sig-key"},
            "enc": {"alg": "ECDH-ES+A256GCM", "kid": "enc-key"},
        })
        value, error = eval_bool_with_security(
            'is_signed() && is_encrypted_at_least("channel") && has_scope("write")',
            sec,
            {},
            ["write", "read"],
        )
        assert value is True
        assert error is None


class TestParameterizedSecurityBuiltins:
    """Parameterized tests for security builtins."""

    @pytest.mark.parametrize(
        "expr,sec_input,expected_value,desc",
        [
            ("is_signed()", None, False, "unsigned envelope"),
            ("is_signed()", {"sig": {}}, True, "signed envelope"),
            ("is_signed()", {"enc": {"alg": "ECDH-ES+A256GCM"}}, False, "enc only"),
            ("is_encrypted()", None, False, "plaintext envelope"),
            ("is_encrypted()", {"enc": {"alg": "ECDH-ES+A256GCM"}}, True, "sealed"),
            ("is_encrypted()", {"enc": {"alg": "chacha20-poly1305-channel"}}, True, "ch"),
            ("is_encrypted()", {"enc": {"alg": "custom"}}, True, "unknown enc"),
            ("encryption_level()", None, "plaintext", "no encryption"),
            ("encryption_level()", {"enc": {"alg": "ECDH-ES+A256GCM"}}, "sealed", "seal"),
            ("encryption_level()", {"enc": {"alg": "chacha20-poly1305-channel"}}, "channel", "ch"),
            ("encryption_level()", {"enc": {"alg": "xyz"}}, "unknown", "unknown alg"),
        ],
    )
    def test_security_predicate(self, expr, sec_input, expected_value, desc):
        sec = create_security_bindings(sec_input)
        result = eval_with_security(expr, sec)
        assert result == expected_value
#!/usr/bin/env python3
"""
Test security policy validation during node attach handshake.
"""

import pytest

from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.policy.security_policy import (
    CryptoLevel,
    EncryptionConfig,
    InboundCryptoRules,
    InboundSigningRules,
    OutboundCryptoRules,
    OutboundSigningRules,
    ResponseCryptoRules,
    ResponseSigningRules,
    SignaturePolicy,
    SigningConfig,
)


@pytest.mark.asyncio
async def test_attach_validation_with_signing_requirements():
    """Test that security policy correctly validates signing key requirements during attach."""
    print("Testing attach validation with signing requirements...")

    # Create a policy that requires signing AND encryption
    # If we want encryption, we need to explicitly configure it
    signing_config = SigningConfig(
        outbound=OutboundSigningRules(default_signing=True),
        inbound=InboundSigningRules(signature_policy=SignaturePolicy.REQUIRED),
        response=ResponseSigningRules(mirror_request_signing=True),
    )
    
    encryption_config = EncryptionConfig(
        outbound=OutboundCryptoRules(default_level=CryptoLevel.CHANNEL),
        inbound=InboundCryptoRules(allow_channel=True, allow_sealed=True, allow_plaintext=False),
        response=ResponseCryptoRules(minimum_response_level=CryptoLevel.CHANNEL),
    )

    policy = DefaultSecurityPolicy(signing=signing_config, encryption=encryption_config)
    requirements = policy.requirements()

    # Should require both signing and encryption key exchange (realistic security model)
    assert requirements.require_signing_key_exchange
    assert requirements.require_encryption_key_exchange  # Explicitly configured encryption
    assert requirements.signing_required
    assert requirements.verification_required
    assert requirements.encryption_required  # Channel encryption is explicitly configured

    # Test with both signing and encryption keys (realistic scenario)
    complete_keys = [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "kid": "test-signing-key",
            "x": "dummy_signing_key_data",
        },
        {
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "kid": "test-encryption-key",
            "x": "dummy_encryption_key_data",
        },
    ]

    is_valid, reason = policy.validate_attach_security_compatibility(
        peer_keys=complete_keys,
        peer_requirements=None,
        node_like=None,
    )

    assert is_valid, f"Expected valid with both key types, got: {reason}"

    # Test with missing keys (should fail)
    no_keys = []
    is_valid, reason = policy.validate_attach_security_compatibility(
        peer_keys=no_keys,
        peer_requirements=None,
        node_like=None,
    )

    assert not is_valid
    assert "key exchange" in reason.lower()

    # Test with only signing keys but missing encryption keys (should fail in realistic model)
    signing_only_keys = [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "kid": "test-signing-key",
            "x": "dummy_signing_key_data",
        }
    ]

    is_valid, reason = policy.validate_attach_security_compatibility(
        peer_keys=signing_only_keys,
        peer_requirements=None,
        node_like=None,
    )

    assert not is_valid
    assert "encryption keys" in reason.lower()

    # Test with only encryption keys but missing signing keys (should fail)
    encryption_only_keys = [
        {
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "kid": "test-encryption-key",
            "x": "dummy_encryption_key_data",
        }
    ]

    is_valid, reason = policy.validate_attach_security_compatibility(
        peer_keys=encryption_only_keys,
        peer_requirements=None,
        node_like=None,
    )

    assert not is_valid
    assert "signing keys" in reason.lower()

    print("✓ Attach validation with signing requirements passed")


@pytest.mark.asyncio
async def test_attach_validation_with_encryption_requirements():
    """Test that security policy correctly validates encryption key requirements during attach."""
    print("Testing attach validation with encryption requirements...")

    # Create a policy that requires encryption
    encryption_config = EncryptionConfig(
        outbound=OutboundCryptoRules(default_level=CryptoLevel.SEALED),
        inbound=InboundCryptoRules(allow_plaintext=False, allow_sealed=True),
        response=ResponseCryptoRules(minimum_response_level=CryptoLevel.SEALED),
    )

    policy = DefaultSecurityPolicy(encryption=encryption_config)
    requirements = policy.requirements()

    # Should require encryption key exchange
    assert requirements.require_encryption_key_exchange
    assert requirements.encryption_required
    assert requirements.decryption_required

    # Test with valid encryption keys
    valid_encryption_keys = [
        {
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "kid": "test-encryption-key",
            "x": "dummy_public_key_data",
        }
    ]

    is_valid, reason = policy.validate_attach_security_compatibility(
        peer_keys=valid_encryption_keys,
        peer_requirements=None,
        node_like=None,
    )

    assert is_valid, f"Expected valid with encryption keys, got: {reason}"

    # Test with missing encryption keys
    no_keys = []
    is_valid, reason = policy.validate_attach_security_compatibility(
        peer_keys=no_keys,
        peer_requirements=None,
        node_like=None,
    )

    assert not is_valid
    assert "encryption key exchange" in reason.lower()

    # Test with signing keys but no encryption keys
    signing_only_keys = [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "kid": "test-signing-key",
            "x": "dummy_signing_key_data",
        }
    ]

    is_valid, reason = policy.validate_attach_security_compatibility(
        peer_keys=signing_only_keys,
        peer_requirements=None,
        node_like=None,
    )

    assert not is_valid
    assert "encryption keys" in reason.lower()

    print("✓ Attach validation with encryption requirements passed")


@pytest.mark.asyncio
async def test_attach_validation_with_both_requirements():
    """Test validation when both signing and encryption are required."""
    print("Testing attach validation with both signing and encryption requirements...")

    # Create a policy that requires both signing and encryption
    encryption_config = EncryptionConfig(
        outbound=OutboundCryptoRules(default_level=CryptoLevel.SEALED),
        inbound=InboundCryptoRules(allow_plaintext=False, allow_sealed=True),
        response=ResponseCryptoRules(minimum_response_level=CryptoLevel.SEALED),
    )

    signing_config = SigningConfig(
        outbound=OutboundSigningRules(default_signing=True),
        inbound=InboundSigningRules(signature_policy=SignaturePolicy.REQUIRED),
        response=ResponseSigningRules(mirror_request_signing=True),
    )

    policy = DefaultSecurityPolicy(encryption=encryption_config, signing=signing_config)
    requirements = policy.requirements()

    # Should require both types of key exchange
    assert requirements.require_signing_key_exchange
    assert requirements.require_encryption_key_exchange
    assert requirements.require_key_exchange

    # Test with both types of keys
    complete_keys = [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "kid": "test-signing-key",
            "x": "dummy_signing_key_data",
        },
        {
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "kid": "test-encryption-key",
            "x": "dummy_encryption_key_data",
        },
    ]

    is_valid, reason = policy.validate_attach_security_compatibility(
        peer_keys=complete_keys,
        peer_requirements=None,
        node_like=None,
    )

    assert is_valid, f"Expected valid with both key types, got: {reason}"

    # Test with only signing keys
    signing_only = [complete_keys[0]]  # Just the signing key
    is_valid, reason = policy.validate_attach_security_compatibility(
        peer_keys=signing_only,
        peer_requirements=None,
        node_like=None,
    )

    assert not is_valid
    assert "encryption keys" in reason.lower()

    # Test with only encryption keys
    encryption_only = [complete_keys[1]]  # Just the encryption key
    is_valid, reason = policy.validate_attach_security_compatibility(
        peer_keys=encryption_only,
        peer_requirements=None,
        node_like=None,
    )

    assert not is_valid
    assert "signing keys" in reason.lower()

    print("✓ Attach validation with both requirements passed")


@pytest.mark.asyncio
async def test_attach_validation_no_requirements():
    """Test that validation passes when using a truly permissive policy with no crypto requirements."""
    print("Testing attach validation with no security requirements...")

    # Create a truly permissive policy with no encryption or signing requirements
    from naylence.fame.security.policy.security_policy import (
        CryptoLevel,
        EncryptionConfig,
        InboundCryptoRules,
        InboundSigningRules,
        OutboundCryptoRules,
        OutboundSigningRules,
        ResponseCryptoRules,
        ResponseSigningRules,
        SignaturePolicy,
        SigningConfig,
    )

    # Explicitly disable all encryption - including outbound defaults
    encryption_config = EncryptionConfig(
        outbound=OutboundCryptoRules(
            default_level=CryptoLevel.PLAINTEXT,  # Force plaintext outbound
            escalate_if_peer_supports=False,
            prefer_sealed_for_sensitive=False,
        ),
        inbound=InboundCryptoRules(
            allow_plaintext=True,
            allow_channel=False,  # Disable channel encryption to avoid key exchange requirement
            allow_sealed=False,  # Disable sealed encryption to avoid key exchange requirement
        ),
        response=ResponseCryptoRules(
            minimum_response_level=CryptoLevel.PLAINTEXT,  # Force plaintext responses
            mirror_request_level=False,
            escalate_sealed_responses=False,
        ),
    )

    # Explicitly disable all signing
    signing_config = SigningConfig(
        outbound=OutboundSigningRules(
            default_signing=False,
            sign_sensitive_operations=False,
            sign_if_recipient_expects=False,
        ),
        inbound=InboundSigningRules(signature_policy=SignaturePolicy.DISABLED),
        response=ResponseSigningRules(
            mirror_request_signing=False,
            always_sign_responses=False,
            sign_error_responses=False,
        ),
    )

    policy = DefaultSecurityPolicy(encryption=encryption_config, signing=signing_config)
    requirements = policy.requirements()

    # Should not require key exchange when both encryption and signing are disabled
    assert not requirements.require_signing_key_exchange
    assert not requirements.require_encryption_key_exchange
    assert not requirements.require_key_exchange

    # Should pass with no keys
    is_valid, reason = policy.validate_attach_security_compatibility(
        peer_keys=[],
        peer_requirements=None,
        node_like=None,
    )

    assert is_valid, f"Expected valid with no requirements, got: {reason}"

    # Should also pass with keys (no harm in providing extra)
    extra_keys = [
        {"kty": "OKP", "crv": "Ed25519", "use": "sig", "kid": "extra-signing-key", "x": "dummy_key_data"}
    ]

    is_valid, reason = policy.validate_attach_security_compatibility(
        peer_keys=extra_keys,
        peer_requirements=None,
        node_like=None,
    )

    assert is_valid, f"Expected valid with extra keys, got: {reason}"

    print("✓ Attach validation with no requirements passed")


if __name__ == "__main__":
    import asyncio

    async def run_tests():
        await test_attach_validation_with_signing_requirements()
        await test_attach_validation_with_encryption_requirements()
        await test_attach_validation_with_both_requirements()
        await test_attach_validation_no_requirements()
        print("\n🎉 All attach security validation tests passed!")

    asyncio.run(run_tests())

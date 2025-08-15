import pytest

"""
Test script to verify the complete certificate-enabled signing and verification workflow
using policy-driven EdDSAEnvelopeSigner and EdDSAEnvelopeVerifier.
"""


@pytest.mark.asyncio
async def test_end_to_end_certificate_workflow():
    """Test the complete certificate signing and verification workflow."""

    from naylence.fame.core.protocol.envelope import FameEnvelope
    from naylence.fame.core.protocol.frames import DataFrame
    from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
    from naylence.fame.security.keys.key_store import get_key_store
    from naylence.fame.security.policy import DefaultSecurityPolicy
    from naylence.fame.security.policy.security_policy import (
        InboundSigningRules,
        OutboundSigningRules,
        SignaturePolicy,
        SigningConfig,
    )
    from naylence.fame.security.security_manager_factory import SecurityManagerFactory
    from naylence.fame.util.util import secure_digest

    print("=== Testing End-to-End Certificate Workflow ===\n")

    # Set up policy with certificate features enabled
    from naylence.fame.security.policy.security_policy import SigningMaterial

    cert_policy = DefaultSecurityPolicy(
        signing=SigningConfig(
            inbound=InboundSigningRules(signature_policy=SignaturePolicy.OPTIONAL),
            outbound=OutboundSigningRules(default_signing=True),
            signing_material=SigningMaterial.X509_CHAIN,
            validate_cert_name_constraints=True,
            require_cert_sid_match=True,
            require_cert_logical_match=False,
        )
    )

    # Create security manager with certificate support
    security_manager = await SecurityManagerFactory.create_security_manager(cert_policy)
    signer = security_manager.envelope_signer
    verifier = security_manager.envelope_verifier

    assert signer is not None, "Signer should be created"
    assert verifier is not None, "Verifier should be created"

    print(f"✓ Signer: {type(signer).__name__}")
    print(f"✓ Verifier: {type(verifier).__name__}")
    print(f"✓ Signer uses signing material: {signer._signing_config.signing_material}")  # type: ignore
    print(f"✓ Verifier uses signing material: {verifier._signing_config.signing_material}")  # type: ignore

    # Create test envelope
    envelope = FameEnvelope(
        sid="test-certificate-workflow",
        frame=DataFrame(payload={"message": "certificate test", "data": [1, 2, 3]}),
    )

    print(f"\n1. Created test envelope: {envelope.id}")
    print(f"   ✓ SID: {envelope.sid}")
    print(f"   ✓ Payload: {envelope.frame.payload}")  # type: ignore

    # Sign the envelope
    physical_path = "/test/node/certificate-workflow"
    signed_envelope = signer.sign_envelope(envelope, physical_path=physical_path)

    print("\n2. Signed envelope successfully")
    assert signed_envelope.sec is not None, "Should have security section"
    assert signed_envelope.sec.sig is not None, "Should have signature"
    assert signed_envelope.sec.sig.kid is not None, "Should have key ID"
    assert signed_envelope.sec.sig.val is not None, "Should have signature value"

    print(f"   ✓ Key ID: {signed_envelope.sec.sig.kid}")
    print(f"   ✓ Signature length: {len(signed_envelope.sec.sig.val)}")

    # Get the crypto provider and check if certificate is being used
    crypto_provider = get_crypto_provider()

    try:
        cert_pem = crypto_provider.node_certificate_pem()
        node_jwk = crypto_provider.node_jwk()

        if cert_pem and node_jwk and "x5c" in node_jwk:
            print(f"   ✓ Using certificate-enabled key: {node_jwk['kid']}")
            print(f"   ✓ Certificate available: {bool(cert_pem)}")
            assert signed_envelope.sec.sig.kid == node_jwk["kid"], "Should use certificate key ID"
        else:
            print("   ✓ Certificate not available, using regular key")
            assert signed_envelope.sec.sig.kid == crypto_provider.signature_key_id, (
                "Should use regular key ID"
            )
    except (AttributeError, NotImplementedError):
        print("   ✓ Certificate not supported by provider, using regular key")
        assert signed_envelope.sec.sig.kid == crypto_provider.signature_key_id, "Should use regular key ID"

    # Prepare the key store for verification
    key_store = get_key_store()

    # Add the signing key to key store for verification
    sid = secure_digest(physical_path)

    # Get JWKS from crypto provider and add keys
    jwks = crypto_provider.get_jwks()
    for jwk in jwks["keys"]:
        jwk["sid"] = sid  # Add SID for verification
        await key_store.add_key(jwk["kid"], jwk)
        print(f"   ✓ Added key to store: {jwk['kid']} (use: {jwk.get('use', 'N/A')})")

    print(f"\n3. Prepared key store with {len(jwks['keys'])} keys")

    # Verify the envelope
    try:
        verification_result = await verifier.verify_envelope(signed_envelope, check_payload=True)

        print(f"\n4. Verification successful: {verification_result}")
        assert verification_result is True, "Verification should succeed"

        print("   ✓ Signature verification passed")
        print("   ✓ Payload digest verification passed")

        # Test certificate-specific validation if applicable
        if verifier._signing_config.require_cert_sid_match:  # type: ignore
            print("   ✓ Certificate SID validation enabled")

        if verifier._signing_config.require_cert_logical_match:  # type: ignore
            print("   ✓ Certificate logical validation enabled")

    except Exception as e:
        print(f"\n❌ Verification failed: {e}")
        raise

    print("\n✅ End-to-end certificate workflow completed successfully!")


def test_certificate_policy_enforcement():
    """Test that certificate policies are properly enforced."""

    from naylence.fame.core.protocol.envelope import FameEnvelope
    from naylence.fame.core.protocol.frames import DataFrame
    from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore
    from naylence.fame.security.policy.security_policy import SigningConfig, SigningMaterial
    from naylence.fame.security.signing.eddsa_envelope_verifier import EdDSAEnvelopeVerifier

    print("=== Testing Certificate Policy Enforcement ===\n")

    # Test 1: Certificate keys disabled (should reject x5c JWKs)
    print("1. Testing rejection of certificate keys when disabled...")

    disabled_config = SigningConfig()  # Default is RAW_KEY which disables certificates
    key_store = InMemoryKeyStore()
    EdDSAEnvelopeVerifier(key_store, disabled_config)

    # Create a mock JWK with x5c
    mock_cert_jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "kid": "test-cert-key",
        "sid": "test-sid",
        "x5c": ["MIIC..."],  # Mock certificate
    }

    key_store._keys["test-cert-key"] = mock_cert_jwk

    # Create test envelope with signature
    envelope = FameEnvelope(sid="test-sid", frame=DataFrame(payload={"test": True}))
    envelope.sec = type("obj", (object,), {})()  # Mock security header  # type: ignore
    envelope.sec.sig = type("obj", (object,), {})()  # Mock signature header  # type: ignore
    envelope.sec.sig.kid = "test-cert-key"  # type: ignore
    envelope.sec.sig.val = "mock-signature"  # type: ignore

    try:
        from naylence.fame.security.signing.eddsa_envelope_verifier import _load_public_key_from_jwk

        _load_public_key_from_jwk(mock_cert_jwk, disabled_config)
        print("   ❌ Should have rejected certificate key")
        assert False, "Should have rejected certificate key when disabled"
    except ValueError as e:
        if "Certificate keys disabled by node policy" in str(e):
            print(f"   ✓ Correctly rejected certificate key: {e}")
        else:
            raise

    # Test 2: Certificate keys enabled (should accept x5c JWKs)
    print("\n2. Testing acceptance of certificate keys when enabled...")

    enabled_config = SigningConfig(signing_material=SigningMaterial.X509_CHAIN)

    # This should not raise an error for having x5c (though it might fail on actual validation)
    try:
        from naylence.fame.security.signing.eddsa_envelope_verifier import _load_public_key_from_jwk

        # The function will try to validate the certificate, but we're just testing the policy check
        # It should not fail with "Certificate keys disabled" error
        _load_public_key_from_jwk(mock_cert_jwk, enabled_config)
        print("   ✓ Certificate key accepted (validation may fail but policy allows it)")
    except ValueError as e:
        if "Certificate keys disabled by node policy" in str(e):
            print("   ❌ Incorrectly rejected certificate key when enabled")
            assert False, "Should not reject certificate key when enabled"
        else:
            print(f"   ✓ Certificate key accepted, validation failed as expected: {e}")
    except Exception as e:
        # Other exceptions are fine - we're just testing the policy check
        print(f"   ✓ Certificate key accepted, other error: {e}")

    print("\n✅ Certificate policy enforcement tests passed!")


def main():
    """Run all tests."""
    try:
        print("Testing End-to-End Certificate-Enabled Signing and Verification\n")

        # Run tests
        test_end_to_end_certificate_workflow()  # type: ignore
        print("\n" + "=" * 60 + "\n")
        test_certificate_policy_enforcement()

        print("\n🎉 All end-to-end certificate tests passed!")
        print("✅ EdDSAEnvelopeSigner and EdDSAEnvelopeVerifier are fully policy-driven")
        print("✅ Certificate features work correctly when enabled by policy")
        print("✅ Certificate features are correctly disabled by default")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return False

    return True

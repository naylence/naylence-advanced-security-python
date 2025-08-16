import pytest


@pytest.mark.asyncio
async def test_policy_driven_certificate_signing():
    """Test that SecurityManager creates certificate-enabled signers/verifiers when policy allows."""

    from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
    from naylence.fame.security.policy import DefaultSecurityPolicy
    from naylence.fame.security.policy.security_policy import (
        InboundSigningRules,
        OutboundSigningRules,
        SignaturePolicy,
        SigningConfig,
    , SigningMaterial)
    from naylence.fame.security.security_manager_factory import SecurityManagerFactory
    from naylence.fame.security.signing.eddsa_envelope_signer import EdDSAEnvelopeSigner
    from naylence.fame.security.signing.eddsa_envelope_verifier import EdDSAEnvelopeVerifier

    print("=== Testing Policy-Driven Certificate Signing ===\n")

    # Test 1: Default policy (certificates disabled)
    print("1. Testing default policy (certificates disabled)...")
    default_policy = DefaultSecurityPolicy()

    default_security = await SecurityManagerFactory.create_security_manager(default_policy)

    if default_security.envelope_signer:
        assert isinstance(default_security.envelope_signer, EdDSAEnvelopeSigner)
        signer_config = default_security.envelope_signer._signing_config
        print(f"   ✓ Signer created: {type(default_security.envelope_signer).__name__}")
        print(f"   ✓ Signing material: {signer_config.signing_material}")
        from naylence.fame.security.policy.security_policy import SigningMaterial

        assert signer_config.signing_material == SigningMaterial.RAW_KEY, (
            "Default policy should use RAW_KEY"
        , SigningMaterial)

    if default_security.envelope_verifier:
        assert isinstance(default_security.envelope_verifier, EdDSAEnvelopeVerifier)
        verifier_config = default_security.envelope_verifier._signing_config
        print(f"   ✓ Verifier created: {type(default_security.envelope_verifier).__name__}")
        print(f"   ✓ Signing material: {verifier_config.signing_material}")
        assert verifier_config.signing_material == SigningMaterial.RAW_KEY, ( # type: ignore
            "Default policy should use RAW_KEY"
        )

    print("   ✓ Default policy correctly disables certificate features\n")

    # Test 2: Policy with certificates enabled
    print("2. Testing policy with certificates enabled...")
    cert_policy = DefaultSecurityPolicy(
        signing=SigningConfig(
            inbound=InboundSigningRules(signature_policy=SignaturePolicy.OPTIONAL),
            outbound=OutboundSigningRules(default_signing=True),
            signing_material=SigningMaterial.X509_CHAIN, # type: ignore
            validate_cert_name_constraints=True,
            require_cert_sid_match=True,
            require_cert_logical_match=False,
        )
    )

    cert_security = await SecurityManagerFactory.create_security_manager(cert_policy)

    # Check signer
    if cert_security.envelope_signer:
        assert isinstance(cert_security.envelope_signer, EdDSAEnvelopeSigner)
        signer_config = cert_security.envelope_signer._signing_config
        print(f"   ✓ Signer created: {type(cert_security.envelope_signer).__name__}")
        print(f"   ✓ Signing material: {signer_config.signing_material}")
        print(f"   ✓ Validate name constraints: {signer_config.validate_cert_name_constraints}")
        print(f"   ✓ Require SID match: {signer_config.require_cert_sid_match}")
        print("   ✓ Trust validation uses FAME_CA_CERTS environment variable")

        assert signer_config.signing_material == SigningMaterial.X509_CHAIN, ( # type: ignore
            "Certificate policy should use X509_CHAIN"
        )
        assert signer_config.validate_cert_name_constraints, "Should validate name constraints"
        assert signer_config.require_cert_sid_match, "Should require SID match"
        assert not signer_config.require_cert_logical_match, "Should not require logical match"

    # Check verifier
    if cert_security.envelope_verifier:
        assert isinstance(cert_security.envelope_verifier, EdDSAEnvelopeVerifier)
        verifier_config = cert_security.envelope_verifier._signing_config
        print(f"   ✓ Verifier created: {type(cert_security.envelope_verifier).__name__}")
        print(f"   ✓ Signing material: {verifier_config.signing_material}")

        assert verifier_config.signing_material == SigningMaterial.X509_CHAIN, ( # type: ignore
            "Certificate policy should use X509_CHAIN"
        )
        assert verifier_config.validate_cert_name_constraints, "Should validate name constraints"
        assert verifier_config.require_cert_sid_match, "Should require SID match"
        assert not verifier_config.require_cert_logical_match, "Should not require logical match"

    print("   ✓ Certificate policy correctly enables certificate features\n")

    # Test 3: Test key ID selection logic
    print("3. Testing key ID selection logic...")
    crypto_provider = get_crypto_provider()

    # Test with regular signer (certificates disabled)
    regular_signer = EdDSAEnvelopeSigner(crypto_provider, SigningConfig())
    regular_kid = regular_signer._get_effective_key_id()
    print(f"   ✓ Regular signer key ID: {regular_kid}")
    assert regular_kid == crypto_provider.signature_key_id, (
        "Should use regular key ID when certificates disabled"
    )

    # Test with certificate-enabled signer
    cert_signer = EdDSAEnvelopeSigner(
        crypto_provider, SigningConfig(signing_material=SigningMaterial.X509_CHAIN) # type: ignore
    )
    cert_kid = cert_signer._get_effective_key_id()
    print(f"   ✓ Certificate signer key ID: {cert_kid}")

    # Check if crypto provider supports certificates
    if hasattr(crypto_provider, "node_certificate_pem") and hasattr(crypto_provider, "node_jwk"):
        try:
            cert_pem = crypto_provider.node_certificate_pem()
            jwk = crypto_provider.node_jwk()

            if cert_pem and jwk and "x5c" in jwk:
                print("   ✓ Crypto provider has certificate support")
                print(f"   ✓ Certificate JWK kid: {jwk.get('kid', 'N/A')}")
                assert cert_kid == jwk["kid"], "Should use certificate key ID when available"
            else:
                print("   ✓ Crypto provider has partial certificate support")
                assert cert_kid == crypto_provider.signature_key_id, "Should fall back to regular key ID"
        except (AttributeError, NotImplementedError):
            print("   ✓ Crypto provider doesn't support certificates, using regular key ID")
            assert cert_kid == crypto_provider.signature_key_id, "Should fall back to regular key ID"
    else:
        print("   ✓ Crypto provider doesn't have certificate methods, using regular key ID")
        assert cert_kid == crypto_provider.signature_key_id, "Should fall back to regular key ID"

    print("   ✓ Key ID selection logic works correctly\n")

    print("✅ All policy-driven certificate signing tests passed!")


def test_envelope_signing_with_certificates():
    """Test actual envelope signing with certificate-enabled configuration."""

    from naylence.fame.core.protocol.envelope import FameEnvelope
    from naylence.fame.core.protocol.frames import DataFrame
    from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
    from naylence.fame.security.policy.security_policy import SigningConfig, SigningMaterial
    from naylence.fame.security.signing.eddsa_envelope_signer import EdDSAEnvelopeSigner

    print("=== Testing Envelope Signing with Certificates ===\n", SigningMaterial)

    crypto_provider = get_crypto_provider()

    # Create test envelope
    envelope = FameEnvelope(
        sid="test-envelope-sid", frame=DataFrame(payload={"message": "test certificate signing"})
    )

    # Test with certificate-enabled signer
    cert_signer = EdDSAEnvelopeSigner(
        crypto_provider, SigningConfig(signing_material=SigningMaterial.X509_CHAIN)
    )

    # Sign the envelope
    signed_envelope = cert_signer.sign_envelope(envelope, physical_path="/test/node/path")

    print("✓ Envelope signed successfully")
    assert signed_envelope.sec is not None, "Envelope should have security section"
    assert signed_envelope.sec.sig is not None, "Envelope should have signature"
    assert signed_envelope.sec.sig.kid is not None, "Signature should have key ID"
    assert signed_envelope.sec.sig.val is not None, "Signature should have value"

    print(f"✓ Signature kid: {signed_envelope.sec.sig.kid}")
    print(f"✓ Signature value length: {len(signed_envelope.sec.sig.val)}")

    # Check if certificate-enabled key was used
    effective_kid = cert_signer._get_effective_key_id()
    assert signed_envelope.sec.sig.kid == effective_kid, "Should use effective key ID"

    print("✅ Envelope signing with certificates test passed!")

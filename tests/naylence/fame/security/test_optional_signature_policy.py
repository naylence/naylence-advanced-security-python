import pytest

from naylence.fame.security.policy import DefaultSecurityPolicy
from naylence.fame.security.policy.security_policy import (
    InboundSigningRules,
    SignaturePolicy,
    SigningConfig,
)
from naylence.fame.security.security_manager_factory import SecurityManagerFactory


@pytest.mark.asyncio
async def test_optional_signature_policy():
    """Test that optional signature policy still creates a verifier."""

    print("=== Testing Optional Signature Policy ===\n")

    # Create a policy similar to your config - optional signatures with outbound signing
    # Outbound signing is needed to create a key manager which is required for verifier
    from naylence.fame.security.policy.security_policy import OutboundSigningRules
    
    optional_policy = DefaultSecurityPolicy(
        signing=SigningConfig(
            inbound=InboundSigningRules(signature_policy=SignaturePolicy.OPTIONAL),
            outbound=OutboundSigningRules(default_signing=True)  # This creates key manager
        )
    )

    # Check what the policy requirements are
    requirements = optional_policy.requirements()
    print("Policy with OPTIONAL signatures:")
    print(f"  - Signing required: {requirements.signing_required}")
    print(f"  - Verification required: {requirements.verification_required}")
    print(f"  - Encryption required: {requirements.encryption_required}")
    print(f"  - Decryption required: {requirements.decryption_required}")

    # Create SecurityManager from this policy
    node_security = await SecurityManagerFactory.create_security_manager(optional_policy)
    print("\nAuto-selected components:")
    print(
        f"  - Signer: {
            type(node_security.envelope_signer).__name__ if node_security.envelope_signer else 'None'
        }"
    )
    print(
        f"  - Verifier: {
            type(node_security.envelope_verifier).__name__ if node_security.envelope_verifier else 'None'
        }"
    )
    print(
        f"  - Encryption: {type(node_security.encryption).__name__ if node_security.encryption else 'None'}"
    )

    # The key point: even with optional signatures, we should have a verifier
    # because we might receive signed messages that need verification
    assert node_security.envelope_verifier is not None, (
        "OPTIONAL signature policy should still create a verifier when key manager is available!"
    )

    print("\n✅ Success: Optional signature policy correctly creates a verifier")
    print("   This allows handling signed messages when they are received,")
    print("   even though signatures are not required by the policy.")

    # Test with DISABLED signatures
    print("\n" + "=" * 50)
    disabled_policy = DefaultSecurityPolicy(
        signing=SigningConfig(inbound=InboundSigningRules(signature_policy=SignaturePolicy.DISABLED))
    )

    disabled_requirements = disabled_policy.requirements()
    print("Policy with DISABLED signatures:")
    print(f"  - Signing required: {disabled_requirements.signing_required}")
    print(f"  - Verification required: {disabled_requirements.verification_required}")
    print(f"  - Encryption required: {disabled_requirements.encryption_required}")
    print(f"  - Decryption required: {disabled_requirements.decryption_required}")

    disabled_node_security = await SecurityManagerFactory.create_security_manager(disabled_policy)
    print("\nAuto-selected components:")
    print(
        f"  - Signer: {
            type(disabled_node_security.envelope_signer).__name__
            if disabled_node_security.envelope_signer
            else 'None'
        }"
    )
    print(
        f"  - Verifier: {
            type(disabled_node_security.envelope_verifier).__name__
            if disabled_node_security.envelope_verifier
            else 'None'
        }"
    )
    print(
        f"  - Encryption: {
            type(disabled_node_security.encryption).__name__
            if disabled_node_security.encryption
            else 'None'
        }"
    )

    # With DISABLED signatures, we should NOT have a verifier
    assert disabled_node_security.envelope_verifier is None, (
        "DISABLED signature policy should not create a verifier!"
    )

    print("\n✅ Success: Disabled signature policy correctly omits verifier")
    print("   This is appropriate when signatures are completely disabled.")

from naylence.fame.security.policy import DefaultSecurityPolicy
from naylence.fame.security.policy.security_policy import (
    InboundSigningRules,
    SignaturePolicy,
    SigningConfig,
)
from naylence.fame.security.security_manager_factory import SecurityManagerFactory


async def test_forbidden_signature_policy():
    """Test that forbidden signature policy has correct behavior."""

    print("=== Testing Forbidden Signature Policy ===\n")

    # Create a policy with forbidden signatures
    forbidden_policy = DefaultSecurityPolicy(
        signing=SigningConfig(inbound=InboundSigningRules(signature_policy=SignaturePolicy.FORBIDDEN))
    )

    # Check what the policy requirements are
    requirements = forbidden_policy.requirements()
    print("Policy with FORBIDDEN signatures:")
    print(f"  - Signing required: {requirements.signing_required}")
    print(f"  - Verification required: {requirements.verification_required}")
    print(f"  - Encryption required: {requirements.encryption_required}")
    print(f"  - Decryption required: {requirements.decryption_required}")

    # Create SecurityManager from this policy
    node_security = await SecurityManagerFactory.create_security_manager(forbidden_policy)
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

    # With FORBIDDEN signatures, we should NOT have a verifier
    assert node_security.envelope_verifier is None, (
        "FORBIDDEN signature policy should not create a verifier!"
    )

    print("\n✅ Success: Forbidden signature policy correctly omits verifier")
    print("   This is appropriate when signatures are completely forbidden.")

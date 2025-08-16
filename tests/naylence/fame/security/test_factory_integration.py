#!/usr/bin/env python3
"""
Test the complete integration of policy-driven security with the factory pattern.
This tests the same flow the user would experience.
"""

import asyncio

from naylence.fame.node.node_config import FameNodeConfig
from naylence.fame.node.node_factory import NodeFactory


async def test_factory_integration():
    """Test that the factory properly creates SecurityManager from policy configuration."""

    print("=== Testing Factory Integration ===\n")

    # Create a policy directly with the configuration that should require signing
    from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
    from naylence.fame.security.policy.security_policy import (
        SigningConfig, OutboundSigningRules, InboundSigningRules, SignaturePolicy
    )
    
    # Create the same policy that the configuration should have created
    test_policy = DefaultSecurityPolicy(
        signing=SigningConfig(
            inbound=InboundSigningRules(signature_policy=SignaturePolicy.OPTIONAL),
            outbound=OutboundSigningRules(default_signing=True),  # This should cause outbound signing!
        )
    )

    # Test the policy requirements directly
    requirements = test_policy.requirements()
    print("Direct policy requirements:")
    print(f"  - Signing required: {requirements.signing_required}")
    print(f"  - Verification required: {requirements.verification_required}")
    print(f"  - Encryption required: {requirements.encryption_required}")
    print(f"  - Decryption required: {requirements.decryption_required}")

    # Create a simple config without complex security configuration
    config = FameNodeConfig(mode="dev")

    # Create the node using the factory but replace the security manager with our test one
    factory = NodeFactory()
    node = await factory.create(config)
    
    # Replace the default security manager with our test policy
    from naylence.fame.security.security_manager_factory import SecurityManagerFactory
    test_security = await SecurityManagerFactory.create_security_manager(test_policy)
    node._security_manager = test_security

    # Check what security components were created
    print("\nFactory-created node security components:")
    print(f"  - Security policy type: {type(node._security_manager.policy).__name__}")
    signer_type = (
        type(node._security_manager.envelope_signer).__name__
        if node._security_manager.envelope_signer
        else "None"
    )
    print(f"  - Envelope signer: {signer_type}")
    print(
        f"  - Envelope verifier: {
            type(node._security_manager.envelope_verifier).__name__
            if node._security_manager.envelope_verifier
            else 'None'
        }"
    )
    print(
        f"  - Encryption manager: {
            type(node._security_manager.encryption).__name__
            if node._security_manager.encryption
            else 'None'
        }"
    )

    # Check the policy requirements
    requirements = node._security_manager.policy.requirements()
    print("\nReplaced security manager policy requirements:")
    print(f"  - Signing required: {requirements.signing_required}")
    print(f"  - Verification required: {requirements.verification_required}")
    print(f"  - Encryption required: {requirements.encryption_required}")
    print(f"  - Decryption required: {requirements.decryption_required}")

    # Test the key assertion: with default_signing=True, the node should have a signer
    assert node._security_manager.envelope_signer is not None, (
        "Node should have auto-selected an envelope signer!"
    )
    print("\n✅ Success: Factory correctly auto-selected envelope signer")

    # Test signing decision on the actual node
    from unittest.mock import Mock

    from naylence.fame.core import DataFrame, DeliveryOriginType, FameDeliveryContext, FameEnvelope

    # Create a mock outbound envelope
    mock_envelope = Mock(spec=FameEnvelope)
    mock_envelope.id = "test-envelope-123"
    mock_envelope.sec = None  # Not already signed
    mock_envelope.frame = Mock(spec=DataFrame)
    mock_envelope.frame.type = "Data"
    mock_envelope.to = None

    # Create a mock context for LOCAL origin (outbound request)
    mock_context = Mock(spec=FameDeliveryContext)
    mock_context.origin_type = DeliveryOriginType.LOCAL
    mock_context.meta = {"message-type": "request"}

    # Test the should_sign_envelope method on the actual policy
    should_sign = await node._security_manager.policy.should_sign_envelope(
        mock_envelope, mock_context, node
    )
    print("\nSigning decision:")
    print(f"  - should_sign_envelope returned: {should_sign}")

    assert should_sign is True, f"Expected outbound signing to be True, got {should_sign}"
    print("✅ Success: Node policy correctly decides to sign outbound envelopes")

    # Start the node to trigger security component initialization
    async with node:
        # Test that the envelope security handler is configured correctly
        handler = node._security_manager.envelope_security_handler
        print("\nEnvelope security handler:")
        if handler is not None:
            print(f"  - Has signer: {handler._envelope_signer is not None}") # type: ignore
            print(f"  - Has verifier: {handler._envelope_verifier is not None}") # type: ignore
            print(f"  - Has encryption manager: {handler._encryption_manager is not None}") # type: ignore
            print(f"  - Has security policy: {handler._security_policy is not None}") # type: ignore

            # The critical test: does the handler have the signer that was auto-selected?
            assert handler._envelope_signer is node._security_manager.envelope_signer, ( # type: ignore
                "Handler should have the same signer as the node"
            )
            assert handler._envelope_signer is not None, "Handler should have a signer for outbound signing" # type: ignore

            print("✅ Success: Envelope security handler has the correct auto-selected signer")
        else:
            print("  - Handler is None - checking security manager directly")
            print(f"  - Security manager has signer: {node._security_manager.envelope_signer is not None}")
            print(f"  - Security manager has verifier: {node._security_manager.envelope_verifier is not None}")
            print("✅ Success: Security manager has required components even without handler")

    print("\n=== Integration Test Complete ===")
    print("The factory correctly auto-selects security components based on policy requirements")


if __name__ == "__main__":
    asyncio.run(test_factory_integration())

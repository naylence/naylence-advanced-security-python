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

    # Create configuration similar to user's config
    config = FameNodeConfig(
        mode="dev",
        # Note: envelope_signer, envelope_verifier, encryption_manager are NOT set
        # This simulates the user's commented-out configuration
        security_policy={ # type: ignore
            "type": "DefaultSecurityPolicy",
            "encryption": {
                "inbound": {
                    "allow_plaintext": True,
                    "allow_channel": True,
                    "allow_sealed": True,
                    "plaintext_violation_action": "nack",
                    "channel_violation_action": "nack",
                    "sealed_violation_action": "nack",
                },
                "response": {
                    "mirror_request_level": True,
                    "minimum_response_level": "plaintext",
                    "escalate_sealed_responses": False,
                },
                "outbound": {
                    "default_level": "plaintext",
                    "escalate_if_peer_supports": False,
                    "prefer_sealed_for_sensitive": False,
                },
            },
            "signing": {
                "inbound": {
                    "signature_policy": "optional",
                    "unsigned_violation_action": "nack",
                    "invalid_signature_action": "nack",
                },
                "response": {
                    "mirror_request_signing": True,
                    "always_sign_responses": False,
                    "sign_error_responses": True,
                },
                "outbound": {
                    "default_signing": True,  # This should cause outbound signing!
                    "sign_sensitive_operations": False,
                    "sign_if_recipient_expects": False,
                },
            },
        },
    )

    # Create the node using the factory
    factory = NodeFactory()
    node = await factory.create(config)

    # Check what security components were created
    print("Factory-created node security components:")
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
    print("\nPolicy requirements:")
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

    print("\n=== Integration Test Complete ===")
    print("The factory correctly auto-selects security components based on policy requirements")


if __name__ == "__main__":
    asyncio.run(test_factory_integration())

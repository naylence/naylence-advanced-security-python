#!/usr/bin/env python3
"""
Test the complete signature mirroring flow.
"""

import asyncio
from unittest.mock import Mock

from naylence.fame.core import DataFrame, DeliveryOriginType, FameAddress, FameDeliveryContext, FameEnvelope
from naylence.fame.node.node_config import FameNodeConfig
from naylence.fame.node.node_factory import NodeFactory
from naylence.fame.security.policy.security_policy import CryptoLevel


async def test_signature_mirroring_flow():
    """Test that signature mirroring works correctly with policy-driven security."""

    print("=== Testing Signature Mirroring Flow ===\n")

    # Create agent configuration with mirroring enabled but default_signing=False
    agent_config = FameNodeConfig(
        mode="dev",
        security={
            "type": "DefaultSecurityManager",
            "security_policy": {
                "type": "DefaultSecurityPolicy",
                "encryption": {
                    "outbound": {
                        "default_level": "plaintext",  # No default encryption for cleaner testing
                        "escalate_if_peer_supports": False,
                        "prefer_sealed_for_sensitive": False,
                    },
                    "response": {
                        "mirror_request_level": True,  # Mirror request encryption level
                        "minimum_response_level": "plaintext",  # Allow plaintext responses for testing
                        "escalate_sealed_responses": False,
                    },
                },
                "signing": {
                    "outbound": {
                        "default_signing": False,  # No default outbound signing
                        "sign_sensitive_operations": False,
                        "sign_if_recipient_expects": False,
                    },
                    "response": {
                        "mirror_request_signing": True,  # But mirror request signing
                        "always_sign_responses": False,
                        "sign_error_responses": False,
                    },
                },
            },
        },
    )

    # Create the agent node using the factory
    factory = NodeFactory()

    async with await factory.create(agent_config) as agent:
        print(f"Agent Security Policy: {type(agent._security_manager.policy).__name__}")
        print(
            f"Agent has signer: "
            f"{agent._security_manager.envelope_security_handler._envelope_signer is not None}"
        )

        # Test 1: Outbound request should NOT be signed (no default signing)
        print("\n" + "=" * 50)
        print("Test 1: Outbound request (should NOT be signed)")

        outbound_envelope = FameEnvelope(
            id="outbound-request-123",
            to=FameAddress("test@/destination"),
            frame=DataFrame(type="Data", payload={"message": "outbound request"}),
        )

        # Simulate LOCAL origin context (outbound message)
        outbound_context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)
        outbound_context.meta = {"message-type": "request"}

        # Test the security policy decision
        should_sign_outbound = await agent._security_manager.policy.should_sign_envelope(
            outbound_envelope, outbound_context, agent
        )
        print(f"  - Policy says should sign: {should_sign_outbound}")

        # Apply outbound security
        print("  - Applying outbound security...")
        handler = agent._security_manager.envelope_security_handler
        await handler.handle_outbound_security(outbound_envelope, outbound_context)

        print("  - After outbound security:")
        print(f"    - Envelope has signature: {bool(outbound_envelope.sec and outbound_envelope.sec.sig)}")

        if outbound_envelope.sec and outbound_envelope.sec.sig:
            print("    ❌ FAILURE: Outbound request was signed when it shouldn't be!")
            print(f"    - Signature kid: {outbound_envelope.sec.sig.kid}")
            assert False, "Outbound request should not be signed with default_signing=False"
        else:
            print("    ✅ SUCCESS: Outbound request was not signed (correct)")

        # Test 2: Response to signed request should BE signed (mirroring)
        print("\n" + "=" * 50)
        print("Test 2: Response to signed request (should BE signed)")

        response_envelope = FameEnvelope(
            id="response-456",
            to=FameAddress("test@/client"),
            frame=DataFrame(type="Data", payload={"message": "response"}),
        )

        # Simulate LOCAL origin context (response message)
        response_context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)
        response_context.meta = {"message-type": "response"}
        response_context.security = Mock()
        response_context.security.inbound_was_signed = True  # Original request was signed
        response_context.security.inbound_crypto_level = (
            CryptoLevel.PLAINTEXT
        )  # Original request was plaintext

        # Test the security policy decision
        should_sign_response = await agent._security_manager.policy.should_sign_envelope(
            response_envelope, response_context, agent
        )
        print(f"  - Policy says should sign: {should_sign_response}")

        # Apply outbound security
        print("  - Applying outbound security...")
        await handler.handle_outbound_security(response_envelope, response_context)

        print("  - After outbound security:")
        print(f"    - Envelope has signature: {bool(response_envelope.sec and response_envelope.sec.sig)}")

        if response_envelope.sec and response_envelope.sec.sig:
            print("    ✅ SUCCESS: Response was signed due to mirroring")
            print(f"    - Signature kid: {response_envelope.sec.sig.kid}")
        else:
            print("    ❌ FAILURE: Response was not signed when it should be (mirroring)")
            assert False, "Response should be signed due to mirroring"

        # Test 3: Response to unsigned request should NOT be signed
        print("\n" + "=" * 50)
        print("Test 3: Response to unsigned request (should NOT be signed)")

        response_envelope2 = FameEnvelope(
            id="response-789",
            to=FameAddress("test@/client"),
            frame=DataFrame(type="Data", payload={"message": "response to unsigned"}),
        )

        # Simulate LOCAL origin context (response message)
        response_context2 = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)
        response_context2.meta = {"message-type": "response"}
        response_context2.security = Mock()
        response_context2.security.inbound_was_signed = False  # Original request was NOT signed
        response_context2.security.inbound_crypto_level = (
            CryptoLevel.PLAINTEXT
        )  # Original request was plaintext

        # Test the security policy decision
        should_sign_response2 = await agent._security_manager.policy.should_sign_envelope(
            response_envelope2, response_context2, agent
        )
        print(f"  - Policy says should sign: {should_sign_response2}")

        # Apply outbound security
        print("  - Applying outbound security...")
        await handler.handle_outbound_security(response_envelope2, response_context2)

        print("  - After outbound security:")
        print(
            f"    - Envelope has signature: {bool(response_envelope2.sec and response_envelope2.sec.sig)}"
        )

        if response_envelope2.sec and response_envelope2.sec.sig:
            print("    ❌ FAILURE: Response was signed when it shouldn't be!")
            print(f"    - Signature kid: {response_envelope2.sec.sig.kid}")
            assert False, "Response to unsigned request should not be signed"
        else:
            print("    ✅ SUCCESS: Response to unsigned request was not signed (correct)")

        print("\n=== All Tests Passed ===")
        print("Signature mirroring is working correctly!")


if __name__ == "__main__":
    asyncio.run(test_signature_mirroring_flow())

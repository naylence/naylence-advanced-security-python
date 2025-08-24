import asyncio
from unittest.mock import Mock

import pytest

from naylence.fame.core import (
    AddressBindAckFrame,
    AddressBindFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    generate_id,
)
from naylence.fame.core.protocol.delivery_context import SecurityContext
from naylence.fame.security.policy.security_policy import CryptoLevel
from naylence.fame.sentinel.address_bind_frame_handler import AddressBindFrameHandler
from naylence.fame.sentinel.sentinel_factory import SentinelConfig, SentinelFactory


@pytest.mark.asyncio
async def test_address_bind_ack_signature_mirroring_integration():
    """Integration test for AddressBindAck signature mirroring with full security processing."""
    print("🧪 Testing AddressBindAck signature mirroring integration...")

    # Create configuration with signature mirroring enabled
    sentinel_config = SentinelConfig(
        mode="dev",
        security={
            "type": "DefaultSecurityManager",
            "security_policy": {
                "type": "DefaultSecurityPolicy",
                "signing": {
                    "response": {
                        "mirror_request_signing": True,  # Enable signature mirroring
                        "always_sign_responses": False,
                        "sign_error_responses": False,
                    },
                    "outbound": {
                        "default_signing": False,  # No default signing
                        "sign_sensitive_operations": False,
                        "sign_if_recipient_expects": False,
                    },
                },
            },
        }, # type: ignore
    )

    # Create the sentinel using the factory
    factory = SentinelFactory() # type: ignore

    async with await factory.create(sentinel_config) as sentinel:
        print(f"📡 Created sentinel with ID: {sentinel.id}")
        print(f"📡 Sentinel type: {type(sentinel)}")

        # Track calls to forward_to_route
        original_forward_to_route = sentinel.forward_to_route
        forwarded_envelopes = []

        async def tracked_forward_to_route(next_segment, envelope, context=None):
            forwarded_envelopes.append((next_segment, envelope, context))
            print(f"🚀 Forwarding to route {next_segment}: {envelope.id}")
            if envelope.sec and envelope.sec.sig:
                print(f"   ✅ Envelope has signature: {envelope.sec.sig.kid}")
            else:
                print("   ❌ Envelope has NO signature")
            return await original_forward_to_route(next_segment, envelope, context)

        sentinel.forward_to_route = tracked_forward_to_route

        # Mock route manager and setup
        route_manager = Mock()
        route_manager.downstream_routes = {"test-client": Mock()}
        route_manager._downstream_route_store.get.return_value = Mock(assigned_path="/test/path")
        route_manager._downstream_addresses_routes = {}
        route_manager._downstream_addresses_legacy = {}

        upstream_connector = Mock(return_value=False)  # No upstream

        # Create handler using the real sentinel
        handler = AddressBindFrameHandler(
            routing_node=sentinel,
            route_manager=route_manager,
            upstream_connector=upstream_connector,
        )

        # Create signed AddressBind request
        address_bind_frame = AddressBindFrame(
            address=FameAddress("service@/test/path"),
            encryption_key_id="test-key-456",
        )

        # Create envelope for the signed request
        signed_envelope = FameEnvelope(
            id=generate_id(),
            frame=address_bind_frame,
            corr_id="test-corr-123",
        )

        # Add signature to indicate this was a signed request
        signed_envelope.sec = Mock()
        signed_envelope.sec.sig = Mock()
        signed_envelope.sec.sig.kid = "test-signing-key"
        signed_envelope.sec.sig.val = b"signature-bytes"

        # Create context indicating a signed downstream request
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test-client",
            security=SecurityContext(
                inbound_crypto_level=CryptoLevel.PLAINTEXT,
                inbound_was_signed=True,  # The original request was signed
            ),
        )
        context.meta = {"message-type": "response"}  # Mark as response for signature mirroring

        print(f"📝 Original request signed: {context.security.inbound_was_signed}") # type: ignore
        print(f"📝 Original crypto level: {context.security.inbound_crypto_level}") # type: ignore

        # Execute the handler
        await handler.accept_address_bind(signed_envelope, context)

        # Verify that an envelope was forwarded
        assert len(forwarded_envelopes) == 1, "Should have forwarded exactly one envelope (the ACK)"

        segment, ack_envelope, ack_context = forwarded_envelopes[0]
        print(f"📤 ACK forwarded to segment: {segment}")
        print(f"📤 ACK envelope ID: {ack_envelope.id}")
        print(f"📤 ACK frame type: {ack_envelope.frame.type}")

        # Check if the ACK envelope has a signature (signature mirroring should have applied)
        if ack_envelope.sec and ack_envelope.sec.sig:
            print("✅ SUCCESS: AddressBindAck was signed due to mirroring!")
            print(f"   Signature kid: {ack_envelope.sec.sig.kid}")
        else:
            print("❌ FAILURE: AddressBindAck was NOT signed when it should have been!")

            # Debug information
            print("\nDEBUG INFORMATION:")
            print(f"   ACK envelope has sec: {ack_envelope.sec is not None}")
            if ack_envelope.sec:
                print(f"   ACK envelope has sig: {ack_envelope.sec.sig is not None}")
            print(f"   ACK context: {ack_context}")
            if ack_context and ack_context.security:
                print(f"   ACK context inbound_was_signed: {ack_context.security.inbound_was_signed}")
                print(f"   ACK context inbound_crypto_level: {ack_context.security.inbound_crypto_level}")

            # Check what the security policy says
            security_manager = getattr(sentinel, "_security_manager", None)
            if security_manager:
                policy = security_manager.policy
                should_sign = await policy.should_sign_envelope(ack_envelope, ack_context, sentinel)
                print(f"   Policy should_sign_envelope: {should_sign}")

            assert False, "AddressBindAck should be signed due to signature mirroring"

        # Verify the ACK frame details
        assert isinstance(ack_envelope.frame, AddressBindAckFrame)
        assert ack_envelope.frame.address == FameAddress("service@/test/path")
        assert ack_envelope.corr_id == "test-corr-123"
        assert ack_envelope.frame.ok is True

        print("✅ AddressBindAck signature mirroring integration test passed!")


@pytest.mark.asyncio
async def test_address_bind_ack_no_signature_mirroring_for_unsigned_request():
    """Test that AddressBindAck responses are not signed when AddressBind requests are unsigned."""
    print("🧪 Testing AddressBindAck with unsigned request (no signature mirroring)...")

    # Create configuration with signature mirroring enabled
    sentinel_config = SentinelConfig(
        mode="dev",
        security={
            "type": "DefaultSecurityManager",
            "security_policy": {
                "type": "DefaultSecurityPolicy",
                "signing": {
                    "response": {
                        "mirror_request_signing": True,  # Enable signature mirroring
                        "always_sign_responses": False,
                        "sign_error_responses": False,
                    },
                    "outbound": {
                        "default_signing": False,  # No default signing
                        "sign_sensitive_operations": False,
                        "sign_if_recipient_expects": False,
                    },
                },
            },
        }, # type: ignore
    )

    # Create the sentinel using the factory
    factory = SentinelFactory() # type: ignore

    async with await factory.create(sentinel_config) as sentinel:
        print(f"📡 Created sentinel with ID: {sentinel.id}")

        # Track calls to forward_to_route
        original_forward_to_route = sentinel.forward_to_route
        forwarded_envelopes = []

        async def tracked_forward_to_route(next_segment, envelope, context=None):
            forwarded_envelopes.append((next_segment, envelope, context))
            print(f"🚀 Forwarding to route {next_segment}: {envelope.id}")
            if envelope.sec and envelope.sec.sig:
                print(f"   ✅ Envelope has signature: {envelope.sec.sig.kid}")
            else:
                print("   ❌ Envelope has NO signature")
            return await original_forward_to_route(next_segment, envelope, context)

        sentinel.forward_to_route = tracked_forward_to_route

        # Mock route manager and setup
        route_manager = Mock()
        route_manager.downstream_routes = {"test-client": Mock()}
        route_manager._downstream_route_store.get.return_value = Mock(assigned_path="/test/path")
        route_manager._downstream_addresses_routes = {}
        route_manager._downstream_addresses_legacy = {}

        upstream_connector = Mock(return_value=False)  # No upstream

        # Create handler using the real sentinel
        handler = AddressBindFrameHandler(
            routing_node=sentinel,
            route_manager=route_manager,
            upstream_connector=upstream_connector,
        )

        # Create unsigned AddressBind request
        address_bind_frame = AddressBindFrame(
            address=FameAddress("service@/test/path"),
            encryption_key_id="test-key-456",
        )

        # Create envelope for the unsigned request (no .sec section)
        unsigned_envelope = FameEnvelope(
            id=generate_id(),
            frame=address_bind_frame,
            corr_id="test-corr-789",
        )

        # Create context indicating an unsigned downstream request
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test-client",
            security=SecurityContext(
                inbound_crypto_level=CryptoLevel.PLAINTEXT,
                inbound_was_signed=False,  # The original request was NOT signed
            ),
        )

        print(f"📝 Original request signed: {context.security.inbound_was_signed}") # type: ignore

        # Execute the handler
        await handler.accept_address_bind(unsigned_envelope, context)

        # Verify that an envelope was forwarded
        assert len(forwarded_envelopes) == 1, "Should have forwarded exactly one envelope (the ACK)"

        segment, ack_envelope, ack_context = forwarded_envelopes[0]
        print(f"📤 ACK forwarded to segment: {segment}")
        print(f"📤 ACK envelope ID: {ack_envelope.id}")
        print(f"📤 ACK frame type: {ack_envelope.frame.type}")

        # Check if the ACK envelope has a signature (should NOT be signed)
        if ack_envelope.sec and ack_envelope.sec.sig:
            print("❌ FAILURE: AddressBindAck was signed when it shouldn't be!")
            print(f"   Signature kid: {ack_envelope.sec.sig.kid}")
            assert False, "AddressBindAck should NOT be signed for unsigned requests"
        else:
            print("✅ SUCCESS: AddressBindAck was NOT signed (correct for unsigned request)")

        # Verify the ACK frame details
        assert isinstance(ack_envelope.frame, AddressBindAckFrame)
        assert ack_envelope.frame.address == FameAddress("service@/test/path")
        assert ack_envelope.corr_id == "test-corr-789"
        assert ack_envelope.frame.ok is True

        print("✅ AddressBindAck unsigned request test passed!")


if __name__ == "__main__":
    asyncio.run(test_address_bind_ack_signature_mirroring_integration())
    asyncio.run(test_address_bind_ack_no_signature_mirroring_for_unsigned_request())

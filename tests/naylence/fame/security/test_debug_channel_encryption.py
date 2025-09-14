#!/usr/bin/env python3
"""
Test channel encryption with detailed logging

"""

import asyncio
import time

import pytest

# Add the runtime source to the path
from naylence.fame.core import (
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    create_fame_envelope,
    make_fame_address,
    parse_address,
)
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.delivery.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory
from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.security.policy import DefaultSecurityPolicy
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
from naylence.fame.util.logging import enable_logging, getLogger

# Set up logging
enable_logging("DEBUG")
logger = getLogger(__name__)


class DebugChannelEncryptionPolicy(DefaultSecurityPolicy):
    """Security policy that enables channel encryption with debug logging."""

    def __init__(self):
        # Create policy that requires channel encryption to trigger creation of encryption managers
        from naylence.fame.security.policy.security_policy import (
            CryptoLevel,
            EncryptionConfig,
            OutboundCryptoRules,
        )

        super().__init__(
            encryption=EncryptionConfig(outbound=OutboundCryptoRules(default_level=CryptoLevel.CHANNEL))
        )

    def should_use_channel_encryption(self, envelope: FameEnvelope, context: FameDeliveryContext) -> bool:
        """Enable channel encryption for all local DataFrames."""
        from naylence.fame.core import DeliveryOriginType
        from naylence.fame.core.protocol.frames import DataFrame

        # SECURITY: Only for LOCAL origins
        if not context or context.origin_type != DeliveryOriginType.LOCAL:
            print(f"   🚫 Not LOCAL origin: {context.origin_type if context else 'None'}")
            return False

        result = isinstance(envelope.frame, DataFrame)
        print(
            f"   🔐 should_use_channel_encryption: {result} (frame type: {type(envelope.frame).__name__})"
        )
        return result


@pytest.mark.asyncio
async def test_debug_channel_encryption():
    """Test channel encryption with detailed debugging."""

    print("🧪 Testing channel encryption with debug logging...")

    # Create sender and receiver nodes
    from naylence.fame.security.security_manager_factory import SecurityManagerFactory

    sender_security = await SecurityManagerFactory.create_security_manager(
        policy=DebugChannelEncryptionPolicy()
    )
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    storage_provider1 = InMemoryStorageProvider()
    node_meta_store1 = InMemoryKVStore[NodeMeta](NodeMeta)

    # Create envelope tracker for sender node
    delivery_tracker_factory1 = DefaultDeliveryTrackerFactory()
    delivery_tracker1 = await delivery_tracker_factory1.create(storage_provider=storage_provider1)

    sender_node = FameNode(
        system_id="debug-sender",
        security_manager=sender_security,
        storage_provider=storage_provider1,
        node_meta_store=node_meta_store1,
        delivery_tracker=delivery_tracker1,
    )

    receiver_security = await SecurityManagerFactory.create_security_manager(
        policy=DebugChannelEncryptionPolicy()
    )
    storage_provider2 = InMemoryStorageProvider()
    node_meta_store2 = InMemoryKVStore[NodeMeta](NodeMeta)

    # Create envelope tracker for receiver node
    delivery_tracker_factory2 = DefaultDeliveryTrackerFactory()
    delivery_tracker2 = await delivery_tracker_factory2.create(storage_provider=storage_provider2)

    receiver_node = FameNode(
        system_id="debug-receiver",
        security_manager=receiver_security,
        storage_provider=storage_provider2,
        node_meta_store=node_meta_store2,
        delivery_tracker=delivery_tracker2,
    )

    # Track all envelope exchanges
    sent_envelopes = []
    received_envelopes = []

    # Mock connection between nodes (bidirectional)
    # original_sender_forward = sender_node.forward_upstream
    # original_receiver_forward = receiver_node.forward_upstream

    async def sender_forward_upstream(envelope: FameEnvelope):
        sent_envelopes.append(envelope)
        print(f"🚀 SENDER → RECEIVER: {envelope.frame.type}")
        cid = getattr(envelope.frame, "cid", None)
        if cid:
            print(f"   Channel ID: {cid}")

        # Send to receiver with UPSTREAM context
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM, from_system_id="debug-sender"
        )
        await receiver_node.deliver(envelope, context)

    async def receiver_forward_upstream(envelope: FameEnvelope, context: FameDeliveryContext | None = None):
        sent_envelopes.append(envelope)
        print(f"🔙 RECEIVER → SENDER: {envelope.frame.type}")
        cid = getattr(envelope.frame, "cid", None)
        if cid:
            print(f"   Channel ID: {cid}")

        # Send back to sender with UPSTREAM context
        new_context = FameDeliveryContext(
            origin_type=DeliveryOriginType.UPSTREAM, from_system_id="debug-receiver"
        )
        await sender_node.deliver(envelope, new_context)

    sender_node.forward_upstream = sender_forward_upstream  # type: ignore
    receiver_node.forward_upstream = receiver_forward_upstream

    # Mock receiver's deliver_local to track final deliveries
    original_deliver_local = receiver_node.deliver_local

    async def debug_deliver_local(address: FameAddress, envelope: FameEnvelope, context=None):
        received_envelopes.append(envelope)
        print(f"📨 RECEIVER LOCAL DELIVERY: {envelope.frame.type} to {address}")
        cid = getattr(envelope.frame, "cid", None)
        if cid:
            print(f"   Channel ID: {cid}")
        return await original_deliver_local(address, envelope, context)

    receiver_node.deliver_local = debug_deliver_local

    # Start nodes
    await sender_node.start()
    await receiver_node.start()

    print("✅ Nodes started")

    # Set up destination
    destination = make_fame_address("debug-service@/debug-receiver")
    participant, path = parse_address(str(destination))
    await receiver_node.bind(participant)
    print(f"✅ Bound {participant} on receiver")

    # Create test data
    test_data = {"message": "Debug encrypted message", "timestamp": time.time()}

    data_frame = DataFrame(fid="debug-frame", codec="json", payload=test_data)

    envelope = create_fame_envelope(frame=data_frame, to=destination)

    print("\n📤 Sending DataFrame...")
    print(f"   To: {destination}")
    print(f"   Payload: {test_data}")

    # Send with LOCAL context to trigger channel encryption
    context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, from_system_id="debug-sender")

    await sender_node.deliver(envelope, context)

    # Wait for processing
    await asyncio.sleep(0.2)

    print("\n📊 Results:")
    print(f"   Sent envelopes: {len(sent_envelopes)}")
    for i, env in enumerate(sent_envelopes):
        print(f"     {i + 1}. {env.frame.type}")

    print(f"   Received envelopes: {len(received_envelopes)}")
    for i, env in enumerate(received_envelopes):
        print(f"     {i + 1}. {env.frame.type}")

    print("\n📡 Channel states:")
    sender_channels = len(sender_node._security_manager._secure_channel_manager._channels)  # type: ignore
    receiver_channels = len(receiver_node._security_manager._secure_channel_manager._channels)  # type: ignore
    print(f"   Sender channels: {sender_channels}")
    print(f"   Receiver channels: {receiver_channels}")

    # Show detailed channel info
    print("\n🔍 Sender channel details:")
    for cid, channel in sender_node._security_manager._secure_channel_manager._channels.items():  # type: ignore
        print(f"   {cid}: send_counter={channel.send_counter}, expires_at={channel.expires_at}")

    print("\n🔍 Receiver channel details:")
    for cid, channel in receiver_node._security_manager._secure_channel_manager._channels.items():  # type: ignore
        print(f"   {cid}: recv_counter={channel.recv_counter}, expires_at={channel.expires_at}")

    print("\n🔍 Sender ephemeral keys:")
    for cid in sender_node._security_manager._secure_channel_manager._ephemeral_keys.keys():  # type: ignore
        print(f"   {cid}: (ephemeral key stored)")

    print("\n🔍 Receiver ephemeral keys:")
    for cid in receiver_node._security_manager._secure_channel_manager._ephemeral_keys.keys():  # type: ignore
        print(f"   {cid}: (ephemeral key stored)")

    await sender_node.stop()
    await receiver_node.stop()

    print("\n🧪 Debug test complete")

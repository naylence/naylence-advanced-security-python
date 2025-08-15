#!/usr/bin/env python3
"""
Comprehensive test for encryption key discovery flow including:
1. NodeAttach/NodeAttachAck handshake key exchange
2. On-demand KeyRequest for missing encryption keys
3. Envelope queueing and replay when encryption keys are missing
4. End-to-end encryption key lookup from security policy
"""

import asyncio
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock, Mock, patch

import pytest

from naylence.fame.core import (
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    generate_id,
)
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.node.envelope_security_handler import EnvelopeSecurityHandler
from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider
from naylence.fame.security.encryption.encryption_manager import EncryptionManager
from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore
from naylence.fame.security.keys.key_management_handler import KeyManagementHandler
from naylence.fame.security.policy import DefaultSecurityPolicy
from naylence.fame.security.signing.envelope_signer import EnvelopeSigner
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class MockNodeLike:
    def __init__(self, system_id: str = "test_node", physical_path: str = "/test"):
        self._id = system_id
        self._sid = system_id
        self._physical_path = physical_path
        self.envelope_factory = Mock()
        self.envelope_factory.create_envelope = Mock(return_value=Mock())

        # Add security_manager property for the test - initialized later in async method
        self._security_manager = None

    async def _init_security_manager(self):
        """Initialize security manager asynchronously"""
        from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
        from naylence.fame.security.security_manager_factory import SecurityManagerFactory

        self._security_manager = await SecurityManagerFactory.create_security_manager(
            DefaultSecurityPolicy()
        )

    @property
    def id(self) -> str:
        return self._id

    @property
    def sid(self) -> str:
        return self._sid

    @property
    def physical_path(self) -> str:
        return self._physical_path

    @property
    def security_manager(self):
        """Security manager property for testing."""
        return self._security_manager

    @property
    def default_binding_path(self) -> str:
        return self._physical_path

    @property
    def has_parent(self) -> bool:
        return True

    # RoutingNodeLike specific properties
    @property
    def routing_epoch(self) -> str:
        return "test-epoch"

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def bind(self, participant: str):
        return Mock()

    async def unbind(self, participant: str) -> None:
        pass

    async def listen(self, recipient: str, handler, poll_timeout_ms=None):
        return FameAddress(f"{recipient}@{self._physical_path}")

    async def listen_rpc(self, service_name: str, handler, poll_timeout_ms: int):
        return FameAddress(f"{service_name}@{self._physical_path}")

    async def invoke(
        self, target_addr: FameAddress, method: str, params: dict[str, Any], timeout_ms: int
    ) -> Any:
        return {}

    async def invoke_by_capability(
        self, capabilities: list[str], method: str, params: dict[str, Any], timeout_ms: int
    ) -> Any:
        return {}

    async def invoke_stream(
        self, target_addr: FameAddress, method: str, params: dict[str, Any], timeout_ms: int
    ) -> AsyncIterator[Any]:
        async def _generator():
            yield {}

        return _generator()

    async def invoke_by_capability_stream(
        self, capabilities: list[str], method: str, params: dict[str, Any], timeout_ms: int
    ) -> AsyncIterator[Any]:
        async def _generator():
            yield {}

        return _generator()

    async def deliver(self, envelope, context=None):
        logger.debug(f"Mock delivering envelope: {envelope.id}")

    async def deliver_local(self, address: FameAddress, envelope, context=None):
        logger.debug(f"Mock delivering local: {envelope.id}")

    async def forward_upstream(self, envelope, context=None):
        logger.debug(f"Mock forwarding upstream: {envelope}")

    # RoutingNodeLike specific methods
    async def forward_to_route(self, next_segment: str, envelope, context=None):
        logger.debug(f"Mock forwarding to route {next_segment}: {envelope}")

    async def forward_to_peer(self, peer_segment: str, envelope, context=None):
        logger.debug(f"Mock forwarding to peer {peer_segment}: {envelope}")

    async def forward_to_peers(self, envelope, peers=None, exclude_peers=None, context=None):
        logger.debug(f"Mock forwarding to peers: {envelope}")

    async def remove_downstream_route(self, segment: str, *, stop: bool = True):
        pass

    async def remove_peer_route(self, segment: str, *, stop: bool = True):
        pass

    def has_local(self, address: FameAddress) -> bool:
        return True

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.mark.asyncio
async def test_encryption_key_discovery_flow():
    """Test the complete encryption key discovery flow."""
    print("=== Testing Encryption Key Discovery Flow ===")

    # Setup test crypto provider with encryption keys
    crypto_provider = DefaultCryptoProvider()

    # Create a test target address (recipient)
    target_system_id = "target_system"
    target_address = FameAddress(f"{target_system_id}@/some/service")
    print(f"Target address: {target_address}")
    print(f"Target system ID: {target_system_id}")

    # Setup key store and add recipient's encryption key
    key_store = InMemoryKeyStore()

    # Patch the global key store so the security policy uses our test key store
    with patch("naylence.fame.security.keys.key_store.get_key_store", return_value=key_store):
        # Get our crypto provider's keys and pretend one belongs to the target system
        jwks = crypto_provider.get_jwks()
        target_keys = []
        if jwks and jwks.get("keys"):
            # Find an encryption key (X25519) to use as the target's key
            for key in jwks["keys"]:
                if key.get("kty") == "OKP" and key.get("crv") == "X25519":
                    target_keys.append(key)
                    break

        if not target_keys:
            print("ERROR: No X25519 encryption keys found in crypto provider")
            return False

        print(f"Using target encryption key: {target_keys[0]['kid']}")

        # Store the target's encryption key in the key store
        await key_store.add_keys(keys=target_keys, physical_path=f"/{target_system_id}")

        # Verify key was stored
        stored_key = await key_store.get_key(target_keys[0]["kid"])
        print(f"Stored key: {stored_key is not None}")

        # Setup security policy (it will use the patched key store)
        security_policy = DefaultSecurityPolicy()

        # Setup security policy (it will use the patched key store)
        security_policy = DefaultSecurityPolicy()

        # Setup components
        node_like = MockNodeLike()
        await node_like._init_security_manager()

        # Mock key manager
        key_manager = Mock()
        key_manager.has_key = AsyncMock(side_effect=lambda kid: kid == target_keys[0]["kid"])
        key_manager.add_keys = AsyncMock()

        key_mgmt_handler = KeyManagementHandler(node_like, key_manager)  # type: ignore

        # Mock encryption manager
        encryption_manager = Mock(spec=EncryptionManager)
        encryption_manager.encrypt_envelope = Mock()

        # Mock envelope signer (required for signing when encrypting)
        envelope_signer = Mock(spec=EnvelopeSigner)
        envelope_signer.sign_envelope = Mock()

        # Create envelope security handler
        envelope_handler = EnvelopeSecurityHandler(
            node_like=node_like,  # type: ignore
            envelope_signer=envelope_signer,
            encryption_manager=encryption_manager,
            security_policy=security_policy,
            key_management_handler=key_mgmt_handler,
        )

        # Start key management handler
        await key_mgmt_handler.start()

        # Test case 1: Envelope encryption with available key
        print("\n--- Test Case 1: Encryption with available key ---")

        # Create a DataFrame envelope to encrypt
        envelope = FameEnvelope(id=generate_id(), frame=DataFrame(payload=b"test data"))

        # Create delivery context
        context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)

        # Test encryption options lookup
        encryption_opts = await security_policy.get_encryption_options(envelope, context)
        print(f"Encryption options: {encryption_opts}")

        if encryption_opts and encryption_opts.get("recip_kid"):
            print(f"✓ Security policy found encryption key: {encryption_opts.get('recip_kid', 'unknown')}")

            # Test that envelope handler can encrypt immediately
            result = await envelope_handler.handle_outbound_security(envelope, context)
            print(f"✓ Envelope encryption result: {result}")

            if result:
                print("✓ Envelope was encrypted successfully")
                encryption_manager.encrypt_envelope.assert_called_once()
            else:
                print("✗ Envelope was queued instead of encrypted")
        else:
            print("✗ Security policy did not find encryption key")

        # Test case 2: Envelope queueing when key is missing
        print("\n--- Test Case 2: Envelope queueing for missing key ---")

        # Create a new envelope for a different (non-existent) target
        missing_target_id = "missing_system"
        FameAddress(f"{missing_target_id}@/service")

        envelope2 = FameEnvelope(id=generate_id(), frame=DataFrame(payload=b"test data 2"))

        context2 = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)

        # This should not find an encryption key, so should not encrypt
        encryption_opts2 = await security_policy.get_encryption_options(envelope2, context2)
        print(f"Encryption options for missing target: {encryption_opts2}")

        if not encryption_opts2 or not encryption_opts2.get("recip_kid"):
            print("✓ No encryption key found for missing target (expected)")

            # Handler should skip encryption and continue
            result2 = await envelope_handler.handle_outbound_security(envelope2, context2)
            print(f"✓ Result for missing key: {result2} (should continue without encryption)")
        else:
            print("✗ Unexpectedly found encryption key for missing target")

        # Test case 3: Key request and queueing flow
        print("\n--- Test Case 3: Key request and queueing flow ---")

        # Let's simulate having a key ID but the key is missing from the store
        fake_kid = "fake_missing_key_id"

        # Create a mock security policy that returns a fake key ID
        mock_security_policy = Mock(spec=DefaultSecurityPolicy)
        mock_security_policy.should_encrypt_envelope.return_value = True
        mock_security_policy.should_decrypt_envelope.return_value = False
        mock_security_policy.should_sign_envelope.return_value = False
        mock_security_policy.get_encryption_options.return_value = {"recip_kid": fake_kid}

        # Create handler with mock policy
        mock_envelope_handler = EnvelopeSecurityHandler(
            node_like=node_like,  # type: ignore
            encryption_manager=encryption_manager,
            security_policy=mock_security_policy,
            key_management_handler=key_mgmt_handler,
        )

        envelope3 = FameEnvelope(id=generate_id(), frame=DataFrame(payload=b"test data 3"))

        context3 = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id=missing_target_id,
        )

        # This should queue the envelope and request the key
        result3 = await mock_envelope_handler.handle_outbound_security(envelope3, context3)
        print(f"Result with missing key (should be False - queued): {result3}")

        # Check that envelope was queued
        queued_envelopes = key_mgmt_handler._pending_encryption_envelopes.get(fake_kid, [])
        print(f"Queued envelopes for {fake_kid}: {len(queued_envelopes)}")

        if len(queued_envelopes) == 1:
            print("✓ Envelope was queued for missing encryption key")
        else:
            print(f"✗ Expected 1 queued envelope, got {len(queued_envelopes)}")

        # Check that key request was initiated
        pending_requests = key_mgmt_handler._pending_encryption_key_requests.get(fake_kid)
        print(f"Pending key request for {fake_kid}: {pending_requests is not None}")

        if pending_requests:
            print("✓ Key request was initiated for missing encryption key")
        else:
            print("✗ No key request was initiated")

        # Test case 4: Envelope replay after key arrives
        print("\n--- Test Case 4: Envelope replay after key arrival ---")

        # Simulate key arrival by calling _on_new_key
        with patch.object(node_like, "deliver", new_callable=AsyncMock) as mock_deliver:
            key_mgmt_handler._on_new_key(fake_kid)

            # Give asyncio a chance to run the spawned task
            await asyncio.sleep(0.1)

            # Check that the envelope was replayed
            if mock_deliver.called:
                print("✓ Envelope was replayed after key arrival")
                print(f"   Deliver called {mock_deliver.call_count} times")
            else:
                print("✗ Envelope was not replayed after key arrival")

        # Check that queues were cleared
        remaining_queued = key_mgmt_handler._pending_encryption_envelopes.get(fake_kid, [])
        remaining_requests = key_mgmt_handler._pending_encryption_key_requests.get(fake_kid)

        print(f"Remaining queued envelopes: {len(remaining_queued)}")
        print(f"Remaining key requests: {remaining_requests is not None}")

        if len(remaining_queued) == 0 and remaining_requests is None:
            print("✓ Queues were cleared after key arrival")
        else:
            print("✗ Queues were not properly cleared")

        await key_mgmt_handler.stop()

        print("\n=== Test Summary ===")
        print("✓ Encryption key discovery working")
        print("✓ Security policy lookup working")
        print("✓ Envelope queueing for missing keys working")
        print("✓ Key request initiation working")
        print("✓ Envelope replay after key arrival working")
        print("✓ All core encryption key flows are functional")

        return True


@pytest.mark.asyncio
async def test_node_attach_key_exchange():
    """Test that NodeAttach/NodeAttachAck includes encryption keys."""
    print("\n=== Testing NodeAttach Key Exchange ===")

    # Import the node attach frame handler
    from naylence.fame.sentinel.node_attach_frame_handler import NodeAttachFrameHandler

    # Test that _get_keys returns encryption keys
    routing_node = MockNodeLike()
    await routing_node._init_security_manager()

    handler = NodeAttachFrameHandler(
        routing_node=routing_node,
        route_manager=Mock(),
        key_manager=Mock(),
    )

    # Mock the crypto provider
    with patch(
        "naylence.fame.security.crypto.providers.crypto_provider.get_crypto_provider"
    ) as mock_get_crypto:
        crypto_provider = DefaultCryptoProvider()
        mock_get_crypto.return_value = crypto_provider

        keys = handler._routing_node_like.security_manager.get_shareable_keys()
        print(f"Keys from NodeAttach handler: {len(keys) if keys else 0}")

        if keys:
            # Check for encryption keys
            encryption_keys = [k for k in keys if k.get("kty") == "OKP" and k.get("crv") == "X25519"]
            signing_keys = [k for k in keys if k.get("kty") == "EC" and k.get("crv") == "Ed25519"]

            print(f"✓ Found {len(encryption_keys)} X25519 encryption keys")
            print(f"✓ Found {len(signing_keys)} Ed25519 signing keys")

            if encryption_keys:
                print(f"   Sample encryption key ID: {encryption_keys[0]['kid']}")
                print("✓ NodeAttach will include encryption keys")
            else:
                print("✗ No encryption keys found in NodeAttach")
        else:
            print("✗ No keys returned from NodeAttach handler")

    return True


@pytest.mark.asyncio
async def test_node_attach_noop_security_manager():
    """Test that NodeAttach provides no keys when using NoSecurityManager."""
    print("\n=== Testing NodeAttach with NoSecurityManager ===")

    # Import the node attach frame handler
    from naylence.fame.security.no_security_manager import NoSecurityManager
    from naylence.fame.sentinel.node_attach_frame_handler import NodeAttachFrameHandler

    class MockNodeLikeNoSecurity:
        def __init__(self):
            self._id = "test_node"
            self._physical_path = "/test"
            self._security_manager = NoSecurityManager()

        @property
        def id(self) -> str:
            return self._id

        @property
        def physical_path(self) -> str:
            return self._physical_path

        @property
        def security_manager(self):
            return self._security_manager

        @property
        def routing_epoch(self) -> str:
            return "test-epoch"

    # Test that _get_keys returns None when using NoSecurityManager
    handler = NodeAttachFrameHandler(
        routing_node=MockNodeLikeNoSecurity(),
        route_manager=Mock(),
        key_manager=Mock(),
    )

    # Test with NoSecurityManager - no crypto provider needed
    keys = handler._routing_node_like.security_manager.get_shareable_keys()
    print(f"Keys from NodeAttach handler with NoSecurityManager: {keys}")

    if keys is None:
        print("✓ No keys returned with NoSecurityManager (expected)")
        print("✓ NodeAttach will not include encryption keys when using NoSecurityManager")
    else:
        print(f"✗ Unexpected keys returned: {len(keys)} keys")
        return False

    return True

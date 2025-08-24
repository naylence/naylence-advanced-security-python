"""
Channel-aware EncryptionManager that integrates channel encryption with the existing security framework.

This properly implements the EncryptionManager interface for channel encryption:
- Uses proper SecurityHeader.enc headers
- Integrates with existing encryption options and key management
- Handles channel establishment and management through the security framework
"""

import os
from typing import TYPE_CHECKING, Any, Optional

from naylence.fame.core import DataFrame, EncryptionHeader, FameEnvelope, SecurityHeader, generate_id
from naylence.fame.node.node_like import NodeLike
from naylence.fame.security.encryption.encryption_manager import (
    EncryptionManager,
    EncryptionOptions,
    EncryptionResult,
)
from naylence.fame.security.util import require_crypto
from naylence.fame.util.logging import getLogger
from naylence.fame.util.task_spawner import TaskSpawner

if TYPE_CHECKING:
    from naylence.fame.security.encryption.secure_channel_manager import SecureChannelManager

logger = getLogger(__name__)


def _make_json_serializable(obj: Any) -> Any:
    """Convert an object to a JSON-serializable form."""
    if hasattr(obj, "model_dump"):
        # Pydantic v2 style
        return obj.model_dump()
    elif hasattr(obj, "dict"):
        # Pydantic v1 style or other dict-convertible objects
        return obj.dict()
    elif hasattr(obj, "__dict__"):
        # Generic objects with __dict__
        return obj.__dict__
    else:
        # Assume it's already serializable
        return obj


class ChannelEncryptionManager(EncryptionManager):
    """
    Channel-aware encryption manager that provides end-to-end encryption using secure channels.

    This implementation:
    1. Establishes secure channels automatically when encryption is requested
    2. Uses ChaCha20-Poly1305 for symmetric encryption
    3. Produces proper SecurityHeader.enc headers (unlike the old implementation)
    4. Integrates with existing EncryptionOptions and key management
    """

    def __init__(
        self,
        secure_channel_manager: Optional["SecureChannelManager"] = None,
        node_like: Optional[NodeLike] = None,
    ):
        super().__init__()
        self._secure_channel_manager = secure_channel_manager
        self._node_like = node_like
        self._pending_envelopes = {}  # destination -> list of envelopes waiting for channel
        self._handshake_in_progress = set()  # destinations with ongoing handshakes
        self._addr_channel_map = {}  # address -> channel_id (learned from successful decryptions)

    def _is_channel_algorithm(self, algorithm: str) -> bool:
        """Check if the given algorithm is a channel encryption algorithm."""
        # Default supported channel algorithms - this could be made configurable
        supported_channel_algorithms = ["chacha20-poly1305-channel"]
        return algorithm in supported_channel_algorithms

    async def encrypt_envelope(
        self,
        env: FameEnvelope,
        *,
        opts: Optional[EncryptionOptions] = None,
    ) -> EncryptionResult:
        """
        Encrypt envelope using channel encryption with unified prerequisite lifecycle.

        Lifecycle:
        1. Check prerequisite (channel exists)
        2. If missing → initiate fulfillment (SecureOpen) and queue envelope
        3. If ready → encrypt immediately
        """
        frame = env.frame
        if not isinstance(frame, DataFrame):
            return EncryptionResult.skipped(env)  # Only encrypt DataFrames

        if not frame.payload:
            return EncryptionResult.skipped(env)  # Nothing to encrypt

        # Get destination from envelope or encryption options
        destination = None
        if opts and "destination" in opts:
            destination = opts["destination"]
        elif env.to:
            destination = env.to
        else:
            logger.warning("no_destination_for_channel_encryption", envp_id=env.id)
            return EncryptionResult.skipped(env)

        # Get channel manager - use injected dependency
        if not self._secure_channel_manager:
            logger.warning("no_secure_channel_manager_available", envp_id=env.id)
            return EncryptionResult.skipped(env)

        destination_str = str(destination)

        # STEP 1: Check prerequisite - do we have a channel?
        channel_id = await self._find_existing_channel(destination_str)

        if channel_id:
            # STEP 4: Prerequisite met - encrypt immediately
            try:
                encrypted_env = self._encrypt_with_channel(env, channel_id)
                logger.debug("channel_encrypted_immediately", channel_id=channel_id, envp_id=env.id)
                return EncryptionResult.ok(encrypted_env)
            except Exception as e:
                logger.error("channel_encryption_failed", error=str(e), channel_id=channel_id)
                return EncryptionResult.skipped(env)

        # STEP 2 & 3: Prerequisite missing - initiate fulfillment and queue
        await self._queue_and_initiate_handshake(env, destination, destination_str, opts)
        return EncryptionResult.queued()

    async def _find_existing_channel(self, destination: str) -> Optional[str]:
        """
        Find an existing channel for the destination.

        Returns channel_id if found, None otherwise.
        """
        if not self._secure_channel_manager:
            return None

        # Fast path: check if we already learned a channel for this destination
        cached_cid = self._addr_channel_map.get(destination)
        if cached_cid and cached_cid in self._secure_channel_manager.channels:
            logger.debug("using_cached_channel", channel_id=cached_cid, destination=destination)
            return cached_cid

        # Check if we have a direct channel for this destination (fallback)
        existing_channels = [
            cid
            for cid in self._secure_channel_manager.channels.keys()
            if cid.startswith(f"auto-{destination}-")
        ]

        if existing_channels:
            # Channel exists - cache it for future use
            channel_id = existing_channels[0]
            self._addr_channel_map[destination] = channel_id
            logger.debug("using_existing_channel", channel_id=channel_id, destination=destination)
            return channel_id

        return None

    async def _queue_and_initiate_handshake(
        self,
        env: FameEnvelope,
        destination: str,
        destination_str: str,
        opts: Optional[EncryptionOptions],
    ) -> None:
        """
        Queue envelope and initiate channel handshake if not already in progress.

        This method:
        1. Queues the envelope for later delivery when the channel is established
        2. Initiates a handshake if one isn't already in progress for this destination
        """
        # STEP 2: Queue the envelope for later delivery
        if destination_str not in self._pending_envelopes:
            self._pending_envelopes[destination_str] = []

        self._pending_envelopes[destination_str].append(env)
        logger.debug("queued_envelope_for_channel_handshake", envp_id=env.id, destination=destination_str)

        # STEP 3: Initiate handshake if not already in progress
        if destination_str not in self._handshake_in_progress:
            self._handshake_in_progress.add(destination_str)

            # Start async handshake initiation
            if self._node_like and isinstance(self._node_like, TaskSpawner):
                self._node_like.spawn(
                    self._initiate_channel_handshake_async(destination, destination_str),
                    name=f"handshake-{destination_str}",
                )
                logger.debug("started_async_handshake_task", destination=destination_str)
            else:
                # Fallback to sync handshake if no task spawner available
                logger.debug("falling_back_to_sync_handshake", destination=destination_str)
                self._initiate_channel_handshake(destination)
        else:
            logger.debug("handshake_already_in_progress", destination=destination_str)

    async def decrypt_envelope(
        self,
        env: FameEnvelope,
        *,
        opts: Optional[EncryptionOptions] = None,
    ) -> FameEnvelope:
        """
        Decrypt envelope using channel encryption.
        """
        require_crypto()

        frame = env.frame
        if not isinstance(frame, DataFrame):
            return env

        if not frame.payload:
            return env

        # Check for channel encryption header
        if not (env.sec and env.sec.enc):
            return env

        enc_header = env.sec.enc
        # Check if this is a channel encryption algorithm (more flexible than hardcoded check)
        if not enc_header.alg or not self._is_channel_algorithm(enc_header.alg):
            return env

        # Get channel ID from header
        channel_id = enc_header.kid
        if not channel_id:
            logger.error("missing_channel_id_in_encryption_header", envp_id=env.id)
            return env

        # Get nonce from header
        try:
            nonce = bytes.fromhex(enc_header.val or "")
        except ValueError:
            logger.error("invalid_nonce_in_encryption_header", envp_id=env.id)
            return env

        # Use injected channel manager dependency
        if not self._secure_channel_manager:
            logger.warning("no_secure_channel_manager_for_decryption", envp_id=env.id)
            return env

        # Get channel key
        if channel_id not in self._secure_channel_manager.channels:
            logger.error("channel_not_available_for_decryption", channel_id=channel_id)
            return env

        channel_state = self._secure_channel_manager.channels[channel_id]
        channel_key = channel_state.key

        # Decrypt using ChaCha20-Poly1305
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

            aead = ChaCha20Poly1305(channel_key)
            ad = channel_id.encode("utf-8")

            # Decode base64-encoded ciphertext
            import base64

            if isinstance(frame.payload, str):
                ciphertext = base64.b64decode(frame.payload.encode("ascii"))
            else:
                # Handle legacy case where payload might still be bytes
                ciphertext = frame.payload

            plaintext_bytes = aead.decrypt(nonce, ciphertext, ad)

            # Deserialize payload
            import json

            try:
                frame.payload = json.loads(plaintext_bytes.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Fallback to string
                frame.payload = plaintext_bytes.decode("utf-8", errors="replace")

            # Restore codec to json (since we deserialized from JSON)
            frame.codec = "json"

            # Remove encryption header
            env.sec.enc = None
            if not env.sec.sig:
                env.sec = None

            logger.debug("channel_decrypted_envelope", channel_id=channel_id, envp_id=env.id)

            # Learn address-to-channel mapping for bidirectional communication
            # Remember that replyTo address can be reached through this channel
            if env.reply_to:
                self._addr_channel_map[str(env.reply_to)] = channel_id
                logger.debug(
                    "learned_channel_for_reply_to", reply_to=str(env.reply_to), channel_id=channel_id
                )

            # Also learn from envelope source information if available
            if env.sid:
                # Map system ID to channel for future use
                self._addr_channel_map[env.sid] = channel_id
                logger.debug("learned_channel_for_sid", sid=env.sid, channel_id=channel_id)

        except Exception as e:
            logger.error("channel_decryption_failed", error=str(e), channel_id=channel_id)
            return env

        return env

    def _initiate_channel_handshake(self, destination) -> None:
        """
        Initiate a secure channel handshake for the given destination.

        This method only sends the SecureOpenFrame - it doesn't create a temporary channel.
        The real channel will be established when the SecureAccept response is received.
        """
        if not self._secure_channel_manager:
            logger.error("no_secure_channel_manager_for_handshake_initiation")
            return

        try:
            destination_str = str(destination)
            channel_id = f"auto-{destination_str}-{generate_id()}"

            logger.debug("initiating_channel_handshake", channel_id=channel_id, destination=destination_str)

            # Generate SecureOpenFrame
            open_frame = self._secure_channel_manager.generate_open_frame(channel_id, "CHACHA20P1305")

            # Send the SecureOpenFrame to the destination
            if self._send_secure_open_frame_sync(open_frame, destination):
                logger.debug("sent_secure_open_frame", channel_id=channel_id, destination=destination_str)
            else:
                logger.warning("failed_to_send_secure_open_frame", channel_id=channel_id)

            logger.debug("channel_handshake_initiated", channel_id=channel_id, destination=destination_str)

        except Exception as e:
            logger.error("channel_handshake_initiation_failed", error=str(e), destination=str(destination))

    def _establish_channel_with_handshake(self, destination) -> Optional[str]:
        """
        Establish a secure channel for the given destination.

        This method:
        1. Generates a unique channel ID for the destination
        2. Creates and sends a SecureOpenFrame to the destination
        3. Creates a temporary channel state for immediate use
        4. The real handshake will complete asynchronously
        """
        if not self._secure_channel_manager:
            logger.error("no_secure_channel_manager_for_channel_establishment")
            return None

        try:
            destination_str = str(destination)
            channel_id = f"auto-{destination_str}-{generate_id()}"

            logger.debug("establishing_channel", channel_id=channel_id, destination=destination_str)

            # Generate SecureOpenFrame
            open_frame = self._secure_channel_manager.generate_open_frame(channel_id, "CHACHA20P1305")

            # Send the SecureOpenFrame to the destination
            if self._send_secure_open_frame_sync(open_frame, destination):
                logger.debug("sent_secure_open_frame", channel_id=channel_id, destination=destination_str)
            else:
                logger.warning("failed_to_send_secure_open_frame", channel_id=channel_id)

            # Create a temporary channel state for immediate encryption
            # This will be replaced when the real handshake completes
            import time

            from naylence.fame.security.encryption.secure_channel_manager import SecureChannelState

            # Generate a temporary key for immediate use
            # In real handshake, this would be derived from ECDH
            temp_key = os.urandom(32)

            channel_state = SecureChannelState(
                key=temp_key,
                send_counter=0,
                recv_counter=0,
                nonce_prefix=os.urandom(4),
                expires_at=time.time() + 3600,
                algorithm="CHACHA20P1305",
            )

            # Add to channel manager
            self._secure_channel_manager.add_channel(channel_id, channel_state)

            logger.debug(
                "channel_established_with_handshake_initiated",
                channel_id=channel_id,
                destination=destination_str,
            )
            return channel_id

        except Exception as e:
            logger.error("channel_establishment_failed", error=str(e), destination=str(destination))
            return None

    def _send_secure_open_frame_sync(self, open_frame, destination) -> bool:
        """Send SecureOpenFrame to destination via envelope (synchronous)."""
        try:
            if not self._node_like:
                logger.error("no_node_available_for_sending_secure_open")
                return False

            # Create envelope for the SecureOpenFrame
            envelope_factory = getattr(self._node_like, "_envelope_factory", None)
            if not envelope_factory:
                logger.error("no_envelope_factory_available_for_secure_open")
                return False

            # Create envelope with SecureOpenFrame and reply_to address
            from naylence.fame.core import FameAddress
            from naylence.fame.core.address.address import format_address

            # Set reply_to to the node's system inbox so SecureAccept can be delivered back
            node_physical_path = self._node_like.physical_path
            if not node_physical_path:
                logger.error("no_physical_path_available_for_reply_to")
                return False

            reply_to_address = format_address("__sys__", node_physical_path)

            envelope = envelope_factory.create_envelope(
                to=FameAddress(str(destination)), frame=open_frame, reply_to=reply_to_address
            )

            # Send via node's delivery system using a background task
            if isinstance(self._node_like, TaskSpawner):
                self._node_like.spawn(
                    self._deliver_secure_open_async(envelope), name=f"send-secure-open-{open_frame.cid}"
                )
                logger.debug("queued_secure_open_frame_for_delivery", cid=open_frame.cid)
                return True
            else:
                logger.warning("cannot_send_secure_open_no_task_spawner")
                return False

        except Exception as e:
            logger.error("failed_to_send_secure_open_frame_sync", error=str(e))
            return False

    async def _deliver_secure_open_async(self, envelope):
        """Deliver SecureOpenFrame envelope asynchronously."""
        try:
            from naylence.fame.core import DeliveryOriginType, FameDeliveryContext

            if not self._node_like:
                logger.error("no_node_available_for_delivery")
                return

            context = FameDeliveryContext(
                origin_type=DeliveryOriginType.LOCAL, from_system_id=self._node_like.sid
            )

            await self._node_like.deliver(envelope, context)
            logger.debug("delivered_secure_open_frame", frame_id=envelope.frame.cid)

        except Exception as e:
            logger.error("failed_to_deliver_secure_open_frame", error=str(e))

    async def notify_channel_established(self, channel_id: str) -> None:
        """
        Notification that a channel handshake has completed.

        This method drains the pending queue for the destination and
        delivers all queued envelopes with channel encryption.
        """
        logger.debug("channel_encryption_manager_notified", channel_id=channel_id, manager_type="channel")

        # Extract destination from channel ID (auto-<destination>-<id>)
        if not channel_id.startswith("auto-"):
            logger.warning("unexpected_channel_id_format", channel_id=channel_id)
            return

        # Parse destination from channel ID
        parts = channel_id.split("-")
        if len(parts) < 3:
            logger.warning("cannot_parse_destination_from_channel_id", channel_id=channel_id)
            return

        # Reconstruct destination (everything between "auto" and final ID)
        destination_str = "-".join(parts[1:-1])

        # Remove from handshakes in flight
        self._handshake_in_progress.discard(destination_str)

        # Process queued envelopes
        if destination_str in self._pending_envelopes:
            queued_envelopes = self._pending_envelopes.pop(destination_str)
            logger.debug(
                "draining_pending_queue",
                destination=destination_str,
                channel_id=channel_id,
                queue_size=len(queued_envelopes),
            )

            # Get channel manager - use injected dependency
            if not self._secure_channel_manager:
                logger.error("no_secure_channel_manager_for_queue_drain", channel_id=channel_id)
                return

            # Encrypt and deliver each queued envelope
            for envelope in queued_envelopes:
                try:
                    encrypted_envelope = self._encrypt_with_channel(envelope, channel_id)

                    # Deliver the encrypted envelope
                    if self._node_like and isinstance(self._node_like, TaskSpawner):
                        self._node_like.spawn(
                            self._deliver_queued_envelope_async(encrypted_envelope),
                            name=f"deliver-queued-{envelope.id}",
                        )
                        logger.debug(
                            "queued_encrypted_envelope_for_delivery",
                            envp_id=envelope.id,
                            channel_id=channel_id,
                        )
                    else:
                        logger.warning("cannot_deliver_queued_envelope", envp_id=envelope.id)

                except Exception as e:
                    logger.error("failed_to_encrypt_queued_envelope", envp_id=envelope.id, error=str(e))
        else:
            logger.debug("no_pending_queue_for_destination", destination=destination_str)

    async def notify_channel_failed(self, channel_id: str, reason: str = "handshake_failed") -> None:
        """
        Notification that a channel handshake has failed.

        This method drains the pending queue for the destination and logs
        failure notifications for all queued envelopes that were waiting
        for this channel to be established.

        Args:
            channel_id: The ID of the channel that failed to establish
            reason: A description of why the handshake failed
        """
        logger.debug("channel_encryption_manager_notified_failure", channel_id=channel_id, reason=reason)

        # Extract destination from channel ID (auto-<destination>-<id>)
        if not channel_id.startswith("auto-"):
            logger.warning("unexpected_channel_id_format_on_failure", channel_id=channel_id)
            return

        # Parse destination from channel ID
        parts = channel_id.split("-")
        if len(parts) < 3:
            logger.warning("cannot_parse_destination_from_channel_id_on_failure", channel_id=channel_id)
            return

        # Reconstruct destination (everything between "auto" and final ID)
        destination_str = "-".join(parts[1:-1])

        # Remove from handshakes in flight
        self._handshake_in_progress.discard(destination_str)

        # Process queued envelopes that were waiting for this failed channel
        if destination_str in self._pending_envelopes:
            queued_envelopes = self._pending_envelopes.pop(destination_str)
            logger.debug(
                "draining_failed_channel_queue",
                destination=destination_str,
                channel_id=channel_id,
                queue_size=len(queued_envelopes),
                reason=reason,
            )

            # Process each queued envelope and send NACKs if appropriate
            for envelope in queued_envelopes:
                await self._handle_failed_envelope(envelope, destination_str, channel_id, reason)

        else:
            logger.debug("no_pending_queue_for_failed_destination", destination=destination_str)

    async def _deliver_queued_envelope_async(self, envelope):
        """Deliver a queued envelope that was encrypted after channel establishment."""
        try:
            from naylence.fame.core import DeliveryOriginType, FameDeliveryContext

            if not self._node_like:
                logger.error("no_node_available_for_queued_delivery")
                return

            context = FameDeliveryContext(
                origin_type=DeliveryOriginType.LOCAL, from_system_id=self._node_like.sid
            )

            await self._node_like.deliver(envelope, context)
            logger.debug("delivered_queued_envelope", envp_id=envelope.id)

        except Exception as e:
            logger.error("failed_to_deliver_queued_envelope", envp_id=envelope.id, error=str(e))

    def _encrypt_with_channel(self, env: FameEnvelope, channel_id: str) -> FameEnvelope:
        """Encrypt envelope with an existing channel."""
        if not self._secure_channel_manager:
            logger.error("no_secure_channel_manager_for_encryption")
            return env

        frame = env.frame

        # Ensure we have a DataFrame
        if not isinstance(frame, DataFrame):
            logger.error("attempted_to_encrypt_non_dataframe", frame_type=type(frame).__name__)
            return env

        # Get channel key for encryption
        if channel_id not in self._secure_channel_manager.channels:
            logger.error("channel_not_in_channels", channel_id=channel_id)
            return env

        channel_state = self._secure_channel_manager.channels[channel_id]
        channel_key = channel_state.key

        # Encrypt using ChaCha20-Poly1305
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

            nonce = os.urandom(12)
            aead = ChaCha20Poly1305(channel_key)

            # Serialize payload for encryption
            if isinstance(frame.payload, (dict | list)):
                import json

                payload_bytes = json.dumps(frame.payload, separators=(",", ":")).encode("utf-8")
            elif isinstance(frame.payload, str):
                payload_bytes = frame.payload.encode("utf-8")
            elif isinstance(frame.payload, bytes):
                payload_bytes = frame.payload
            else:
                # Handle Pydantic models and other objects
                import json

                serializable_payload = _make_json_serializable(frame.payload)
                payload_bytes = json.dumps(serializable_payload, separators=(",", ":")).encode("utf-8")

            # Encrypt with associated data (channel ID)
            ad = channel_id.encode("utf-8")
            ciphertext = aead.encrypt(nonce, payload_bytes, ad)

            # Create proper encryption header
            enc_header = EncryptionHeader(
                alg="chacha20-poly1305-channel",
                val=nonce.hex(),
                kid=channel_id,  # Use channel ID as key identifier
            )

            # Set security header
            if env.sec:
                env.sec.enc = enc_header
            else:
                env.sec = SecurityHeader(enc=enc_header)

            # Replace payload with base64-encoded ciphertext (for JSON serialization)
            import base64

            frame.payload = base64.b64encode(ciphertext).decode("ascii")

            # Keep codec as "b64" to indicate base64 encoding
            frame.codec = "b64"

            logger.debug("channel_encrypted_envelope", channel_id=channel_id, envp_id=env.id)

        except Exception as e:
            logger.error("channel_encryption_failed", error=str(e), channel_id=channel_id)
            return env

        return env

    def _find_channel_for_destination(self, destination_str: str) -> Optional[str]:
        """
        Find an existing channel that can reach the given destination.

        This uses learned address-to-channel mappings from successful decryptions.
        """
        if not self._secure_channel_manager:
            return None

        # Check cache first
        cached_cid = self._addr_channel_map.get(destination_str)
        if cached_cid and cached_cid in self._secure_channel_manager.channels:
            logger.debug("found_cached_channel", destination=destination_str, channel_id=cached_cid)
            return cached_cid

        # Fallback: check for direct channels to this destination
        direct_channels = [
            cid
            for cid in self._secure_channel_manager.channels.keys()
            if cid.startswith(f"auto-{destination_str}-")
        ]

        if direct_channels:
            # Cache this mapping for future use
            channel_id = direct_channels[0]
            self._addr_channel_map[destination_str] = channel_id
            logger.debug(
                "found_direct_channel_and_cached", destination=destination_str, channel_id=channel_id
            )
            return channel_id

        # No suitable channel found
        logger.debug("no_channel_found_for_destination", destination=destination_str)
        return None

    async def _initiate_channel_handshake_async(self, destination, destination_str: str) -> None:
        """
        Async version of channel handshake initiation.

        This method:
        1. Initiates the handshake asynchronously
        2. Sends the SecureOpenFrame to the destination
        3. Cleans up handshake tracking on completion
        """
        if not self._secure_channel_manager:
            logger.error("no_secure_channel_manager_for_async_handshake_initiation")
            return

        try:
            channel_id = f"auto-{destination_str}-{generate_id()}"

            logger.debug(
                "initiating_async_channel_handshake", channel_id=channel_id, destination=destination_str
            )

            # Generate SecureOpenFrame
            open_frame = self._secure_channel_manager.generate_open_frame(channel_id, "CHACHA20P1305")

            # Send the SecureOpenFrame to the destination asynchronously
            success = await self._send_secure_open_frame_async(open_frame, destination)

            if success:
                logger.debug(
                    "sent_secure_open_frame_async", channel_id=channel_id, destination=destination_str
                )
            else:
                logger.warning("failed_to_send_secure_open_frame_async", channel_id=channel_id)

            logger.debug(
                "async_channel_handshake_initiated", channel_id=channel_id, destination=destination_str
            )

        except Exception as e:
            logger.error(
                "async_channel_handshake_initiation_failed", error=str(e), destination=destination_str
            )
        finally:
            # Always clean up the handshake tracking
            self._handshake_in_progress.discard(destination_str)
            logger.debug("cleaned_up_handshake_tracking", destination=destination_str)

    async def _send_secure_open_frame_async(self, open_frame, destination) -> bool:
        """Send SecureOpenFrame to destination via envelope (asynchronous)."""
        try:
            if not self._node_like:
                logger.error("no_node_available_for_sending_secure_open_async")
                return False

            # Create envelope for the SecureOpenFrame
            envelope_factory = getattr(self._node_like, "_envelope_factory", None)
            if not envelope_factory:
                logger.error("no_envelope_factory_available_for_secure_open_async")
                return False

            # Create envelope with SecureOpenFrame and reply_to address
            from naylence.fame.core import FameAddress
            from naylence.fame.core.address.address import format_address

            # Set reply_to to the node's system inbox so SecureAccept can be delivered back
            node_physical_path = self._node_like.physical_path
            if not node_physical_path:
                logger.error("no_physical_path_available_for_reply_to_async")
                return False

            reply_to_address = format_address("__sys__", node_physical_path)

            envelope = envelope_factory.create_envelope(
                to=FameAddress(str(destination)),
                frame=open_frame,
                reply_to=reply_to_address,
                corr_id=generate_id()
            )

            # Deliver directly using async
            await self._deliver_secure_open_async(envelope)
            logger.debug("delivered_secure_open_frame_async", cid=open_frame.cid)
            return True

        except Exception as e:
            logger.error("failed_to_send_secure_open_frame_async", error=str(e))
            return False

    async def _handle_failed_envelope(
        self, envelope: FameEnvelope, destination_str: str, channel_id: str, reason: str
    ) -> None:
        """
        Handle a failed envelope by sending a delivery NACK if appropriate.

        For DataFrames with reply_to addresses, this sends a DeliveryAckFrame with ok=False
        to notify the sender that the envelope could not be delivered due to channel handshake failure.

        Args:
            envelope: The envelope that failed to be delivered
            destination_str: The destination that failed
            channel_id: The channel ID that failed to establish
            reason: The reason for the failure
        """
        logger.warning(
            "envelope_failed_due_to_channel_handshake_failure",
            envp_id=envelope.id,
            destination=destination_str,
            channel_id=channel_id,
            reason=reason,
        )

        # Check if this is a DataFrame with a reply_to address
        from naylence.fame.core import DataFrame

        if not isinstance(envelope.frame, DataFrame):
            logger.debug(
                "skipping_nack_for_non_dataframe",
                envp_id=envelope.id,
                frame_type=type(envelope.frame).__name__,
            )
            return

        if not envelope.reply_to:
            logger.debug("skipping_nack_no_reply_to", envp_id=envelope.id)
            return

        # Send a delivery NACK back to the sender
        try:
            await self._send_delivery_nack(envelope, f"channel_handshake_failed: {reason}")
            logger.debug(
                "sent_delivery_nack_for_failed_envelope",
                envp_id=envelope.id,
                reply_to=str(envelope.reply_to),
                reason=reason,
            )
        except Exception as e:
            logger.error(
                "failed_to_send_delivery_nack",
                envp_id=envelope.id,
                error=str(e),
            )

    async def _send_delivery_nack(self, original_envelope: FameEnvelope, failure_reason: str) -> None:
        """
        Send a DeliveryAckFrame NACK back to the original sender.

        Args:
            original_envelope: The original envelope that failed
            failure_reason: A description of why the delivery failed
        """
        if not self._node_like:
            logger.error("no_node_available_for_sending_delivery_nack")
            return

        # Create envelope factory
        envelope_factory = getattr(self._node_like, "_envelope_factory", None)
        if not envelope_factory:
            logger.error("no_envelope_factory_available_for_delivery_nack")
            return

        try:
            from naylence.fame.core import (
                DeliveryAckFrame,
                DeliveryOriginType,
                FameAddress,
                FameDeliveryContext,
            )

            # Create DeliveryAckFrame with failure status
            # Use the original envelope's corr_id
            original_corr_id = original_envelope.corr_id
            nack_frame = DeliveryAckFrame(
                ok=False,
                code="channel_handshake_failed",
                reason=failure_reason,
            )

            # Create envelope for the NACK
            nack_envelope = envelope_factory.create_envelope(
                to=FameAddress(str(original_envelope.reply_to)),
                frame=nack_frame,
                corr_id=original_corr_id,
            )

            # Create delivery context
            context = FameDeliveryContext(
                origin_type=DeliveryOriginType.LOCAL,
                from_system_id=self._node_like.sid,
            )

            # Deliver the NACK
            await self._node_like.deliver(nack_envelope, context)
            logger.debug(
                "delivered_delivery_nack",
                original_envp_id=original_envelope.id,
                nack_envp_id=nack_envelope.id,
            )

        except Exception as e:
            logger.error("failed_to_create_or_send_delivery_nack", error=str(e))

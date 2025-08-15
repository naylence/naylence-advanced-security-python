import json
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    EncryptionHeader,
    FameDeliveryContext,
    FameEnvelope,
    KeyRequestFrame,
    SecurityHeader,
)
from naylence.fame.security.crypto.crypto_utils import sealed_decrypt, sealed_encrypt
from naylence.fame.security.crypto.providers.crypto_provider import CryptoProvider, get_crypto_provider
from naylence.fame.security.encryption.encryption_manager import (
    EncryptionManager,
    EncryptionOptions,
    EncryptionResult,
)
from naylence.fame.security.keys.key_provider import KeyProvider
from naylence.fame.security.util import require_crypto
from naylence.fame.util import logging

if TYPE_CHECKING:
    from naylence.fame.node import NodeLike

FIXED_PREFIX_LEN = 44  # 32-byte eph_pub + 12-byte nonce

logger = logging.getLogger(__name__)


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


class X25519EncryptionManager(EncryptionManager):
    def __init__(
        self,
        *,
        key_provider: KeyProvider,
        node_like: Optional["NodeLike"] = None,
        crypto: Optional[CryptoProvider] = None,
    ):
        self._node_like = node_like
        self._crypto = crypto or get_crypto_provider()
        self._key_provider = key_provider  # Required - no fallback to singleton
        self._pending_envelopes: Dict[
            str, List[FameEnvelope]
        ] = {}  # key_id -> list of envelopes waiting for key
        self._key_requests_in_progress: Set[str] = set()  # key_ids with ongoing requests

    async def encrypt_envelope(
        self,
        env: FameEnvelope,
        *,
        opts: Optional[EncryptionOptions] = None,
    ) -> EncryptionResult:
        """
        Encrypt envelope using X25519 sealed encryption with unified prerequisite lifecycle.

        Lifecycle:
        1. Check prerequisite (recipient public key available)
        2. If missing → initiate fulfillment (key request) and queue envelope
        3. If ready → encrypt immediately
        """
        require_crypto()

        if not isinstance(env.frame, DataFrame):
            return EncryptionResult.skipped(env)  # Only encrypt DataFrames

        if not env.frame.payload:
            return EncryptionResult.skipped(env)  # Nothing to encrypt

        # STEP 1: Check prerequisite - do we have the recipient's public key?
        recip_pub = None
        recip_kid = None

        if opts:
            # Direct public key provided
            if "recip_pub" in opts:
                recip_pub = opts["recip_pub"]
                recip_kid = opts.get("recip_kid", "recip-kid-stub")

            # Key ID provided - try to resolve it
            elif "recip_kid" in opts:
                recip_kid = opts["recip_kid"]
                try:
                    key_data = await self._key_provider.get_key(recip_kid)
                    # Extract public key from the key data
                    if "encryption_public_pem" in key_data:
                        from cryptography.hazmat.primitives import serialization

                        pub_pem = key_data["encryption_public_pem"]
                        pub_key = serialization.load_pem_public_key(pub_pem.encode())
                        recip_pub = pub_key.public_bytes(
                            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
                        )
                    else:
                        # Public key not available locally
                        pass
                except Exception:
                    # Key not found locally
                    pass

            # Address provided - need to request key for that address
            elif "request_address" in opts:
                request_addr = opts["request_address"]
                # The security policy is indicating that we need to request a key for this address
                # We don't have a key ID yet, so we'll queue this envelope and let the key management
                # system handle the key request. Once the key arrives, it will have a proper key ID.
                recip_kid = f"request-{str(request_addr)}"  # Temporary ID for queueing
                # Don't try to resolve locally - this indicates we should request the key

        if not recip_pub or not recip_kid:
            # STEP 2: Prerequisite missing - queue envelope and request key if needed
            await self._queue_and_request_key(env, recip_kid, opts)

            # STEP 3: Return QUEUED status
            return EncryptionResult.queued()

        # STEP 4: Prerequisite met - encrypt immediately
        return await self._encrypt_with_key(env, recip_pub, recip_kid)

    async def _queue_and_request_key(
        self, env: FameEnvelope, recip_kid: Optional[str], opts: Optional[EncryptionOptions]
    ) -> None:
        """
        Queue envelope and initiate key request if not already in progress.
        """
        if not recip_kid:
            # Cannot request key without key ID
            return

        # Queue the envelope
        if recip_kid not in self._pending_envelopes:
            self._pending_envelopes[recip_kid] = []

        self._pending_envelopes[recip_kid].append(env)

        # Send key request if not already in progress and we have node_like
        if (
            self._node_like
            and recip_kid not in self._key_requests_in_progress
            and opts
            and "request_address" in opts
        ):
            # Mark key request as in progress
            self._key_requests_in_progress.add(recip_kid)

            try:
                # Create and send key request
                request_frame = KeyRequestFrame(address=opts["request_address"])

                key_request_envelope = FameEnvelope(frame=request_frame, to=opts["request_address"])

                logger.debug(
                    "sending_x25519_key_request",
                    kid=recip_kid,
                    address=opts["request_address"],
                    env_id=key_request_envelope.id,
                )
                # Create delivery context with proper LOCAL origin and system ID
                context = FameDeliveryContext(
                    origin_type=DeliveryOriginType.LOCAL, from_system_id=self._node_like.sid
                )
                await self._node_like.deliver(key_request_envelope, context=context)

            except Exception as e:
                logger.error(f"Failed to send key request for {recip_kid}: {e}")
                # Remove from in-progress set on failure
                self._key_requests_in_progress.discard(recip_kid)

    async def _encrypt_with_key(
        self, env: FameEnvelope, recip_pub: bytes, recip_kid: str
    ) -> EncryptionResult:
        """Encrypt envelope with available recipient public key."""
        try:
            # Ensure we have a DataFrame (should already be checked, but be safe)
            if not isinstance(env.frame, DataFrame):
                return EncryptionResult.skipped(env)

            # Create a payload structure that includes original codec and payload
            original_codec = env.frame.codec
            payload = env.frame.payload

            # Convert to JSON-serializable form
            serializable_payload = _make_json_serializable(payload)

            payload_with_codec = {"original_codec": original_codec, "payload": serializable_payload}
            payload_bytes = json.dumps(payload_with_codec).encode("utf-8")
            blob = sealed_encrypt(payload_bytes, recip_pub)
            prefix, ciphertext = blob[:FIXED_PREFIX_LEN], blob[FIXED_PREFIX_LEN:]
            env.frame.codec = "b64"
            env.frame.payload = urlsafe_b64encode(ciphertext).decode("ascii")
            enc_hdr = EncryptionHeader(
                alg="ECDH-ES+A256GCM",
                kid=recip_kid,
                val=urlsafe_b64encode(prefix).decode("ascii"),
            )
            if env.sec:
                env.sec.enc = enc_hdr
            else:
                env.sec = SecurityHeader(enc=enc_hdr)
            return EncryptionResult.ok(env)
        except Exception:
            return EncryptionResult.skipped(env)

    async def decrypt_envelope(
        self, env: FameEnvelope, *, opts: Optional[EncryptionOptions] = None
    ) -> FameEnvelope:
        require_crypto()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        if not env.sec or not env.sec.enc or not isinstance(env.frame, DataFrame):
            return env
        prefix = urlsafe_b64decode(env.sec.enc.val + "=" * (-len(env.sec.enc.val) % 4))
        ct_tag = urlsafe_b64decode(env.frame.payload + "=" * (-len(env.frame.payload) % 4))
        blob = prefix + ct_tag
        priv_key_bytes = opts.get("priv_key") if opts and "priv_key" in opts else None
        if priv_key_bytes is not None:
            priv_key = X25519PrivateKey.from_private_bytes(priv_key_bytes)
        else:
            # Try to get the key using the key ID from the encryption header
            kid = env.sec.enc.kid if env.sec.enc.kid != "recip-kid-stub" else None

            if kid:
                # Use the instance key provider to look up the key by ID
                try:
                    key_data = await self._key_provider.get_key(kid)

                    # Validate that this key is meant for encryption
                    from naylence.fame.security.crypto.jwk_validation import (
                        JWKValidationError,
                        validate_encryption_key,
                    )

                    try:
                        validate_encryption_key(key_data)
                    except JWKValidationError as e:
                        raise ValueError(f"Key {kid} is not valid for encryption: {e}")

                    # Extract the private key from the key data
                    if "encryption_private_pem" in key_data:
                        encryption_pem = key_data["encryption_private_pem"]
                        key = serialization.load_pem_private_key(encryption_pem.encode(), password=None)
                        if not isinstance(key, X25519PrivateKey):
                            raise ValueError(f"Key {kid} is not a valid X25519PrivateKey")
                        priv_key = key
                    else:
                        raise ValueError(f"Key {kid} does not contain encryption_private_pem")
                except Exception as e:
                    # Check if this is our own encryption key - use CryptoProvider directly
                    # This handles the case where we're decrypting a message encrypted for us
                    if kid == self._crypto.encryption_key_id:
                        encryption_pem = self._crypto.encryption_private_pem
                        if not encryption_pem:
                            raise ValueError(
                                f"Failed to find key {kid} and CryptoProvider "
                                "has no encryption private key: {e}"
                            )
                        key = serialization.load_pem_private_key(encryption_pem.encode(), password=None)
                        if not isinstance(key, X25519PrivateKey):
                            raise ValueError(
                                "CryptoProvider encryption key is not a valid X25519PrivateKey"
                            )
                        priv_key = key
                    else:
                        raise ValueError(f"Failed to find key {kid}: {e}")
            else:
                # No key ID specified, use the CryptoProvider's own encryption private key
                encryption_pem = self._crypto.encryption_private_pem
                if not encryption_pem:
                    raise ValueError("CryptoProvider does not have encryption private key for decryption")
                key = serialization.load_pem_private_key(encryption_pem.encode(), password=None)
                if not isinstance(key, X25519PrivateKey):
                    raise ValueError("CryptoProvider encryption key is not a valid X25519PrivateKey")
                priv_key = key
        pt = sealed_decrypt(blob, priv_key)
        payload_with_codec = json.loads(pt.decode("utf-8"))

        # Restore original payload and codec
        env.frame.payload = payload_with_codec["payload"]
        env.frame.codec = payload_with_codec["original_codec"]

        env.sec.enc = None
        if env.sec.sig is None:
            env.sec = None
        return env

    async def notify_key_available(self, key_id: str) -> None:
        """
        Notification that a public key is now available for encryption.

        This method flushes queued envelopes and replays them through the delivery system.
        """
        if key_id not in self._pending_envelopes:
            return  # No envelopes waiting for this key

        # Get the queued envelopes
        queued_envelopes = self._pending_envelopes.pop(key_id)

        # Clear the key request in progress flag
        self._key_requests_in_progress.discard(key_id)

        # If we have node_like, replay the envelopes
        if self._node_like and queued_envelopes:
            logger.debug(f"Replaying {len(queued_envelopes)} queued envelopes for key {key_id}")

            for envelope in queued_envelopes:
                try:
                    # Re-deliver the envelope, which will trigger encryption again
                    # This time the key should be available
                    await self._node_like.deliver(envelope)
                except Exception as e:
                    logger.error(f"Failed to replay envelope {envelope.id} for key {key_id}: {e}")
        else:
            logger.debug(
                f"Discarding {len(queued_envelopes)} queued envelopes for key {key_id} (no node_like)"
            )

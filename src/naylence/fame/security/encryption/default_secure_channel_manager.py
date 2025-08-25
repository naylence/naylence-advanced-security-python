import os
import time
from typing import Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from naylence.fame.core import DataFrame, SecureAcceptFrame, SecureCloseFrame, SecureOpenFrame
from naylence.fame.security.encryption.secure_channel_manager import (
    SecureChannelManager,
    SecureChannelState,
)
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class DefaultSecureChannelManager(SecureChannelManager):
    """Default implementation of SecureChannelManager using XChaCha20-Poly1305 encryption."""

    DEFAULT_CHANNEL_TTL = 3600.0  # 1 hour

    def __init__(self):
        self._channels: Dict[str, SecureChannelState] = {}
        self._ephemeral_keys: Dict[str, X25519PrivateKey] = {}  # For pending handshakes

    @property
    def channels(self) -> Dict[str, SecureChannelState]:
        """Get the current active channels."""
        return self._channels.copy()  # Return a copy to prevent external modification

    def generate_open_frame(self, cid: str, algorithm: str = "CHACHA20P1305") -> SecureOpenFrame:
        """Generate a SecureOpenFrame to initiate a channel."""
        # Generate ephemeral key pair
        priv_key = X25519PrivateKey.generate()
        pub_key = priv_key.public_key()

        # Store the private key for when we get the accept
        self._ephemeral_keys[cid] = priv_key

        # Get public key bytes
        pub_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        logger.debug("generated_channel_open", cid=cid, algorithm=algorithm)

        return SecureOpenFrame(
            cid=cid,
            eph_pub=pub_bytes,
            alg=algorithm,
            # corr_id=generate_id()
        )

    async def handle_open_frame(self, frame: SecureOpenFrame) -> SecureAcceptFrame:
        """Handle incoming SecureOpenFrame and generate response."""
        if frame.alg != "CHACHA20P1305":
            logger.warning("unsupported_channel_algorithm", cid=frame.cid, alg=frame.alg)
            return SecureAcceptFrame(
                cid=frame.cid,
                eph_pub=b"\x00" * 32,  # Dummy key
                ok=False,
                reason=f"Unsupported algorithm: {frame.alg}",
            )

        # Generate our ephemeral key pair
        my_priv = X25519PrivateKey.generate()
        my_pub = my_priv.public_key()

        # Derive shared secret
        peer_pub = X25519PublicKey.from_public_bytes(frame.eph_pub)
        shared_secret = my_priv.exchange(peer_pub)

        # Derive channel key
        channel_key = self._derive_channel_key(frame.cid, shared_secret)

        # Create channel state
        channel_state = SecureChannelState(
            key=channel_key,
            send_counter=0,
            recv_counter=0,
            nonce_prefix=os.urandom(4),  # 4-byte random prefix for ChaCha20Poly1305
            expires_at=time.time() + self.DEFAULT_CHANNEL_TTL,
            algorithm=frame.alg,
        )

        # Store the channel
        self._channels[frame.cid] = channel_state

        # Get our public key bytes
        my_pub_bytes = my_pub.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        logger.debug("channel_established", cid=frame.cid, algorithm=frame.alg)

        return SecureAcceptFrame(cid=frame.cid, eph_pub=my_pub_bytes, alg=frame.alg, ok=True)

    async def handle_accept_frame(self, frame: SecureAcceptFrame) -> bool:
        """Handle incoming SecureAcceptFrame to complete handshake."""
        if not frame.ok:
            logger.warning("channel_rejected", cid=frame.cid, error=frame.reason)
            # Clean up our ephemeral key
            self._ephemeral_keys.pop(frame.cid, None)
            return False

        # Get our ephemeral private key
        my_priv = self._ephemeral_keys.pop(frame.cid, None)
        if not my_priv:
            logger.error("no_ephemeral_key", cid=frame.cid)
            return False

        # Derive shared secret
        peer_pub = X25519PublicKey.from_public_bytes(frame.eph_pub)
        shared_secret = my_priv.exchange(peer_pub)

        # Derive channel key
        channel_key = self._derive_channel_key(frame.cid, shared_secret)

        # Create channel state
        channel_state = SecureChannelState(
            key=channel_key,
            send_counter=0,
            recv_counter=0,
            nonce_prefix=os.urandom(4),  # 4-byte random prefix for ChaCha20Poly1305
            expires_at=time.time() + self.DEFAULT_CHANNEL_TTL,
            algorithm=frame.alg,
        )

        # Store the channel
        self._channels[frame.cid] = channel_state

        logger.debug("channel_completed", cid=frame.cid, algorithm=frame.alg)
        return True

    def handle_close_frame(self, frame: SecureCloseFrame) -> None:
        """Handle channel close."""
        if frame.cid in self._channels:
            del self._channels[frame.cid]
            logger.debug("channel_closed", cid=frame.cid, reason=frame.reason)
        else:
            logger.warning("close_unknown_channel", cid=frame.cid)

    def is_channel_encrypted(self, df: DataFrame) -> bool:
        """Check if a DataFrame is channel encrypted."""
        return df.cid is not None and df.nonce is not None

    def has_channel(self, cid: str) -> bool:
        """Check if we have an active channel."""
        return cid in self._channels

    def get_channel_info(self, cid: str) -> Optional[Dict]:
        """Get channel information for debugging."""
        channel = self._channels.get(cid)
        if not channel:
            return None

        return {
            "cid": cid,
            "algorithm": channel.algorithm,
            "send_counter": channel.send_counter,
            "recv_counter": channel.recv_counter,
            "expires_at": channel.expires_at,
            "expired": time.time() > channel.expires_at,
        }

    def close_channel(self, cid: str, reason: str = "User requested") -> SecureCloseFrame:
        """Close a channel and return close frame."""
        if cid in self._channels:
            del self._channels[cid]
            logger.debug("channel_closed_by_user", cid=cid, reason=reason)

        return SecureCloseFrame(cid=cid, reason=reason)

    def cleanup_expired_channels(self) -> int:
        """Remove expired channels. Returns number of channels cleaned up."""
        now = time.time()
        expired = [cid for cid, channel in self._channels.items() if now > channel.expires_at]

        for cid in expired:
            del self._channels[cid]
            logger.debug("channel_expired_cleanup", cid=cid)

        return len(expired)

    def _derive_channel_key(self, cid: str, shared_secret: bytes) -> bytes:
        """Derive a channel key from shared secret."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for ChaCha20-Poly1305
            salt=None,
            info=f"fame-channel:{cid}".encode(),
        )
        return hkdf.derive(shared_secret)

    def add_channel(self, cid: str, channel_state: SecureChannelState) -> None:
        """Add a channel to the manager."""
        self._channels[cid] = channel_state

    def remove_channel(self, cid: str) -> bool:
        """Remove a channel from the manager."""
        if cid in self._channels:
            del self._channels[cid]
            return True
        return False

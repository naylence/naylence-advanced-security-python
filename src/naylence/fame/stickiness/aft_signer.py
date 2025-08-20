"""
AFT (Affinity Tag) Signer - Creates signed JWT tokens for session affinity.

This component is responsible for generating AFTs (Affinity Tags) that replicas
use to request sticky routing from sentinels.
"""

from __future__ import annotations

import base64
import time
from abc import ABC, abstractmethod
from typing import Optional, Protocol

from naylence.fame.stickiness.aft_model import AFTClaims, AFTHeader
from naylence.fame.stickiness.stickiness_mode import StickinessMode

try:
    import jwt
except ImportError:
    jwt = None


class AFTSigner(Protocol):
    """Interface for AFT signing implementations."""

    def sign_aft(
        self,
        *,
        sid: str,
        ttl_sec: int = 30,
        scope: Optional[str] = None,
        client_sid: Optional[str] = None,
    ) -> str:
        """
        Generate and sign an AFT token.

        Args:
            sid: Sender node ID
            ttl_sec: Time to live in seconds
            scope: Optional scope hint ('node', 'flow', 'sess')
            client_sid: Optional original client session ID for session affinity

        Returns:
            JWS compact format token
        """
        ...

    @property
    def security_level(self) -> StickinessMode:
        """Get the security level this signer operates at."""
        ...


class BaseAFTSigner(ABC):
    """Base class for AFT signers."""

    def __init__(self, kid: str, max_ttl_sec: int = 7200):
        self.kid = kid
        self.max_ttl_sec = max_ttl_sec

    @abstractmethod
    def _sign_payload(self, header: str, payload: str) -> str:
        """Sign the header.payload and return the signature."""
        pass

    @abstractmethod
    def _get_algorithm(self) -> str:
        """Get the algorithm identifier."""
        pass

    @property
    @abstractmethod
    def security_level(self) -> StickinessMode:
        """Get the security level this signer operates at."""
        pass

    def sign_aft(
        self,
        *,
        sid: str,
        ttl_sec: int = 30,
        scope: Optional[str] = None,
        client_sid: Optional[str] = None,
    ) -> str:
        """Generate and sign an AFT token."""
        # Validate TTL
        if ttl_sec > self.max_ttl_sec:
            ttl_sec = self.max_ttl_sec

        # Create expiration time
        exp = int(time.time()) + ttl_sec

        # Build header
        header = AFTHeader(alg=self._get_algorithm(), kid=self.kid)

        # Build claims
        claims = AFTClaims(sid=sid, exp=exp, scp=scope, client_sid=client_sid)

        # Encode header and payload
        header_b64 = self._b64url_encode(header.model_dump_json())
        payload_b64 = self._b64url_encode(claims.model_dump_json())

        # Sign
        signature = self._sign_payload(header_b64, payload_b64)
        signature_b64 = self._b64url_encode(signature.encode() if isinstance(signature, str) else signature)

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def _b64url_encode(self, data: str | bytes) -> str:
        """Base64url encode with padding removed."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class SignedAFTSigner(BaseAFTSigner):
    """AFT signer that uses cryptographic signatures."""

    def __init__(
        self,
        kid: str,
        private_key_pem: str,
        algorithm: str = "EdDSA",
        max_ttl_sec: int = 7200,
    ):
        super().__init__(kid, max_ttl_sec)
        self.private_key_pem = private_key_pem
        self.algorithm = algorithm

    @property
    def security_level(self) -> StickinessMode:
        return StickinessMode.STRICT

    def _get_algorithm(self) -> str:
        return self.algorithm

    def _sign_payload(self, header: str, payload: str) -> str:
        """Sign using JWT library."""
        try:
            import importlib.util

            if importlib.util.find_spec("jwt") is None:
                raise ImportError("PyJWT is not available")
        except ImportError:
            raise RuntimeError("PyJWT is required for signed AFTs")

        # Create the full payload for signing

        # We'll use JWT encode directly with just the payload
        # The header and payload construction is handled by the JWT library
        return ""  # Placeholder - actual signing handled differently

    def sign_aft(
        self,
        *,
        sid: str,
        ttl_sec: int = 30,
        scope: Optional[str] = None,
        client_sid: Optional[str] = None,
    ) -> str:
        """Generate and sign an AFT token using JWT library."""
        # Validate TTL
        if ttl_sec > self.max_ttl_sec:
            ttl_sec = self.max_ttl_sec

        # Create expiration time
        exp = int(time.time()) + ttl_sec

        # Build claims
        claims = {"sid": sid, "exp": exp}
        if scope:
            claims["scp"] = scope
        if client_sid:
            claims["client_sid"] = client_sid

        # Build headers
        headers = {"kid": self.kid}

        try:
            import jwt
        except ImportError:
            raise RuntimeError("PyJWT is required for signed AFTs")

        # Create JWT using the PEM string directly
        token = jwt.encode(claims, self.private_key_pem, algorithm=self.algorithm, headers=headers)

        return token


class UnsignedAFTSigner(BaseAFTSigner):
    """AFT signer for unsigned tokens (signed-optional mode)."""

    @property
    def security_level(self) -> StickinessMode:
        return StickinessMode.SIGNED_OPTIONAL

    def _get_algorithm(self) -> str:
        return "none"

    def _sign_payload(self, header: str, payload: str) -> str:
        """Return empty signature for unsigned tokens."""
        return ""

    def sign_aft(
        self,
        *,
        sid: str,
        ttl_sec: int = 30,
        scope: Optional[str] = None,
        client_sid: Optional[str] = None,
    ) -> str:
        """Generate unsigned AFT token."""
        # Validate TTL
        if ttl_sec > self.max_ttl_sec:
            ttl_sec = self.max_ttl_sec

        # Create expiration time
        exp = int(time.time()) + ttl_sec

        # Build header
        header = AFTHeader(alg="none", kid=self.kid)

        # Build claims
        claims = AFTClaims(sid=sid, exp=exp, scp=scope, client_sid=client_sid)
        claims = AFTClaims(sid=sid, exp=exp, scp=scope)

        # Encode header and payload
        header_b64 = self._b64url_encode(header.model_dump_json())
        payload_b64 = self._b64url_encode(claims.model_dump_json())

        # No signature for unsigned tokens
        return f"{header_b64}.{payload_b64}."


class NoAFTSigner(BaseAFTSigner):
    """No-op signer for SID-only mode."""

    def __init__(self):
        super().__init__("none", 0)

    @property
    def security_level(self) -> StickinessMode:
        return StickinessMode.SID_ONLY

    def sign_aft(
        self,
        *,
        sid: str,
        ttl_sec: int = 30,
        scope: Optional[str] = None,
        client_sid: Optional[str] = None,
    ) -> str:
        """Return empty string - no AFT generation in SID-only mode."""
        return ""

    def _get_algorithm(self) -> str:
        return "none"

    def _sign_payload(self, header: str, payload: str) -> str:
        return ""


def create_aft_signer(
    security_level: StickinessMode,
    kid: str,
    private_key_pem: Optional[str] = None,
    algorithm: str = "EdDSA",
    max_ttl_sec: int = 7200,
) -> AFTSigner:
    """Factory function to create appropriate AFT signer based on security level."""

    if security_level == StickinessMode.STRICT:
        if not private_key_pem:
            raise ValueError("Private key PEM required for strict security level")
        return SignedAFTSigner(kid, private_key_pem, algorithm, max_ttl_sec)

    elif security_level == StickinessMode.SIGNED_OPTIONAL:
        if private_key_pem:
            return SignedAFTSigner(kid, private_key_pem, algorithm, max_ttl_sec)
        else:
            return UnsignedAFTSigner(kid, max_ttl_sec)

    elif security_level == StickinessMode.SID_ONLY:
        return NoAFTSigner()

    else:
        raise ValueError(f"Unknown security level: {security_level}")

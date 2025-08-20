"""
AFT (Affinity Tag) Verifier - Validates signed JWT tokens for session affinity.

This component is responsible for verifying AFTs (Affinity Tags) that sentinels
receive from replicas or clients for routing decisions. It integrates with Fame's
existing key management system.
"""

from __future__ import annotations

import json
import time
from abc import abstractmethod
from typing import NamedTuple, Optional, Protocol

from naylence.fame.security.keys.key_provider import KeyProvider
from naylence.fame.stickiness.aft_model import AFTClaims, AFTHeader
from naylence.fame.stickiness.stickiness_mode import StickinessMode


class AFTVerificationResult(NamedTuple):
    """Result of AFT verification."""

    valid: bool
    sid: Optional[str] = None
    exp: Optional[int] = None
    scope: Optional[str] = None
    trust_level: str = "untrusted"  # "trusted", "low-trust", "untrusted"
    error: Optional[str] = None
    client_sid: Optional[str] = None


class AFTVerifier(Protocol):
    """Interface for AFT verification implementations."""

    async def verify(self, token: str, expected_sid: Optional[str] = None) -> AFTVerificationResult:
        """
        Verify an AFT token.

        Args:
            token: JWS compact format token
            expected_sid: Expected sender node ID for validation

        Returns:
            Verification result
        """
        ...

    @property
    def security_level(self) -> StickinessMode:
        """Get the security level this verifier operates at."""
        ...


class BaseAFTVerifier(AFTVerifier):
    """Base class for AFT verifiers."""

    def __init__(self, default_ttl_sec: int = 30):
        self.default_ttl_sec = default_ttl_sec

    @abstractmethod
    async def _verify_signature(self, token: str, header: AFTHeader, claims: AFTClaims) -> bool:
        """Verify the token signature."""
        pass

    @property
    @abstractmethod
    def security_level(self) -> StickinessMode:
        """Get the security level this verifier operates at."""
        pass

    async def verify(self, token: str, expected_sid: Optional[str] = None) -> AFTVerificationResult:
        """Verify an AFT token."""
        try:
            # Parse token
            parts = token.split(".")
            if len(parts) != 3:
                return AFTVerificationResult(valid=False, error="Invalid token format - expected 3 parts")

            header_b64, payload_b64, signature_b64 = parts

            # Decode header and payload
            try:
                header_json = self._b64url_decode(header_b64).decode("utf-8")
                payload_json = self._b64url_decode(payload_b64).decode("utf-8")

                header_data = json.loads(header_json)
                payload_data = json.loads(payload_json)

                header = AFTHeader(**header_data)
                claims = AFTClaims(**payload_data)

            except Exception as e:
                return AFTVerificationResult(valid=False, error=f"Failed to decode token: {e}")

            # Check expiration
            current_time = int(time.time())
            if claims.exp <= current_time:
                return AFTVerificationResult(
                    valid=False,
                    sid=claims.sid,
                    exp=claims.exp,
                    scope=claims.scp,
                    error="Token expired",
                )

            # Check SID match if provided
            if expected_sid and claims.sid != expected_sid:
                return AFTVerificationResult(
                    valid=False,
                    sid=claims.sid,
                    exp=claims.exp,
                    scope=claims.scp,
                    client_sid=claims.client_sid,
                    error=f"SID mismatch: expected {expected_sid}, got {claims.sid}",
                )

            # Verify signature
            if not await self._verify_signature(token, header, claims):
                return AFTVerificationResult(
                    valid=False,
                    sid=claims.sid,
                    exp=claims.exp,
                    scope=claims.scp,
                    client_sid=claims.client_sid,
                    error="Invalid signature",
                )

            # Determine trust level
            trust_level = self._determine_trust_level(header, claims)

            return AFTVerificationResult(
                valid=True,
                sid=claims.sid,
                exp=claims.exp,
                scope=claims.scp,
                client_sid=claims.client_sid,
                trust_level=trust_level,
            )

        except Exception as e:
            return AFTVerificationResult(valid=False, error=f"Verification failed: {e}")

    def _b64url_decode(self, data: str) -> bytes:
        """Base64url decode with padding restoration."""
        # Add padding if needed
        missing_padding = len(data) % 4
        if missing_padding:
            data += "=" * (4 - missing_padding)

        import base64

        return base64.urlsafe_b64decode(data)

    def _determine_trust_level(self, header: AFTHeader, claims: AFTClaims) -> str:
        """Determine the trust level of the token."""
        if header.alg == "none":
            return "low-trust"
        else:
            return "trusted"


class StrictAFTVerifier(BaseAFTVerifier):
    """AFT verifier for strict security mode."""

    def __init__(self, key_provider: KeyProvider, default_ttl_sec: int = 30):
        super().__init__(default_ttl_sec)
        self.key_provider = key_provider

    @property
    def security_level(self) -> StickinessMode:
        return StickinessMode.STRICT

    async def _verify_signature(self, token: str, header: AFTHeader, claims: AFTClaims) -> bool:
        """Verify signature using PyJWT."""
        if header.alg == "none":
            return False  # Strict mode doesn't accept unsigned tokens

        try:
            import jwt
        except ImportError:
            raise RuntimeError("PyJWT is required for signed AFT verification")

        # Get public key
        key_data = await self.key_provider.get_key(header.kid)
        if not key_data:
            return False

        # Convert JWK to appropriate key format for PyJWT
        try:
            public_key = self._jwk_to_key(key_data, header.alg)
            if not public_key:
                return False
        except Exception:
            return False

        try:
            # Verify using PyJWT
            jwt.decode(
                token,
                public_key,
                algorithms=[header.alg],
                options={"verify_exp": False},  # We handle expiry ourselves
            )
            return True
        except jwt.InvalidTokenError:
            return False

    def _jwk_to_key(self, jwk: dict, algorithm: str):
        """Convert JWK to cryptography key object for PyJWT."""
        if algorithm == "EdDSA":
            # Handle EdDSA keys (Ed25519)
            x_b64 = jwk.get("x")
            if not x_b64:
                return None

            try:
                import base64

                from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                    Ed25519PublicKey,
                )

                # Decode the base64url encoded public key
                raw = base64.urlsafe_b64decode(x_b64 + "=" * (-len(x_b64) % 4))
                return Ed25519PublicKey.from_public_bytes(raw)
            except Exception:
                return None

        # For other algorithms, try PEM format
        public_key_pem = jwk.get("public_key_pem")
        if public_key_pem:
            return public_key_pem

        return None


class SignedOptionalAFTVerifier(BaseAFTVerifier):
    """AFT verifier for signed-optional security mode."""

    def __init__(self, key_provider: Optional[KeyProvider] = None, default_ttl_sec: int = 30):
        super().__init__(default_ttl_sec)
        self.key_provider = key_provider

    @property
    def security_level(self) -> StickinessMode:
        return StickinessMode.SIGNED_OPTIONAL

    async def _verify_signature(self, token: str, header: AFTHeader, claims: AFTClaims) -> bool:
        """Verify signature if signed, accept if unsigned."""
        if header.alg == "none":
            # Accept unsigned tokens in signed-optional mode
            return True

        # If signed, verify it
        if not self.key_provider:
            return False  # Can't verify without key provider

        try:
            import jwt
        except ImportError:
            return False  # Can't verify without JWT library

        # Get public key
        try:
            key_data = await self.key_provider.get_key(header.kid)
            public_key = self._jwk_to_key(key_data, header.alg)
            if not public_key:
                return False
        except (ValueError, KeyError):
            return False

        try:
            # Verify using PyJWT
            jwt.decode(
                token,
                public_key,
                algorithms=[header.alg],
                options={"verify_exp": False},  # We handle expiry ourselves
            )
            return True
        except jwt.InvalidTokenError:
            return False

    def _jwk_to_key(self, jwk: dict, algorithm: str):
        """Convert JWK to cryptography key object for PyJWT."""
        if algorithm == "EdDSA":
            # Handle EdDSA keys (Ed25519)
            x_b64 = jwk.get("x")
            if not x_b64:
                return None

            try:
                import base64

                from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                    Ed25519PublicKey,
                )

                # Decode the base64url encoded public key
                raw = base64.urlsafe_b64decode(x_b64 + "=" * (-len(x_b64) % 4))
                return Ed25519PublicKey.from_public_bytes(raw)
            except Exception:
                return None

        # For other algorithms, try PEM format
        public_key_pem = jwk.get("public_key_pem")
        if public_key_pem:
            return public_key_pem

        return None


class SidOnlyAFTVerifier(BaseAFTVerifier):
    """AFT verifier for SID-only mode (ignores AFTs completely)."""

    @property
    def security_level(self) -> StickinessMode:
        return StickinessMode.SID_ONLY

    async def verify(self, token: str, expected_sid: Optional[str] = None) -> AFTVerificationResult:
        """Always returns invalid - SID-only mode ignores AFTs."""
        return AFTVerificationResult(valid=False, error="SID-only mode ignores AFTs")

    async def _verify_signature(self, token: str, header: AFTHeader, claims: AFTClaims) -> bool:
        return False


def create_aft_verifier(
    security_level: StickinessMode,
    key_provider: KeyProvider,
    default_ttl_sec: int = 30,
) -> AFTVerifier:
    """Factory function to create appropriate AFT verifier based on security level."""

    if security_level == StickinessMode.STRICT:
        return StrictAFTVerifier(key_provider, default_ttl_sec)

    elif security_level == StickinessMode.SIGNED_OPTIONAL:
        return SignedOptionalAFTVerifier(key_provider, default_ttl_sec)

    elif security_level == StickinessMode.SID_ONLY:
        return SidOnlyAFTVerifier(default_ttl_sec)

    else:
        raise ValueError(f"Unknown security level: {security_level}")

from typing import Optional

from pydantic import BaseModel, Field


class AFTClaims(BaseModel):
    """JWT claims structure for Affinity Tags."""

    sid: str = Field(..., description="Sender node id (duplicated for anti-replay)")
    exp: int = Field(..., description="Unix epoch seconds, ≤ 2 h ahead")
    scp: Optional[str] = Field(default=None, description="OPTIONAL: scope hint 'node' | 'flow' | 'sess'")
    client_sid: Optional[str] = Field(
        default=None, description="OPTIONAL: original client session id for session affinity"
    )


class AFTHeader(BaseModel):
    """JWT header structure for Affinity Tags."""

    alg: str = Field(..., description="Algorithm: 'EdDSA', 'ES256', or 'none'")
    kid: str = Field(..., description="≤ 32 ascii chars, unique per public key")


class AFTPayload(BaseModel):
    """Complete AFT payload combining header and claims."""

    header: AFTHeader
    claims: AFTClaims

    @property
    def is_signed(self) -> bool:
        """Check if this AFT is cryptographically signed."""
        return self.header.alg != "none"

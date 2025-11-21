from typing import List, Optional

from pydantic import BaseModel, Field


class CertificateSigningRequest(BaseModel):
    """Certificate Signing Request payload."""

    csr_pem: str = Field(..., description="Certificate Signing Request in PEM format")
    requester_id: str = Field(..., description="ID of the node requesting the certificate")
    physical_path: Optional[str] = Field(None, description="Physical path for the node")
    logicals: Optional[List[str]] = Field(
        default_factory=list,
        description="Host-like logical addresses the node will serve",
    )


class CertificateIssuanceResponse(BaseModel):
    """Certificate issuance response."""

    certificate_pem: str = Field(..., description="Issued certificate in PEM format")
    certificate_chain_pem: Optional[str] = Field(None, description="Full certificate chain in PEM format")
    expires_at: str = Field(..., description="Certificate expiration time in ISO format")


class TrustBundleRoot(BaseModel):
    """Trust bundle certificate entry."""

    pem: str = Field(..., description="Certificate in PEM format")
    kid: Optional[str] = Field(None, description="Optional key identifier", alias="kid")
    not_before: Optional[str] = Field(None, description="Optional notBefore timestamp", alias="notBefore")
    not_after: Optional[str] = Field(None, description="Optional notAfter timestamp", alias="notAfter")

    model_config = {"populate_by_name": True}


class TrustBundleDocument(BaseModel):
    """Trust bundle document served by the CA."""

    version: int = Field(
        ..., description="Monotonic version number that changes when bundle contents rotate"
    )
    issued_at: str = Field(..., description="Time the bundle was generated", alias="issuedAt")
    valid_until: Optional[str] = Field(
        None, description="Earliest expiration among the bundled roots", alias="validUntil"
    )
    roots: List[TrustBundleRoot] = Field(..., description="Trust anchors")

    model_config = {"populate_by_name": True}

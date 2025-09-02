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

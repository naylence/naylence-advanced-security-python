from typing import Optional

from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.cert.fastapi_model import (
    CertificateIssuanceResponse,
    CertificateSigningRequest,
    TrustBundleDocument,
)


class CAService:
    """Abstract CA signing service interface."""

    @property
    def authorizer(self) -> Optional[Authorizer]:
        return None

    async def issue_certificate(self, csr: CertificateSigningRequest) -> CertificateIssuanceResponse:
        """Issue a certificate from a CSR."""
        raise NotImplementedError

    async def get_trust_bundle(self) -> Optional[TrustBundleDocument]:
        """
        Retrieve the current trust bundle served by this CA service.

        Default implementation returns None if the service does not expose a bundle.
        """
        return None

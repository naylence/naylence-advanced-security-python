from typing import Optional

from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.cert.fastapi_model import CertificateIssuanceResponse, CertificateSigningRequest


class CAService:
    """Abstract CA signing service interface."""

    @property
    def authorizer(self) -> Optional[Authorizer]:
        return None

    async def issue_certificate(self, csr: CertificateSigningRequest) -> CertificateIssuanceResponse:
        """Issue a certificate from a CSR."""
        raise NotImplementedError

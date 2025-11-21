"""
FastAPI router for Certificate Signing Service.

Provides HTTP endpoints for Certificate Signing Requests (CSR) and certificate issuance.
Designed to be pluggable with different CA backends (local OpenSSL, Vault, AWS PCA, etc.).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Request

from naylence.fame.security.cert.ca_service import CAService
from naylence.fame.security.cert.fastapi_model import CertificateIssuanceResponse, CertificateSigningRequest
from naylence.fame.util.logging import getLogger

if TYPE_CHECKING:
    from fastapi import APIRouter

logger = getLogger(__name__)

DEFAULT_PREFIX = "/fame/v1/ca"


def create_ca_router(
    *,
    ca_service: CAService,
    expected_audience: str = "fame.fabric",
    prefix: str = DEFAULT_PREFIX,
) -> APIRouter:
    """Create FastAPI router for CA signing service."""
    from fastapi import APIRouter, HTTPException

    router = APIRouter(prefix=prefix, tags=["Certificate Signing Service"])

    @router.post("/sign", response_model=CertificateIssuanceResponse)
    async def sign_certificate(request: Request, csr_request: CertificateSigningRequest):
        """
        Sign a Certificate Signing Request (CSR) and return the issued certificate.

        This endpoint accepts a CSR in PEM format along with node metadata and returns
        a signed certificate. The certificate will be short-lived (24 hours) and include
        the node's physical and logicals in the Subject Alternative Names extension.
        """

        if ca_service.authorizer:
            auth_header = request.headers.get("authorization", "")

            auth_result = await ca_service.authorizer.authenticate(auth_header)
            if auth_result is None:
                logger.warning(
                    "client_authentication_failed",
                    authorizer_type=type(ca_service.authorizer).__name__,
                )
                raise HTTPException(401, "Authentication failed")

        try:
            result = await ca_service.issue_certificate(csr_request)
            return result

        except ValueError as e:
            logger.warning("invalid_csr_request", error=str(e))
            raise HTTPException(status_code=400, detail=f"Invalid CSR: {e}")

        except Exception as e:
            logger.error("certificate_signing_error", error=str(e), exc_info=True)
            raise HTTPException(status_code=500, detail="Certificate signing failed")

    @router.get("/health")
    async def health_check():
        """Health check endpoint for the CA service."""
        return {"status": "healthy", "service": "ca-signing"}

    @router.get("/.well-known/naylence/trust-bundle.json")
    async def get_trust_bundle(request: Request):
        """
        Retrieve the trust bundle containing root certificates.

        Returns a JSON document with the current trust anchors and version information.
        Supports ETag-based caching for efficient updates.
        """
        import hashlib

        from fastapi import Response

        bundle = await ca_service.get_trust_bundle()
        if bundle is None:
            raise HTTPException(status_code=404, detail={"error": "trust_bundle_unavailable"})

        # Serialize bundle for ETag computation (use camelCase via aliases)
        # exclude_none=True omits null fields to match TypeScript behavior
        payload = bundle.model_dump_json(by_alias=True, exclude_none=True)
        etag_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
        etag = f'"{etag_hash}"'

        # Check if client has cached version
        request_etag = request.headers.get("if-none-match")
        if request_etag:
            # Strip W/ prefix and quotes for comparison
            clean_request_etag = request_etag.replace("W/", "").strip('"')
            clean_etag = etag.strip('"')
            if clean_request_etag == clean_etag:
                return Response(
                    status_code=304,
                    headers={
                        "ETag": etag,
                        "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400",
                    },
                )

        return Response(
            content=payload,
            media_type="application/json",
            headers={
                "ETag": etag,
                "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400",
            },
        )

    return router

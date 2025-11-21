import os
from typing import List, Optional

from naylence.fame.security.auth.authorizer import Authorizer  # Add this import (adjust path if needed)
from naylence.fame.security.cert.ca_fastapi_router import logger
from naylence.fame.security.cert.ca_service import CAService
from naylence.fame.security.cert.fastapi_model import (
    CertificateIssuanceResponse,
    CertificateSigningRequest,
    TrustBundleDocument,
    TrustBundleRoot,
)


class DefaultCAService(CAService):
    """Local CA signing service using the existing ca_service module."""

    def __init__(
        self,
        ca_cert_pem: Optional[str] = None,
        ca_key_pem: Optional[str] = None,
        intermediate_chain_pem: Optional[str] = None,
        signing_cert_pem: Optional[str] = None,
        signing_key_pem: Optional[str] = None,
        authorizer: Optional[Authorizer] = None,
    ):
        """
        Initialize the CA signing service.

        Args:
            ca_cert_pem: Root CA certificate in PEM format
            ca_key_pem: Root CA private key in PEM format (only needed if no signing cert provided)
            intermediate_chain_pem: Complete intermediate CA chain in PEM format (optional)
            signing_cert_pem: Certificate to use for signing (leaf of the chain, optional)
            signing_key_pem: Private key for the signing certificate (optional)
        """
        self._ca_cert_pem = ca_cert_pem
        self._ca_key_pem = ca_key_pem
        self._intermediate_chain_pem = intermediate_chain_pem
        self._signing_cert_pem = signing_cert_pem
        self._signing_key_pem = signing_key_pem
        self._authorizer = authorizer

    @property
    def authorizer(self) -> Optional[Authorizer]:
        return self._authorizer

    def _get_ca_credentials(
        self,
    ) -> tuple[str, str, Optional[str], Optional[str], Optional[str]]:
        """
        Get CA credentials from environment or configuration.

        Returns:
            tuple: (root_ca_cert_pem, root_ca_key_pem, intermediate_chain_pem,
                   signing_cert_pem, signing_key_pem)
        """
        ca_cert_pem = self._ca_cert_pem
        ca_key_pem = self._ca_key_pem
        intermediate_chain_pem = self._intermediate_chain_pem
        signing_cert_pem = self._signing_cert_pem
        signing_key_pem = self._signing_key_pem

        # Try environment variables if not provided
        if not ca_cert_pem:
            ca_cert_file = os.environ.get("FAME_CA_CERT_FILE")
            if ca_cert_file and os.path.exists(ca_cert_file):
                with open(ca_cert_file) as f:
                    ca_cert_pem = f.read()
            else:
                ca_cert_pem = os.environ.get("FAME_CA_CERT_PEM")

        if not ca_key_pem:
            ca_key_file = os.environ.get("FAME_CA_KEY_FILE")
            if ca_key_file and os.path.exists(ca_key_file):
                with open(ca_key_file) as f:
                    ca_key_pem = f.read()
            else:
                ca_key_pem = os.environ.get("FAME_CA_KEY_PEM")

        # Add intermediate chain support
        if not intermediate_chain_pem:
            intermediate_chain_file = os.environ.get("FAME_INTERMEDIATE_CHAIN_FILE")
            if intermediate_chain_file and os.path.exists(intermediate_chain_file):
                with open(intermediate_chain_file) as f:
                    intermediate_chain_pem = f.read()
            else:
                intermediate_chain_pem = os.environ.get("FAME_INTERMEDIATE_CHAIN_PEM")

        # Add signing certificate support (leaf of the intermediate chain)
        if not signing_cert_pem:
            signing_cert_file = os.environ.get("FAME_SIGNING_CERT_FILE")
            if signing_cert_file and os.path.exists(signing_cert_file):
                with open(signing_cert_file) as f:
                    signing_cert_pem = f.read()
            else:
                signing_cert_pem = os.environ.get("FAME_SIGNING_CERT_PEM")

        if not signing_key_pem:
            signing_key_file = os.environ.get("FAME_SIGNING_KEY_FILE")
            if signing_key_file and os.path.exists(signing_key_file):
                with open(signing_key_file) as f:
                    signing_key_pem = f.read()
            else:
                signing_key_pem = os.environ.get("FAME_SIGNING_KEY_PEM")

        # Fallback to test CA if nothing configured
        if not ca_cert_pem or not ca_key_pem:
            from naylence.fame.security.cert.internal_ca_service import create_test_ca

            logger.warning("No CA credentials configured, using test CA (not for production!)")
            root_cert, root_key = create_test_ca()
            return (
                root_cert,
                root_key,
                intermediate_chain_pem,
                signing_cert_pem,
                signing_key_pem,
            )

        return (
            ca_cert_pem,
            ca_key_pem,
            intermediate_chain_pem,
            signing_cert_pem,
            signing_key_pem,
        )

    def _parse_certificate_chain(self, chain_pem: str) -> List[str]:
        """
        Parse a PEM certificate chain into individual certificates.

        Args:
            chain_pem: Certificate chain in PEM format

        Returns:
            List of individual certificate PEM strings, ordered from leaf to root
        """
        certificates = []
        current_cert = ""
        in_cert = False

        for line in chain_pem.split("\n"):
            if "-----BEGIN CERTIFICATE-----" in line:
                in_cert = True
                current_cert = line + "\n"
            elif "-----END CERTIFICATE-----" in line:
                current_cert += line + "\n"
                certificates.append(current_cert.strip())
                current_cert = ""
                in_cert = False
            elif in_cert:
                current_cert += line + "\n"

        return certificates

    async def issue_certificate(self, csr: CertificateSigningRequest) -> CertificateIssuanceResponse:
        """Issue a certificate from a CSR using the local CA service."""

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from naylence.fame.security.cert.internal_ca_service import (
            CASigningService as InternalCAService,
        )
        from naylence.fame.util.util import secure_digest

        # Get CA credentials including intermediate chain
        (
            ca_cert_pem,
            ca_key_pem,
            intermediate_chain_pem,
            signing_cert_pem,
            signing_key_pem,
        ) = self._get_ca_credentials()

        # Determine which certificate and key to use for signing
        if signing_cert_pem and signing_key_pem:
            # Use specific signing certificate (leaf of intermediate chain)
            ca_service = InternalCAService(signing_cert_pem, signing_key_pem)
            logger.debug("using_signing_certificate_for_signing", requester_id=csr.requester_id)
        elif intermediate_chain_pem:
            # Extract the leaf certificate from the intermediate chain
            intermediate_certs = self._parse_certificate_chain(intermediate_chain_pem)
            if intermediate_certs:
                # Use the first certificate in the chain (should be the leaf/signing certificate)
                leaf_cert_pem = intermediate_certs[0]
                # For now, we'll need the signing key to be provided separately
                # This is a limitation - in a real implementation, you'd have key management
                if signing_key_pem:
                    ca_service = InternalCAService(leaf_cert_pem, signing_key_pem)
                    logger.debug(
                        "using_intermediate_leaf_ca_for_signing",
                        requester_id=csr.requester_id,
                    )
                else:
                    # Fall back to root CA if no signing key provided
                    ca_service = InternalCAService(ca_cert_pem, ca_key_pem)
                    logger.warning(
                        "no_signing_key_for_intermediate_falling_back_to_root",
                        requester_id=csr.requester_id,
                    )
            else:
                # Fall back to root CA
                ca_service = InternalCAService(ca_cert_pem, ca_key_pem)
                logger.warning(
                    "invalid_intermediate_chain_falling_back_to_root",
                    requester_id=csr.requester_id,
                )
        else:
            # Sign with root CA
            ca_service = InternalCAService(ca_cert_pem, ca_key_pem)
            logger.debug("using_root_ca_for_signing", requester_id=csr.requester_id)

        # Parse the CSR to extract information
        csr_obj = x509.load_pem_x509_csr(csr.csr_pem.encode())

        # Extract public key from CSR
        public_key = csr_obj.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        # Determine node SID and physical path
        physical_path = csr.physical_path or f"/unknown/{csr.requester_id}"
        node_sid = secure_digest(physical_path)
        logicals = csr.logicals or []

        logger.debug(
            "issuing_certificate",
            requester_id=csr.requester_id,
            physical_path=physical_path,
            logicals=logicals,
            node_sid=node_sid,
        )

        try:
            # Issue the certificate
            cert_pem = ca_service.sign_node_cert(
                public_key_pem=public_key_pem,
                node_id=csr.requester_id,
                node_sid=node_sid,
                physical_path=physical_path,
                logicals=logicals,
                ttl_days=1,  # Short-lived certificates (24 hours)
            )

            # Parse certificate to get expiration
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())
            expires_at = cert_obj.not_valid_after_utc.isoformat()

            # Build proper certificate chain: node cert -> intermediate cert(s)
            # Note: Root CA is intentionally excluded as it should only exist in trust stores
            chain_parts = [cert_pem.strip()]

            logger.debug(
                "chain_building_start",
                requester_id=csr.requester_id,
                has_intermediate_chain=intermediate_chain_pem is not None,
                has_signing_cert=signing_cert_pem is not None,
                signing_cert_matches_root=signing_cert_pem
                and ca_cert_pem
                and signing_cert_pem.strip() == ca_cert_pem.strip(),
            )

            # Add intermediate certificates if present (but exclude root CA)
            if intermediate_chain_pem:
                intermediate_certs = self._parse_certificate_chain(intermediate_chain_pem)

                # Filter out root CA from intermediate chain
                filtered_intermediate_certs = []
                for cert in intermediate_certs:
                    if cert.strip() != ca_cert_pem.strip():
                        filtered_intermediate_certs.append(cert.strip())
                    else:
                        logger.debug(
                            "excluded_root_ca_from_intermediate_chain",
                            requester_id=csr.requester_id,
                        )

                chain_parts.extend(filtered_intermediate_certs)
                logger.debug(
                    "included_intermediate_chain_in_response",
                    requester_id=csr.requester_id,
                    intermediate_count=len(filtered_intermediate_certs),
                    excluded_root_ca=True,
                    intermediate_subjects=[f"cert_{i}" for i in range(len(filtered_intermediate_certs))],
                )
            elif signing_cert_pem and signing_cert_pem.strip() != ca_cert_pem.strip():
                # If we have a signing cert that's different from root CA, include it
                chain_parts.append(signing_cert_pem.strip())
                logger.debug("included_signing_cert_in_chain", requester_id=csr.requester_id)

            # Root CA is intentionally NOT included in the response chain
            # It should only exist in trust stores on the receiving nodes
            logger.debug(
                "root_ca_excluded_from_chain",
                requester_id=csr.requester_id,
                reason="security_best_practice",
            )

            certificate_chain_pem = "\n".join(chain_parts)

            logger.debug(
                "certificate_issued_successfully",
                requester_id=csr.requester_id,
                expires_at=expires_at,
                cert_serial=str(cert_obj.serial_number),
                chain_length=len(chain_parts),
                has_intermediate_chain=intermediate_chain_pem is not None,
            )

            return CertificateIssuanceResponse(
                certificate_pem=cert_pem,
                certificate_chain_pem=certificate_chain_pem,
                expires_at=expires_at,
            )

        except Exception as e:
            logger.error(
                "certificate_issuance_failed",
                requester_id=csr.requester_id,
                error=str(e),
                exc_info=True,
            )
            raise

    async def get_trust_bundle(self) -> Optional[TrustBundleDocument]:
        """
        Retrieve the trust bundle containing root certificates.

        Returns:
            TrustBundleDocument with versioned trust anchors, or None if unavailable
        """
        from datetime import datetime

        from cryptography import x509

        try:
            # Get CA credentials
            (
                ca_cert_pem,
                ca_key_pem,
                intermediate_chain_pem,
                signing_cert_pem,
                signing_key_pem,
            ) = self._get_ca_credentials()

            # Parse root certificate
            root_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())

            # Extract certificate validity dates in ISO format with .000Z suffix (matching TS)
            not_before = root_cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            not_after = root_cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%S.000Z")

            # Build trust bundle with root certificate
            roots = [
                TrustBundleRoot(
                    pem=ca_cert_pem,
                    kid=None,  # Could extract from cert subject key identifier if needed
                    not_before=not_before,
                    not_after=not_after,
                )
            ]

            # Compute version from root PEM hash (matching TS implementation)
            import hashlib

            serialized = "\n".join(root.pem for root in roots)
            digest = hashlib.sha256(serialized.encode()).hexdigest()
            version_hex = digest[:12]  # First 12 hex chars
            version = int(version_hex, 16)

            # Create trust bundle document with ISO timestamp matching TS format
            from datetime import datetime, timezone

            issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            trust_bundle = TrustBundleDocument(
                version=version,
                issued_at=issued_at,
                valid_until=not_after,  # Valid until root expires
                roots=roots,
            )

            logger.debug(
                "trust_bundle_generated", root_count=len(roots), valid_until=not_after, version=version
            )
            return trust_bundle

        except Exception as e:
            logger.error("trust_bundle_generation_failed", error=str(e), exc_info=True)
            return None

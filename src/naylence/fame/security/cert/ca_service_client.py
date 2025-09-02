"""
Certificate client for requesting certificates from a CA signing service.

Provides async HTTP client to request certificates from the CA signing service.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Tuple

import aiohttp
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from naylence.fame.grants.http_connection_grant import HttpConnectionGrant
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


ENV_VAR_FAME_CA_SERVICE_URL = "FAME_CA_SERVICE_URL"


def _extract_certificate_info(cert_pem: str) -> dict:
    """
    Parse certificate and extract information as a dictionary for structured logging.

    Args:
        cert_pem: Certificate in PEM format

    Returns:
        Dictionary with certificate details
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

        # Extract basic information
        subject = cert.subject
        issuer = cert.issuer
        serial_number = cert.serial_number
        not_valid_before = cert.not_valid_before_utc
        not_valid_after = cert.not_valid_after_utc

        # Format subject and issuer as readable strings
        subject_str = ", ".join([f"{attr.oid._name}={attr.value}" for attr in subject])
        issuer_str = ", ".join([f"{attr.oid._name}={attr.value}" for attr in issuer])

        # Extract Subject Alternative Names if present
        san_list = []
        spiffe_id = None
        try:
            for ext in cert.extensions:
                if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    san_names = ext.value
                    for name in san_names:
                        san_str = str(name)
                        san_list.append(san_str)
                        # Extract SPIFFE ID if present
                        if "spiffe://" in san_str:
                            # Extract the actual URI value from the UniformResourceIdentifier representation
                            import re

                            match = re.search(r"value='(spiffe://[^']+)'", san_str)
                            if match:
                                spiffe_id = match.group(1)
                    break
        except Exception:
            pass

        # Extract Fame-specific extensions
        node_sid = None
        node_id = None
        logical_hosts = []

        try:
            # Import here to avoid circular imports
            from naylence.fame.security.cert.internal_ca_service import (
                extract_logical_hosts_from_cert,
                extract_node_id_from_cert,
                extract_sid_from_cert,
                extract_sid_from_spiffe_id,
            )

            # Extract SID from certificate extension (fallback if no SPIFFE ID)
            try:
                sid_bytes = extract_sid_from_cert(cert_pem)
                if sid_bytes:
                    try:
                        node_sid = sid_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        node_sid = f"<{len(sid_bytes)} bytes>"
            except Exception:
                pass

            # Extract SID from SPIFFE ID for display (primary method)
            if spiffe_id:
                try:
                    spiffe_sid = extract_sid_from_spiffe_id(spiffe_id)
                    if spiffe_sid:
                        node_sid = spiffe_sid  # SPIFFE ID takes precedence
                except Exception:
                    pass

            try:
                node_id = extract_node_id_from_cert(cert_pem)
            except Exception:
                pass

            try:
                logical_hosts = extract_logical_hosts_from_cert(cert_pem)
            except Exception:
                pass

        except ImportError:
            # Fame extensions not available, skip
            pass

        # Calculate validity status
        now = datetime.now(not_valid_before.tzinfo)
        time_remaining = not_valid_after - now

        status = "unknown"
        days_remaining = 0
        hours_remaining = 0
        minutes_remaining = 0

        if now < not_valid_before:
            status = "not_yet_valid"
        elif now > not_valid_after:
            status = "expired"
        else:
            status = "valid"
            days_remaining = time_remaining.days
            hours_remaining = time_remaining.seconds // 3600
            minutes_remaining = (time_remaining.seconds % 3600) // 60

        result = {
            "subject": subject_str,
            "issuer": issuer_str,
            "serial_number": f"{serial_number:x}",
            "valid_from": not_valid_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "valid_until": not_valid_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "subject_alternative_names": san_list if san_list else None,
            "status": status,
            "days_remaining": days_remaining if status == "valid" else None,
            "hours_remaining": hours_remaining if status == "valid" else None,
            "minutes_remaining": minutes_remaining if status == "valid" else None,
        }

        # Add Fame-specific fields if present
        if spiffe_id:
            result["spiffe_id"] = spiffe_id
        if node_sid:
            result["node_sid"] = node_sid
        if node_id:
            result["node_id"] = node_id
        if logical_hosts:
            result["logical_hosts"] = logical_hosts

        return result

    except Exception as e:
        return {"error": f"Failed to parse certificate: {e}"}


def _format_certificate_info(cert_pem: str, cert_type: str = "Certificate") -> str:
    """
    Parse and format certificate information in a human-readable format.

    Args:
        cert_pem: Certificate in PEM format
        cert_type: Type description for logging (e.g., "Certificate", "CA Certificate")

    Returns:
        Formatted string with certificate details
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

        # Extract basic information
        subject = cert.subject
        issuer = cert.issuer
        serial_number = cert.serial_number
        not_valid_before = cert.not_valid_before_utc
        not_valid_after = cert.not_valid_after_utc

        # Format subject and issuer as readable strings
        subject_str = ", ".join([f"{attr.oid._name}={attr.value}" for attr in subject])
        issuer_str = ", ".join([f"{attr.oid._name}={attr.value}" for attr in issuer])

        # Extract Subject Alternative Names if present
        san_list = []
        spiffe_id = None
        try:
            for ext in cert.extensions:
                if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    # Handle SAN extension safely
                    san_names = ext.value
                    for name in san_names:
                        san_str = str(name)
                        san_list.append(san_str)
                        # Extract SPIFFE ID if present
                        if "spiffe://" in san_str:
                            # Extract the actual URI value from the UniformResourceIdentifier representation
                            import re

                            match = re.search(r"value='(spiffe://[^']+)'", san_str)
                            if match:
                                spiffe_id = match.group(1)
                    break
        except Exception:
            # If SAN parsing fails for any reason, just skip it
            pass

        # Extract Fame-specific extensions
        node_sid = None
        node_id = None
        logical_hosts = []

        try:
            # Import here to avoid circular imports
            from naylence.fame.security.cert.internal_ca_service import (
                extract_logical_hosts_from_cert,
                extract_node_id_from_cert,
                extract_sid_from_cert,
                extract_sid_from_spiffe_id,
            )

            # Try to extract Fame extensions

            # Extract SID from certificate extension (fallback if no SPIFFE ID)
            try:
                sid_bytes = extract_sid_from_cert(cert_pem)
                if sid_bytes:
                    try:
                        node_sid = sid_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        node_sid = f"<{len(sid_bytes)} bytes>"
            except Exception:
                pass

            # Extract SID from SPIFFE ID for display (primary method)
            if spiffe_id:
                try:
                    spiffe_sid = extract_sid_from_spiffe_id(spiffe_id)
                    if spiffe_sid:
                        node_sid = spiffe_sid  # SPIFFE ID takes precedence
                except Exception:
                    pass

            try:
                node_id = extract_node_id_from_cert(cert_pem)
            except Exception:
                pass

            try:
                logical_hosts = extract_logical_hosts_from_cert(cert_pem)
            except Exception:
                pass

        except ImportError:
            # Fame extensions not available, skip
            pass

        # Format the information
        info_lines = [
            f"=== {cert_type} Information ===",
            f"Subject: {subject_str}",
            f"Issuer: {issuer_str}",
            f"Serial Number: {serial_number:x}",
            f"Valid From: {not_valid_before.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Valid Until: {not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        ]

        if san_list:
            info_lines.append(f"Subject Alternative Names: {', '.join(san_list)}")

        # Add Fame-specific information if present
        if spiffe_id:
            info_lines.append(f"SPIFFE ID: {spiffe_id}")
        if node_sid:
            info_lines.append(f"Node SID: {node_sid}")
        if node_id:
            info_lines.append(f"Node ID: {node_id}")
        if logical_hosts:
            info_lines.append(f"Logical Hosts: {', '.join(logical_hosts)}")

        # Calculate validity period
        now = datetime.now(not_valid_before.tzinfo)
        if now < not_valid_before:
            info_lines.append("Status: Not yet valid")
        elif now > not_valid_after:
            info_lines.append("Status: Expired")
        else:
            time_remaining = not_valid_after - now
            days_remaining = time_remaining.days
            hours_remaining = time_remaining.seconds // 3600
            minutes_remaining = (time_remaining.seconds % 3600) // 60

            if days_remaining > 0:
                info_lines.append(f"Status: Valid ({days_remaining} days remaining)")
            elif hours_remaining > 0:
                if minutes_remaining > 0:
                    info_lines.append(
                        f"Status: Valid ({hours_remaining} hours, {minutes_remaining} minutes remaining)"
                    )
                else:
                    info_lines.append(f"Status: Valid ({hours_remaining} hours remaining)")
            else:
                info_lines.append(f"Status: Valid ({minutes_remaining} minutes remaining)")

        return "\n".join(info_lines)

    except Exception as e:
        return f"=== {cert_type} Information ===\nError parsing certificate: {e}"


class CAServiceClient:
    """Client for requesting certificates from a CA signing service."""

    def __init__(
        self,
        connection_grant: HttpConnectionGrant,
        session: Optional[aiohttp.ClientSession] = None,
        timeout_seconds: float = 30.0,
    ):
        assert isinstance(connection_grant, HttpConnectionGrant), (
            "connection_grant must be an instance of HttpConnectionGrant"
        )

        self._connection_grant = connection_grant
        self._session = session
        self._timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self._should_close_session = session is None
        self._auth_header: Optional[str] = None

    def set_auth_header(self, auth_header: str) -> None:
        """Set the authorization header for outbound requests."""
        self._auth_header = auth_header

    async def __aenter__(self):
        if self._session is None:
            self._session = aiohttp.ClientSession(timeout=self._timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._should_close_session and self._session:
            await self._session.close()

    async def request_certificate(
        self,
        csr_pem: str,
        requester_id: str,
        physical_path: Optional[str] = None,
        logicals: Optional[list[str]] = None,
    ) -> Tuple[str, str]:
        """
        Request a certificate from the CA service.

        Args:
            csr_pem: Certificate Signing Request in PEM format
            requester_id: ID of the node requesting the certificate
            physical_path: Physical path for the node (optional)
            logicals: Logicals the node will serve (optional)

        Returns:
            Tuple of (certificate_pem, certificate_chain_pem)

        Raises:
            CertificateRequestError: If the request fails
        """
        if not self._session:
            raise RuntimeError("Certificate client not initialized - use async context manager")

        request_data = {
            "csr_pem": csr_pem,
            "requester_id": requester_id,
            "physical_path": physical_path,
            "logicals": logicals or [],
        }

        url = f"{self._connection_grant.url.rstrip('/')}/sign"

        logger.debug(
            "requesting_certificate",
            requester_id=requester_id,
            ca_service_url=url,
            physical_path=physical_path,
            logicals=logicals,
        )

        # Prepare headers
        headers = {}
        if self._auth_header:
            headers["Authorization"] = self._auth_header

        try:
            async with self._session.post(url, json=request_data, headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    certificate_pem = result["certificate_pem"]
                    certificate_chain_pem = result.get("certificate_chain_pem", certificate_pem)

                    logger.debug(
                        "certificate_request_successful",
                        requester_id=requester_id,
                        expires_at=result.get("expires_at"),
                    )

                    # Extract and log certificate information with structured logging
                    cert_info = _extract_certificate_info(certificate_pem)
                    logger.debug(
                        "certificate_details",
                        requester_id=requester_id,
                        certificate_type="issued_certificate",
                        **cert_info,
                    )

                    # If we have a separate certificate chain, also log its details
                    if certificate_chain_pem != certificate_pem:
                        # Extract individual certificates from the chain
                        chain_certs = certificate_chain_pem.split("-----END CERTIFICATE-----\n")[:-1]
                        for i, cert_block in enumerate(chain_certs):
                            if cert_block.strip():
                                cert_pem_block = cert_block + "-----END CERTIFICATE-----\n"
                                if i == 0:
                                    # First cert in chain is usually the issued certificate
                                    # (skip if same as above)
                                    if cert_pem_block.strip() != certificate_pem.strip():
                                        chain_cert_info = _extract_certificate_info(cert_pem_block)
                                        logger.debug(
                                            "certificate_chain_details",
                                            requester_id=requester_id,
                                            certificate_type="certificate_chain",
                                            chain_index=i,
                                            **chain_cert_info,
                                        )
                                else:
                                    # Subsequent certs are intermediate/root CAs
                                    ca_cert_info = _extract_certificate_info(cert_pem_block)
                                    logger.debug(
                                        "certificate_chain_details",
                                        requester_id=requester_id,
                                        certificate_type="ca_certificate",
                                        chain_index=i,
                                        **ca_cert_info,
                                    )

                    return certificate_pem, certificate_chain_pem

                else:
                    error_detail = "Unknown error"
                    try:
                        error_data = await response.json()
                        error_detail = error_data.get("detail", error_detail)
                    except Exception:
                        error_detail = await response.text()

                    logger.error(
                        "certificate_request_failed",
                        requester_id=requester_id,
                        status_code=response.status,
                        error=error_detail,
                    )

                    raise CertificateRequestError(
                        f"Certificate request failed (HTTP {response.status}): {error_detail}"
                    )

        except aiohttp.ClientError as e:
            logger.error("certificate_request_network_error", requester_id=requester_id, error=str(e))
            raise CertificateRequestError(f"Network error requesting certificate: {e}")

        except Exception as e:
            logger.error(
                "certificate_request_unexpected_error",
                requester_id=requester_id,
                error=str(e),
                exc_info=True,
            )
            raise CertificateRequestError(f"Unexpected error requesting certificate: {e}")


class CertificateRequestError(Exception):
    """Raised when a certificate request fails."""

    pass

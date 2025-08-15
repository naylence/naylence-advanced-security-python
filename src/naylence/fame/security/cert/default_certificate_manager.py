"""
Default implementation of certificate management for node signing material provisioning.
"""

from __future__ import annotations

import os
from typing import Optional

from naylence.fame.core import NodeWelcomeFrame, SecuritySettings, SigningMaterial
from naylence.fame.security.cert.certificate_client import CertificateClient, CertificateRequestError
from naylence.fame.security.cert.certificate_manager import CertificateManager
from naylence.fame.security.crypto.providers.crypto_provider import (
    CryptoProvider,
    get_crypto_provider,
)
from naylence.fame.security.policy.security_policy import SigningConfig
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class DefaultCertificateManager(CertificateManager):
    """
    Default implementation of certificate management for node signing material provisioning.

    This manager encapsulates all certificate-related logic and makes it policy-driven,
    removing the need for scattered certificate handling throughout the codebase.
    """

    def __init__(self, security_settings: Optional[SecuritySettings] = None, **kwargs):
        super().__init__(**kwargs)
        self.security_settings = security_settings or SecuritySettings()

    async def ensure_root_certificate(self, node_id: str, physical_path: str, logicals: list[str]) -> bool:
        """
        Handle certificate provisioning when a root node starts.

        Args:
            node_id: Node identifier
            physical_path: Physical path of the node
            logicals: List of logical addresses this node will serve

        Returns:
            True if certificate is available or not needed, False if provisioning failed
        """
        # Check if we need X.509 certificates based on security profile or signing config
        needs_x509 = (
            self.security_settings.signing_material == SigningMaterial.X509_CHAIN
            or self.signing_config.signing_material == SigningMaterial.X509_CHAIN
        )

        if not needs_x509:
            logger.debug(
                "certificate_not_required", signing_material=self.security_settings.signing_material
            )
            return True

        logger.debug("provisioning_certificate_for_root_node", node_id=node_id, physical_path=physical_path)

        success = await self._ensure_node_certificate(
            node_id=node_id,
            physical_path=physical_path,
            logicals=logicals,
        )

        if success:
            logger.debug(
                "certificate_provisioned_successfully_for_root",
                node_id=node_id,
                physical_path=physical_path,
            )
        else:
            logger.error(
                "certificate_provisioning_failed_for_root",
                node_id=node_id,
                physical_path=physical_path,
                message="Certificate provisioning or validation failed - node cannot start",
            )

        return success

    def _validate_certificate_against_trust_anchors(
        self, crypto_provider: CryptoProvider, node_id: str
    ) -> bool:
        """
        Validate that the stored certificate chain is rooted in a trusted CA.

        This function ensures that when a node obtains a certificate, it can trust
        that certificate based on its configured trusted root CAs.

        Args:
            crypto_provider: The crypto provider containing the stored certificate
            node_id: Node identifier for logging

        Returns:
            True if certificate is valid and trusted, False otherwise
        """
        try:
            from cryptography import x509

            from naylence.fame.security.cert.util import _check_trust_anchor

            # Get trust store from environment
            trust_store_pem = os.environ.get("FAME_CA_CERTS")
            if not trust_store_pem:
                logger.error(
                    "trust_anchor_validation_failed",
                    node_id=node_id,
                    reason="FAME_CA_CERTS_not_set",
                    message="FAME_CA_CERTS environment variable is required for certificate validation",
                )
                return False

            # Check if it's a file path or PEM content
            if not trust_store_pem.startswith("-----BEGIN"):
                # It's a file path
                try:
                    with open(trust_store_pem) as f:
                        trust_store_content = f.read()
                except Exception as e:
                    logger.error(
                        "trust_anchor_validation_failed",
                        node_id=node_id,
                        reason="failed_to_read_trust_store",
                        trust_store_path=trust_store_pem,
                        error=str(e),
                    )
                    return False
            else:
                trust_store_content = trust_store_pem

            # Get the node's JWK which includes x5c certificate chain
            jwk = crypto_provider.node_jwk()
            if "x5c" not in jwk:
                logger.error(
                    "trust_anchor_validation_failed",
                    node_id=node_id,
                    reason="no_certificate_chain_in_jwk",
                    message="Node JWK does not contain x5c certificate chain",
                )
                return False

            x5c = jwk["x5c"]
            if not x5c:
                logger.error(
                    "trust_anchor_validation_failed",
                    node_id=node_id,
                    reason="empty_certificate_chain",
                    message="Certificate chain is empty",
                )
                return False

            # Convert x5c to certificate objects
            import base64

            chain = []
            for i, cert_b64 in enumerate(x5c):
                try:
                    cert_der = base64.b64decode(cert_b64)
                    cert = x509.load_der_x509_certificate(cert_der)
                    chain.append(cert)
                except Exception as e:
                    logger.error(
                        "trust_anchor_validation_failed",
                        node_id=node_id,
                        reason="invalid_certificate_in_chain",
                        cert_index=i,
                        error=str(e),
                    )
                    return False

            logger.debug(
                "validating_certificate_chain_against_trust_anchors",
                node_id=node_id,
                chain_length=len(chain),
                trust_store_size=len(trust_store_content),
            )

            # Validate the certificate chain against trust anchors
            _check_trust_anchor(chain, trust_store_content)

            logger.debug(
                "certificate_chain_validation_successful",
                node_id=node_id,
                chain_length=len(chain),
                message="Certificate chain is rooted in trusted CA",
            )
            return True

        except ValueError as e:
            logger.error(
                "trust_anchor_validation_failed",
                node_id=node_id,
                reason="certificate_not_trusted",
                error=str(e),
                message="Certificate chain is not rooted in a trusted CA from FAME_CA_CERTS",
            )
            return False

        except Exception as e:
            logger.error(
                "trust_anchor_validation_failed",
                node_id=node_id,
                reason="validation_error",
                error=str(e),
                exc_info=True,
            )
            return False

    async def _ensure_node_certificate(
        self,
        node_id: Optional[str] = None,
        physical_path: Optional[str] = None,
        logicals: Optional[list[str]] = None,
        ca_service_url: Optional[str] = None,
        crypto_provider: Optional[CryptoProvider] = None,
    ) -> bool:
        """
        Ensure the node has a valid certificate, requesting one from CA service if needed.

        This function implements the new certificate flow:
        1. Check if crypto provider already has a certificate
        2. If not, create a CSR and request certificate from CA service
        3. Store the received certificate in the crypto provider

        Args:
            crypto_provider: Crypto provider instance (uses default if None)
            node_id: Node identifier (uses crypto provider's if None)
            physical_path: Physical path for the node
            logicals: Logicals the node will serve
            ca_service_url: CA service URL (uses environment variable if None)

        Returns:
            True if certificate is available (existing or newly requested), False otherwise
        """
        # Certificate provisioning always uses CA service - self-signing has been removed

        # Get crypto provider
        if not crypto_provider:
            crypto_provider = get_crypto_provider()

        # Check if we already have a certificate
        if crypto_provider.has_certificate():
            logger.debug("node_certificate_already_available")
            # Validate existing certificate against trust anchors
            if not self._validate_certificate_against_trust_anchors(
                crypto_provider, node_id or crypto_provider.signature_key_id
            ):
                logger.error(
                    "existing_certificate_trust_validation_failed",
                    node_id=node_id or crypto_provider.signature_key_id,
                    message="Existing certificate is not rooted in trusted CA - node startup must fail",
                )
                return False
            logger.debug("existing_certificate_validated_against_trust_anchors")
            return True

        # Validate required parameters
        if not node_id:
            node_id = crypto_provider.signature_key_id

        if not physical_path:
            logger.error("physical_path_required_for_certificate_request")
            return False

        logicals = logicals or []

        try:
            # Create CSR
            logger.debug(
                "creating_certificate_signing_request",
                node_id=node_id,
                physical_path=physical_path,
                logicals=logicals,
            )

            csr_pem = crypto_provider.create_csr(
                node_id=node_id, physical_path=physical_path, logicals=logicals
            )

            # Request certificate from CA service
            logger.debug(
                "requesting_certificate_from_ca_service",
                node_id=node_id,
                ca_service_url=ca_service_url or os.environ.get("FAME_CA_SERVICE_URL", "default"),
            )

            async with CertificateClient(ca_service_url=ca_service_url) as client:
                certificate_pem, certificate_chain_pem = await client.request_certificate(
                    csr_pem=csr_pem,
                    requester_id=node_id,
                    physical_path=physical_path,
                    logicals=logicals,
                )

            # Store certificate in crypto provider
            crypto_provider.store_signed_certificate(certificate_pem, certificate_chain_pem)

            # Validate the stored certificate against trusted CA certs
            if not self._validate_certificate_against_trust_anchors(crypto_provider, node_id):
                logger.error(
                    "certificate_validation_failed",
                    node_id=node_id,
                    message="Stored certificate is not trusted",
                )
                return False

            logger.debug(
                "certificate_provisioned_successfully", node_id=node_id, physical_path=physical_path
            )
            return True

        except CertificateRequestError as e:
            logger.error("certificate_request_failed", node_id=node_id, error=str(e))
            return False

        except Exception as e:
            logger.error("certificate_provisioning_failed", node_id=node_id, error=str(e), exc_info=True)
            return False

    async def ensure_non_root_certificate(
        self,
        welcome_frame: NodeWelcomeFrame,
        ca_service_url: Optional[str] = None,
    ) -> bool:
        """
        Ensure node certificate after receiving welcome frame.

        This is a convenience wrapper for the common case where certificate is requested
        after successful admission (hello -> welcome flow).

        Args:
            welcome_frame: NodeWelcomeFrame from admission process
            crypto_provider: Crypto provider instance (uses default if None)
            ca_service_url: CA service URL (uses environment variable if None)

        Returns:
            True if certificate is available, False otherwise
        """
        # Extract attributes safely for test compatibility
        node_id = welcome_frame.system_id or None
        physical_path = welcome_frame.assigned_path or None
        logicals = welcome_frame.accepted_logicals or []

        if not node_id:
            logger.warning(
                "welcome_frame_missing_system_id", message="Cannot provision certificate without node ID"
            )
            return False

        if not physical_path:
            logger.warning(
                "welcome_frame_missing_assigned_path",
                message="Cannot provision certificate without physical path",
            )
            return False

        return await self._ensure_node_certificate(
            node_id=node_id,
            physical_path=physical_path,
            logicals=logicals,
            ca_service_url=ca_service_url,
        )


def create_certificate_manager(
    security_settings: Optional[SecuritySettings] = None, signing_config: Optional[SigningConfig] = None
) -> DefaultCertificateManager:
    """
    Factory function to create a DefaultCertificateManager instance.

    Args:
        security_settings: Security profile with signing material preferences
        signing_config: Signing configuration from security policy

    Returns:
        Configured DefaultCertificateManager instance
    """
    return DefaultCertificateManager(security_settings, signing_config=signing_config)

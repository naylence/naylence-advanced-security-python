"""
Certificate-based attachment key validator implementation.

This module provides a concrete implementation of AttachmentKeyValidator that
validates certificates during the attachment handshake between nodes, ensuring
both sides trust each other's certificates before establishing the connection.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

from naylence.fame.security.keys.attachment_key_validator import AttachmentKeyValidator
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class AttachmentCertValidator(AttachmentKeyValidator):
    """
    Certificate-based implementation of attachment key validator.

    This validator checks x5c certificate chains in JWK keys against a trusted
    CA store and validates certificate constraints during attachment handshake.
    """

    def __init__(
        self,
        trust_store: Optional[str] = None,
        enforce_name_constraints: bool = True,
        strict_validation: bool = True,
    ):
        self.trust_store = trust_store
        self.enforce_name_constraints = enforce_name_constraints
        self.strict_validation = strict_validation
        logger.debug("attachment_cert_validator_initialized")

    async def validate_attachment_keys(
        self, keys: Optional[List[Dict[str, Any]]], peer_id: str, scenario: str
    ) -> Tuple[bool, str]:
        """
        Validate certificates in keys during attachment handshake.

        This function performs strict certificate validation during the attachment
        process, ensuring that any certificate-bearing keys are rooted in trusted CAs.
        If validation fails, the attachment should be rejected.

        Args:
            keys: List of JWK keys (may contain x5c certificate chains)
            peer_id: Identifier of the peer node for logging
            scenario: Description of the validation scenario (e.g., "child_attach", "parent_attach")

        Returns:
            Tuple of (is_valid, error_message)
            - is_valid: True if all certificates are valid or no certificates present
            - error_message: Description of validation failure if any
        """
        if not keys:
            logger.debug("no_keys_provided_for_attachment_validation", peer_id=peer_id, scenario=scenario)
            return True, "No keys provided"

        # Get trust store - either from configured location or environment variable
        trust_store_pem = None
        if self.trust_store:
            # Read from configured trust store file
            try:
                with open(self.trust_store) as f:
                    trust_store_pem = f.read()
            except Exception as e:
                logger.error(
                    "attachment_trust_store_read_failed",
                    peer_id=peer_id,
                    scenario=scenario,
                    trust_store_path=self.trust_store,
                    error=str(e),
                    action="reject_attachment",
                )
                return False, f"Failed to read trust store from {self.trust_store}: {str(e)}"
        else:
            # Fall back to FAME_CA_CERTS environment variable
            trust_store_pem = os.environ.get("FAME_CA_CERTS")

        if not trust_store_pem:
            # For backward compatibility during transition, log warning but don't fail
            logger.warning(
                "attachment_certificate_validation_skipped",
                peer_id=peer_id,
                scenario=scenario,
                reason="trust_store_not_configured",
                message="Certificate validation skipped - no trust store configured"
                " and FAME_CA_CERTS environment variable not set",
            )
            return True, "Trust store not configured"

        # Validate each key that contains certificates
        has_certificates = False
        validation_errors = []

        for i, key in enumerate(keys):
            if "x5c" not in key:
                continue  # Skip keys without certificates

            has_certificates = True
            kid = key.get("kid", f"key_{i}")

            try:
                from naylence.fame.security.cert.util import validate_jwk_x5c_certificate

                is_valid, error_msg = validate_jwk_x5c_certificate(
                    key,
                    trust_store_pem=trust_store_pem,
                    enforce_name_constraints=self.enforce_name_constraints,
                    strict=self.strict_validation,
                )

                if not is_valid:
                    error_detail = f"Key {kid}: {error_msg}"
                    validation_errors.append(error_detail)
                    logger.error(
                        "attachment_certificate_validation_failed",
                        peer_id=peer_id,
                        scenario=scenario,
                        kid=kid,
                        error=error_msg,
                        action="reject_attachment",
                    )
                else:
                    logger.debug(
                        "attachment_certificate_validation_passed",
                        peer_id=peer_id,
                        scenario=scenario,
                        kid=kid,
                    )

            except Exception as e:
                error_detail = f"Key {kid}: validation exception - {str(e)}"
                validation_errors.append(error_detail)
                logger.error(
                    "attachment_certificate_validation_exception",
                    peer_id=peer_id,
                    scenario=scenario,
                    kid=kid,
                    error=str(e),
                    action="reject_attachment",
                )

        if validation_errors:
            error_summary = (
                f"Certificate validation failed for {len(validation_errors)} key(s): "
                + "; ".join(validation_errors)
            )
            return False, error_summary

        if has_certificates:
            logger.debug(
                "attachment_certificate_validation_successful",
                peer_id=peer_id,
                scenario=scenario,
                validated_keys=len([k for k in keys if "x5c" in k]),
            )
        else:
            logger.debug(
                "attachment_no_certificates_to_validate",
                peer_id=peer_id,
                scenario=scenario,
                total_keys=len(keys),
            )

        return True, "Validation successful"

    async def validate_child_attachment_keys(
        self, child_keys: Optional[List[Dict[str, Any]]], child_id: str
    ) -> Tuple[bool, str]:
        """
        Validate a child node's keys during attachment from the parent's perspective.

        Args:
            child_keys: Keys provided by the child node
            child_id: Child node identifier

        Returns:
            Tuple of (is_valid, error_message)
        """
        return await self.validate_attachment_keys(child_keys, child_id, "child_attach")

    async def validate_child_attachment_logicals(
        self,
        child_keys: Optional[List[Dict[str, Any]]],
        authorized_logicals: Optional[List[str]],
        child_id: str,
    ) -> Tuple[bool, str]:
        """
        Validate that child certificate logicals match authorized paths from welcome token.

        Args:
            child_keys: Keys provided by the child node
            authorized_logicals: Logicals authorized by welcome token
            child_id: Child node identifier

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not child_keys or not authorized_logicals:
            return True, "No certificate or authorization paths to validate"

        # Find keys with certificates
        cert_keys = [key for key in child_keys if "x5c" in key]
        if not cert_keys:
            return True, "No certificate keys to validate"

        try:
            # Validate each certificate's logicals against authorized paths
            for key in cert_keys:
                kid = key.get("kid", "unknown")
                x5c = key.get("x5c", [])

                if not x5c:
                    continue

                # Extract logicals from certificate
                from naylence.fame.security.cert.util import _validate_chain

                try:
                    (pub_key, cert), _ = _validate_chain(
                        x5c=x5c, enforce_name_constraints=False, trust_store_pem=None, return_cert=True
                    )

                    from naylence.fame.security.cert.util import host_logicals_from_cert

                    cert_logicals = host_logicals_from_cert(cert)

                    # Check if all certificate logicals are authorized
                    authorized_set = set(authorized_logicals)
                    cert_set = set(cert_logicals)

                    unauthorized_paths = cert_set - authorized_set
                    if unauthorized_paths:
                        return False, (
                            f"Certificate for {kid} contains unauthorized logicals: "
                            f"{list(unauthorized_paths)}. Authorized paths: {authorized_logicals}"
                        )

                except Exception as e:
                    logger.warning(
                        "certificate_logical_extraction_failed", child_id=child_id, kid=kid, error=str(e)
                    )
                    # Continue validation - this is not a security failure

            return True, "Certificate logicals validation successful"

        except Exception as e:
            return False, f"Logical validation error: {str(e)}"

    async def validate_parent_attachment_keys(
        self, parent_keys: Optional[List[Dict[str, Any]]], parent_id: str
    ) -> Tuple[bool, str]:
        """
        Validate a parent node's keys during attachment from the child's perspective.

        Args:
            parent_keys: Keys provided by the parent node
            parent_id: Parent node identifier

        Returns:
            Tuple of (is_valid, error_message)
        """
        return await self.validate_attachment_keys(parent_keys, parent_id, "parent_attach")

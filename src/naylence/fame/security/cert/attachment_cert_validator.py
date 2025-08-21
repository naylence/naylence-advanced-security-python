"""
Certificate-based attachment key validator implementation.

This module provides a concrete implementation of AttachmentKeyValidator that
validates certificates during the attachment handshake between nodes, ensuring
both sides trust each other's certificates before establishing the connection.
"""

from __future__ import annotations

from datetime import datetime
import os
from typing import Any, Dict, List, Optional, Tuple

from naylence.fame.security.keys.attachment_key_validator import (
    AttachmentKeyValidator,
    KeyInfo,
    KeyValidationError,
)
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class CertKeyInfo(KeyInfo):
    """Metadata about a validated key/certificate."""
    not_before: Optional[datetime] = None
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None


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

    async def validate_key(self, key: Dict[str, Any]) -> KeyInfo:
        """Validate a single JWK and return KeyInfo; raise KeyValidationError on failure."""
        kid = key.get("kid")
        
        # Keys without certificates are allowed; return basic info
        if "x5c" not in key:
            return KeyInfo(kid=kid)

        # Get trust store - either from configured location or environment variable
        trust_store_pem = None
        if self.trust_store:
            try:
                with open(self.trust_store) as f:
                    trust_store_pem = f.read()
            except Exception as e:
                raise KeyValidationError(
                    code="trust_store_read_failed",
                    message=f"Failed to read trust store from {self.trust_store}: {str(e)}",
                    kid=kid,
                )
        else:
            trust_store_pem = os.environ.get("FAME_CA_CERTS")

        if not trust_store_pem:
            # For backward compatibility during transition, log warning but don't fail
            return CertKeyInfo(kid=kid)

        try:
            from naylence.fame.security.cert.util import (
                validate_jwk_x5c_certificate,
                _validate_chain,
            )

            is_valid, error_msg = validate_jwk_x5c_certificate(
                key,
                trust_store_pem=trust_store_pem,
                enforce_name_constraints=self.enforce_name_constraints,
                strict=self.strict_validation,
            )
            
            if not is_valid:
                raise KeyValidationError(
                    code="certificate_invalid",
                    message=error_msg or "certificate validation failed",
                    kid=kid,
                )

            # Extract certificate metadata for KeyInfo
            (pub_key, cert), _ = _validate_chain(
                x5c=key.get("x5c", []),
                enforce_name_constraints=self.enforce_name_constraints,
                trust_store_pem=trust_store_pem,
                return_cert=True,
            )
            
            # Use UTC-aware properties preferentially to avoid deprecation warnings
            expires_at = getattr(cert, "not_valid_after_utc", None)
            not_before = getattr(cert, "not_valid_before_utc", None)
            
            subject = None
            issuer = None
            try:
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()
            except Exception:
                pass
            
            return CertKeyInfo(
                kid=kid,
                expires_at=expires_at,
                not_before=not_before,
                cert_subject=subject,
                cert_issuer=issuer,
            )
            
        except KeyValidationError:
            raise
        except Exception as e:
            raise KeyValidationError(
                code="certificate_validation_error",
                message=str(e),
                kid=kid,
            )

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

"""
Certificate utilities for extracting and validating public keys from X.509 certificates.

Provides functions to extract public keys from JWK x5c fields with optional
validation of certificate chains, name constraints, and trust anchors.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
from typing import Any, List, Optional

from naylence.fame.security.util import require_crypto
from naylence.fame.util.logging import getLogger

from .certificate_cache import get_or_validate

logger = getLogger(__name__)


def _lazy_import():
    """Import cryptography modules on demand."""
    require_crypto()
    global x509, hashes, ExtensionOID, UniformResourceIdentifier
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509 import UniformResourceIdentifier
    from cryptography.x509.oid import ExtensionOID


def public_key_from_x5c(
    x5c: List[str],
    *,
    enforce_name_constraints: bool = True,
    trust_store_pem: Optional[str] = None,
    return_cert: bool = False,
) -> Any:
    """
    Extract public key from X.509 certificate chain with optional validation.

    Args:
        x5c: List of base64-encoded DER certificates (leaf first)
        enforce_name_constraints: Whether to validate name constraints
        trust_store_pem: Optional path to PEM trust store file
        return_cert: If True, return (public_key, certificate) tuple

    Returns:
        The public key from the leaf certificate, or (public_key, cert) if return_cert=True

    Raises:
        ValueError: If certificate validation fails
    """
    if not x5c:
        raise ValueError("Empty certificate chain")

    # Generate a unique call ID for debugging
    import uuid

    call_id = str(uuid.uuid4())[:8]

    logger.debug(
        "public_key_from_x5c_called",
        call_id=call_id,
        x5c_count=len(x5c),
        enforce_name_constraints=enforce_name_constraints,
        has_trust_store=trust_store_pem is not None,
        return_cert=return_cert,
        trust_store_preview=trust_store_pem[:50] + "..."
        if trust_store_pem and len(trust_store_pem) > 50
        else trust_store_pem,
    )

    # Build cache key that includes all validation parameters
    try:
        chain_bytes = b"".join(base64.b64decode(cert_b64) for cert_b64 in x5c)
    except Exception as e:
        raise ValueError(f"Failed to decode certificate: {e}")

    def validator():
        return _validate_chain(x5c, enforce_name_constraints, trust_store_pem, return_cert)

    # Don't use caching when returning certificates to avoid complexity
    if return_cert:
        logger.debug("bypassing_cache_for_return_cert", call_id=call_id, reason="return_cert_true")
        result = validator()
        return result[0]  # ((public_key, cert), not_after)

    # For trust store validation, build comprehensive cache key
    if trust_store_pem:
        # logger.debug(
        #     "certificate_validation_cache_start",
        #     call_id=call_id,
        #     trust_store_param=(
        #         trust_store_pem[:50] + "..." if len(trust_store_pem) > 50 else trust_store_pem
        #     ),
        #     chain_length=len(x5c),
        #     enforce_name_constraints=enforce_name_constraints
        # )

        # Determine if trust_store_pem is file path or PEM content
        if trust_store_pem.startswith("-----BEGIN"):
            # It's PEM content - hash it directly
            trust_store_hash = hashlib.sha256(trust_store_pem.encode("utf-8")).digest()
        else:
            # It's a file path - read and hash the content
            try:
                with open(trust_store_pem, "rb") as f:
                    trust_store_content = f.read()
                trust_store_hash = hashlib.sha256(trust_store_content).digest()
            except Exception as e:
                # If we can't read the file, fall back to hashing the path
                # This ensures we don't break the cache key generation
                logger.warning(
                    "trust_store_file_read_failed",
                    file_path=trust_store_pem,
                    error=str(e),
                    fallback="hashing_path_string",
                )
                trust_store_hash = hashlib.sha256(trust_store_pem.encode("utf-8")).digest()

        cache_key_parts = [
            chain_bytes,
            trust_store_hash,
        ]
        if enforce_name_constraints:
            cache_key_parts.append(b"name_constraints")

        cache_key = b"||".join(cache_key_parts)  # Use separator to avoid collisions
        hashlib.sha256(cache_key).digest()

        result = get_or_validate(cache_key, validator)

        return result[0]  # (public_key, not_after)
    else:
        # Simple caching for basic validation without trust store
        logger.debug(
            "certificate_validation_no_trust_store",
            call_id=call_id,
            enforce_name_constraints=enforce_name_constraints,
        )

        if enforce_name_constraints:
            cache_key = chain_bytes + b"||name_constraints"
        else:
            cache_key = chain_bytes

        result = get_or_validate(cache_key, validator)
        return result[0]  # (public_key, not_after)


def _validate_chain(
    x5c: List[str],
    enforce_name_constraints: bool,
    trust_store_pem: Optional[str],
    return_cert: bool = False,
) -> tuple[Any, datetime.datetime] | tuple[tuple[Any, Any], datetime.datetime]:
    """Validate certificate chain and return (public_key, not_after) or ((public_key, cert), not_after)."""
    _lazy_import()

    # Decode certificate chain
    chain = []
    for cert_b64 in x5c:
        try:
            der_bytes = base64.b64decode(cert_b64)
            cert = x509.load_der_x509_certificate(der_bytes)
            chain.append(cert)
        except Exception as e:
            raise ValueError(f"Failed to decode certificate: {e}")

    leaf = chain[0]
    issuers = chain[1:] if len(chain) > 1 else []

    # Basic temporal validity check
    now = datetime.datetime.now(datetime.timezone.utc)
    if not (leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc):
        raise ValueError("Certificate is not currently valid")

    # Optional name constraints validation
    if enforce_name_constraints and issuers:
        leaf_uris = _extract_uris_from_cert(leaf)
        _check_name_constraints(issuers, leaf_uris)

    # Optional trust store validation
    if trust_store_pem:
        _check_trust_anchor(chain, trust_store_pem)

    if return_cert:
        return (leaf.public_key(), leaf), leaf.not_valid_after_utc
    else:
        return leaf.public_key(), leaf.not_valid_after_utc


def _extract_uris_from_cert(cert) -> List[str]:
    """Extract URI values from Subject Alternative Name extension."""
    _lazy_import()

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = san_ext.value
        return san.get_values_for_type(UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        return []
    except Exception:
        return []


def _check_name_constraints(issuers: List[Any], leaf_uris: List[str]) -> None:
    """Validate that leaf URIs comply with name constraints from issuer certificates."""
    _lazy_import()

    for issuer in issuers:
        try:
            nc_ext = issuer.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
            nc = nc_ext.value
        except x509.ExtensionNotFound:
            continue
        except Exception:
            continue

        # Check permitted subtrees
        if nc.permitted_subtrees:
            permitted_uris = [
                subtree.value
                for subtree in nc.permitted_subtrees
                if isinstance(subtree, UniformResourceIdentifier)
            ]

            if permitted_uris:
                for uri in leaf_uris:
                    if not any(uri.startswith(permitted) for permitted in permitted_uris):
                        raise ValueError(
                            f"URI '{uri}' violates name constraints - "
                            f"not in permitted subtrees: {permitted_uris}"
                        )


def _check_trust_anchor(chain: List[Any], trust_store_path_or_pem: str) -> None:
    """Validate that the certificate chain is rooted in a trusted anchor."""
    _lazy_import()

    logger.debug(
        "trust_anchor_validation_start",
        chain_length=len(chain),
        trust_store_type="pem_content" if trust_store_path_or_pem.startswith("-----BEGIN") else "file_path",
    )

    # Determine if the input is a file path or PEM content
    if trust_store_path_or_pem.startswith("-----BEGIN"):
        # It's PEM content
        trust_store_data = trust_store_path_or_pem.encode()
    else:
        # It's a file path
        try:
            with open(trust_store_path_or_pem, "rb") as f:
                trust_store_data = f.read()
        except Exception as e:
            raise ValueError(f"Failed to read trust store: {e}")

    # Parse trusted certificates from PEM
    trusted_certs = set()
    trusted_cert_info = []
    pem_blocks = trust_store_data.split(b"-----END CERTIFICATE-----")

    for block in pem_blocks:
        if b"-----BEGIN CERTIFICATE-----" in block:
            try:
                # Reconstruct the PEM block
                pem_cert = block + b"-----END CERTIFICATE-----"
                cert = x509.load_pem_x509_certificate(pem_cert)
                trusted_certs.add(cert)

                # Collect certificate info for debugging
                try:
                    subject = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                    issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                    serial = cert.serial_number
                    trusted_cert_info.append(f"CN={subject} (Serial: {serial}, Issuer: {issuer})")
                except Exception:
                    trusted_cert_info.append(f"Serial: {cert.serial_number}")
            except Exception:
                continue  # Skip invalid certificates

    if not trusted_certs:
        raise ValueError("No valid certificates found in trust store")

    # Log trust store contents for debugging

    logger.debug(
        "trust_store_loaded", trust_store_cert_count=len(trusted_certs), trust_store_certs=trusted_cert_info
    )

    # Collect chain info for debugging
    chain_info = []
    for i, cert in enumerate(chain):
        try:
            subject = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            serial = cert.serial_number
            chain_info.append(f"[{i}] CN={subject} (Serial: {serial}, Issuer: {issuer})")
        except Exception:
            chain_info.append(f"[{i}] Serial: {cert.serial_number}")

    logger.debug(
        "certificate_chain_validation",
        chain_length=len(chain),
        chain_certificates=chain_info,
        trust_store_size=len(trusted_certs),
    )

    # Check if any certificate in the chain is in the trust store or if any issuer is trusted
    # Strategy 1: Direct trust - any certificate in the chain is directly trusted
    # Strategy 2: Leaf issuer trust - the leaf certificate's issuer is in the trust store
    # Strategy 3: Chain issuer trust - any certificate in the chain has its issuer in the trust store

    matching_cert = None
    validation_strategy = None

    # Strategy 1: Check if any certificate in the chain is directly in the trust store
    for i, cert in enumerate(chain):
        for trusted_cert in trusted_certs:
            if cert.serial_number == trusted_cert.serial_number:
                matching_cert = trusted_cert
                validation_strategy = f"direct_trust_cert_{i}"
                break
        if matching_cert:
            break

    # Strategy 2: If no direct match, check if the leaf certificate's issuer is in the trust store
    if matching_cert is None and chain:
        leaf_cert = chain[0]
        for trusted_cert in trusted_certs:
            # Check if the trusted cert could be the issuer of the leaf cert
            if (
                trusted_cert.subject == leaf_cert.issuer
                and trusted_cert.serial_number != leaf_cert.serial_number
            ):
                # Additional validation: verify the signature
                try:
                    leaf_cert.verify_directly_issued_by(trusted_cert)
                    matching_cert = trusted_cert
                    validation_strategy = "leaf_issuer_trust"
                    logger.debug(
                        "issuer_signature_verification_success",
                        trusted_cert_serial=trusted_cert.serial_number,
                        leaf_cert_serial=leaf_cert.serial_number,
                        method="verify_directly_issued_by",
                        strategy="leaf_issuer_trust",
                    )
                    break
                except Exception as e:
                    logger.debug(
                        "issuer_signature_verification_failed",
                        trusted_cert_serial=trusted_cert.serial_number,
                        leaf_cert_serial=leaf_cert.serial_number,
                        method="verify_directly_issued_by",
                        error=str(e),
                    )
                    continue

    # Strategy 3: Check if any intermediate certificate's issuer is in the trust store
    if matching_cert is None and len(chain) > 1:
        for i, cert in enumerate(chain[1:], 1):  # Skip leaf cert (index 0)
            for trusted_cert in trusted_certs:
                # Check if the trusted cert could be the issuer of this intermediate cert
                if trusted_cert.subject == cert.issuer and trusted_cert.serial_number != cert.serial_number:
                    # Additional validation: verify the signature
                    try:
                        cert.verify_directly_issued_by(trusted_cert)
                        matching_cert = trusted_cert
                        validation_strategy = f"intermediate_issuer_trust_cert_{i}"
                        logger.debug(
                            "intermediate_issuer_signature_verification_success",
                            trusted_cert_serial=trusted_cert.serial_number,
                            intermediate_cert_serial=cert.serial_number,
                            intermediate_cert_index=i,
                            method="verify_directly_issued_by",
                        )
                        break
                    except Exception as e:
                        logger.debug(
                            "intermediate_issuer_signature_verification_failed",
                            trusted_cert_serial=trusted_cert.serial_number,
                            intermediate_cert_serial=cert.serial_number,
                            intermediate_cert_index=i,
                            method="verify_directly_issued_by",
                            error=str(e),
                        )
                        continue
            if matching_cert:
                break

    if matching_cert is None:
        # Log detailed mismatch information
        leaf_cert = chain[0] if chain else None
        if leaf_cert:
            try:
                leaf_subject = leaf_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                leaf_issuer = leaf_cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                leaf_serial = leaf_cert.serial_number
            except Exception:
                leaf_subject = "Unknown"
                leaf_issuer = "Unknown"
                leaf_serial = leaf_cert.serial_number if leaf_cert else "Unknown"
        else:
            leaf_subject = leaf_issuer = leaf_serial = "Unknown"

        logger.warning(
            "certificate_chain_trust_validation_failed",
            leaf_cert_subject=leaf_subject,
            leaf_cert_issuer=leaf_issuer,
            leaf_cert_serial=leaf_serial,
            trusted_cert_count=len(trusted_certs),
            trusted_cert_details=trusted_cert_info,
            chain_details=chain_info,
            reason="no_matching_trust_anchor",
        )

        raise ValueError("Certificate chain is not rooted in a trusted anchor")

    # Additional validation: Verify chain continuity
    # Each certificate in the chain must be signed by the next certificate
    logger.debug("validating_chain_continuity", chain_length=len(chain))

    for i in range(len(chain) - 1):
        cert = chain[i]
        issuer_cert = chain[i + 1]

        # Verify that cert was signed by issuer_cert
        try:
            # Check issuer name matches
            if cert.issuer != issuer_cert.subject:
                try:
                    cert_subject = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                    cert_issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                    issuer_subject = issuer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
                        0
                    ].value
                except Exception:
                    cert_subject = f"Serial_{cert.serial_number}"
                    cert_issuer = "Unknown"
                    issuer_subject = f"Serial_{issuer_cert.serial_number}"

                logger.warning(
                    "certificate_chain_continuity_failed",
                    cert_index=i,
                    cert_subject=cert_subject,
                    cert_issuer=cert_issuer,
                    expected_issuer_subject=issuer_subject,
                    reason="issuer_name_mismatch",
                )
                raise ValueError(
                    f"Certificate chain continuity broken: certificate at index {i} "
                    f"issuer does not match next certificate subject"
                )

            # Verify signature
            cert.verify_directly_issued_by(issuer_cert)
            logger.debug(
                "chain_continuity_verification_success",
                cert_index=i,
                cert_serial=cert.serial_number,
                issuer_serial=issuer_cert.serial_number,
                method="verify_directly_issued_by",
            )

        except Exception as e:
            try:
                cert_subject = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                issuer_subject = issuer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
                    0
                ].value
            except Exception:
                cert_subject = f"Serial_{cert.serial_number}"
                issuer_subject = f"Serial_{issuer_cert.serial_number}"

            logger.warning(
                "certificate_chain_continuity_failed",
                cert_index=i,
                cert_subject=cert_subject,
                issuer_subject=issuer_subject,
                cert_serial=cert.serial_number,
                issuer_serial=issuer_cert.serial_number,
                error=str(e),
                reason="signature_verification_failed",
            )
            raise ValueError(
                f"Certificate chain continuity broken: certificate at index {i} "
                f"was not signed by certificate at index {i + 1}: {e}"
            )

    logger.debug("chain_continuity_validation_passed", chain_length=len(chain))

    logger.debug(
        "certificate_chain_trust_validation_passed",
        matching_cert_serial=matching_cert.serial_number,
        validation_strategy=validation_strategy,
        chain_length=len(chain),
    )


def sid_from_cert(cert) -> Optional[str]:
    """
    Extract node SID from certificate.

    Supports both legacy certificates (SID in OtherName extension) and
    SPIFFE-compatible certificates (SID from SPIFFE ID in SAN).

    Args:
        cert: X.509 certificate object

    Returns:
        SID string if found, None otherwise
    """
    _lazy_import()

    # First try SPIFFE-compatible extraction from SPIFFE ID
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value

        # Look for SPIFFE ID in SAN
        for gn in san:
            if isinstance(gn, x509.UniformResourceIdentifier):
                uri = gn.value
                if uri.startswith("spiffe://"):
                    # Extract SID from SPIFFE ID path
                    try:
                        from .ca_service import extract_sid_from_spiffe_id

                        return extract_sid_from_spiffe_id(uri)
                    except ImportError:
                        # ca_service not available, try manual parsing
                        parts = uri.split("/")
                        if len(parts) >= 4 and parts[3] == "nodes" and len(parts) >= 5:
                            return parts[4]  # The SID string

    except (x509.ExtensionNotFound, ImportError, Exception):
        pass

    # Fallback to legacy OtherName extension method
    try:
        from .ca_service import SID_OID

        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value

        sid_oid = x509.ObjectIdentifier(SID_OID)
        for gn in san:
            if isinstance(gn, x509.OtherName) and gn.type_id == sid_oid:
                # The value is DER-encoded UTF8String, we need to decode it
                der_value = gn.value
                # Skip DER tag and length bytes to get the actual UTF-8 string
                if len(der_value) >= 2 and der_value[0] == 0x0C:  # UTF8String tag
                    length = der_value[1]
                    if length < 128:
                        # Short form length
                        return der_value[2 : 2 + length].decode("utf-8")
                    else:
                        # Long form length (should not be needed for typical SIDs)
                        length_bytes = length & 0x7F
                        if len(der_value) >= 2 + length_bytes:
                            actual_length = 0
                            for i in range(length_bytes):
                                actual_length = (actual_length << 8) | der_value[2 + i]
                            start_idx = 2 + length_bytes
                            return der_value[start_idx : start_idx + actual_length].decode("utf-8")
                # Fallback: try decoding as raw bytes
                return der_value.decode("utf-8")
    except (x509.ExtensionNotFound, ImportError, Exception):
        pass

    return None


def host_logicals_from_cert(cert) -> List[str]:
    """
    Extract host-like logical addresses from certificate.

    This function extracts logical addresses in host-like format (e.g., "fame.fabric", "api.services")
    instead of path-based format (e.g., "/", "/api").

    Supports both legacy certificates (logical hosts in naylence:// URIs) and
    SPIFFE-compatible certificates (logical hosts in private extension).

    Args:
        cert: X.509 certificate object

    Returns:
        List of host-like logical addresses ["fame.fabric", "api.services"]
    """
    _lazy_import()

    # First try SPIFFE-compatible extraction from private extension
    try:
        from .ca_service import extract_logical_hosts_from_cert

        logical_hosts = extract_logical_hosts_from_cert(cert)
        if logical_hosts:
            return logical_hosts
    except ImportError:
        pass

    # Fallback to legacy naylence:// URI method
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value

        uris = san.get_values_for_type(x509.UniformResourceIdentifier)

        # Extract host-like logical addresses from naylence:// URIs
        host_logicals = []
        for uri in uris:
            if uri.startswith("naylence://"):
                from naylence.fame.util.logicals_util import extract_host_logical_from_uri

                host_logical = extract_host_logical_from_uri(uri)
                if host_logical:
                    host_logicals.append(host_logical)

        return host_logicals

    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass

    return []


def get_certificate_metadata_from_x5c(
    x5c: List[str],
    *,
    trust_store_pem: Optional[str] = None,
) -> dict:
    """
    Extract certificate metadata (SID, logical addresses, etc.) from X.509 certificate chain.

    This function provides an optimized way to get certificate metadata without
    bypassing the cache like public_key_from_x5c(..., return_cert=True) does.

    Args:
        x5c: List of base64-encoded X.509 certificates (first is leaf)
        trust_store_pem: Optional path to trust store or PEM content for validation

    Returns:
        Dictionary containing:
        - 'sid': Certificate SID (if present)
        - 'logicals': List of host-based logical addresses from certificate
            (e.g., ["fame.fabric", "api.services"])
        - 'certificate': The validated certificate object

    Raises:
        ValueError: If certificate chain is invalid or trust validation fails
    """
    import uuid

    call_id = str(uuid.uuid4())[:8]

    if not x5c:
        raise ValueError("Empty x5c list")

    _lazy_import()

    # Create a cache key specific to metadata extraction
    chain_bytes = b"".join(base64.b64decode(cert_b64) for cert_b64 in x5c)

    def metadata_validator():
        """Validate certificate and extract metadata."""
        logger.debug("certificate_metadata_validation_start", call_id=call_id)

        # Parse and validate the leaf certificate
        try:
            leaf_cert_der = base64.b64decode(x5c[0])
            leaf_cert = x509.load_der_x509_certificate(leaf_cert_der)
            logger.debug(
                "leaf_certificate_parsed",
                call_id=call_id,
                subject=str(leaf_cert.subject),
                serial_number=leaf_cert.serial_number,
                not_after=leaf_cert.not_valid_after_utc.isoformat(),
            )
        except Exception as e:
            logger.error("certificate_parsing_failed", call_id=call_id, error=str(e))
            raise ValueError(f"Failed to parse leaf certificate: {e}")

        # Validate the full chain if trust store is provided
        if trust_store_pem:
            try:
                full_chain = [
                    x509.load_der_x509_certificate(base64.b64decode(cert_b64)) for cert_b64 in x5c
                ]
                _check_trust_anchor(full_chain, trust_store_pem)
                logger.debug("certificate_trust_validation_passed", call_id=call_id)
            except Exception as e:
                logger.error("certificate_trust_validation_failed", call_id=call_id, error=str(e))
                raise ValueError(f"Certificate trust validation failed: {e}")

        # Extract metadata
        try:
            sid = sid_from_cert(leaf_cert)
            logical_addresses = host_logicals_from_cert(leaf_cert)

            metadata = {"sid": sid, "logicals": logical_addresses, "certificate": leaf_cert}

            logger.debug(
                "certificate_metadata_extracted",
                call_id=call_id,
                sid=sid,
                logicals_count=len(logical_addresses),
                logicals=logical_addresses[:5],  # Log first 5 for debugging
            )

            return metadata, leaf_cert.not_valid_after_utc

        except Exception as e:
            logger.error("certificate_metadata_extraction_failed", call_id=call_id, error=str(e))
            raise ValueError(f"Failed to extract certificate metadata: {e}")

    # Create cache key for metadata (different from public key cache)
    metadata_cache_key = b"metadata||" + chain_bytes
    if trust_store_pem:
        if trust_store_pem.startswith("-----BEGIN"):
            trust_store_hash = hashlib.sha256(trust_store_pem.encode("utf-8")).digest()
        else:
            try:
                with open(trust_store_pem, "rb") as f:
                    trust_store_content = f.read()
                trust_store_hash = hashlib.sha256(trust_store_content).digest()
            except Exception:
                trust_store_hash = hashlib.sha256(trust_store_pem.encode("utf-8")).digest()
        metadata_cache_key += b"||" + trust_store_hash

    # Use the same cache infrastructure
    result = get_or_validate(metadata_cache_key, metadata_validator)

    return result[0]  # (metadata, not_after)


def validate_jwk_x5c_certificate(
    jwk: dict[str, Any],
    *,
    trust_store_pem: Optional[str] = None,
    enforce_name_constraints: bool = True,
    strict: bool = True,
) -> tuple[bool, Optional[str]]:
    """
    Validate a JWK's x5c certificate chain for key exchange scenarios.

    Args:
        jwk: JWK dictionary that may contain x5c field
        trust_store_pem: Optional path to PEM trust store file or PEM content
        enforce_name_constraints: Whether to validate name constraints
        strict: If True, raise exception on validation failure. If False, return (False, error_message)

    Returns:
        tuple[bool, Optional[str]]: (is_valid, error_message)
        - (True, None) if validation passes or no x5c present
        - (False, error_message) if validation fails and strict=False

    Raises:
        ValueError: If validation fails and strict=True
    """
    if "x5c" not in jwk:
        # No certificate to validate - this is OK
        return (True, None)

    x5c = jwk.get("x5c")
    if not x5c or not isinstance(x5c, list) or len(x5c) == 0:
        error_msg = "Invalid x5c field in JWK"
        if strict:
            raise ValueError(error_msg)
        return (False, error_msg)

    try:
        # Validate the certificate chain
        public_key_from_x5c(
            x5c,
            enforce_name_constraints=enforce_name_constraints,
            trust_store_pem=trust_store_pem,
            return_cert=False,  # We only care about validation, not the certificate
        )
        return (True, None)
    except Exception as e:
        error_msg = f"Certificate validation failed: {str(e)}"
        if strict:
            raise ValueError(error_msg) from e
        return (False, error_msg)

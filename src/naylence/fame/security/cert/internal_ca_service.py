"""
Certificate Authority signing service for node certificates.

Provides both in-process API and optional HTTP server for issuing
certificates with node physical and host-like logical address information.
"""

from __future__ import annotations

import datetime
from typing import List, Optional, Union

from cryptography import x509

from naylence.fame.security.util import require_crypto

# Certificate extension OIDs (using placeholder PEN)
SID_OID = "1.3.6.1.4.1.58530.1"
LOGICALS_OID = "1.3.6.1.4.1.58530.2"
NODE_ID_OID = "1.3.6.1.4.1.58530.4"


class CASigningService:
    """In-process certificate signing service."""

    def __init__(
        self,
        root_cert_pem: str,
        root_key_pem: str,
        intermediate_cert_pem: Optional[str] = None,
        intermediate_key_pem: Optional[str] = None,
    ):
        """
        Initialize CA service with root and optional intermediate certificates.

        Args:
            root_cert_pem: Root CA certificate in PEM format
            root_key_pem: Root CA private key in PEM format
            intermediate_cert_pem: Optional intermediate CA certificate
            intermediate_key_pem: Optional intermediate CA private key
        """
        require_crypto()
        self._lazy_import()

        # Load root CA materials
        self._root_cert = self._x509.load_pem_x509_certificate(root_cert_pem.encode())
        self._root_key = self._serialization.load_pem_private_key(root_key_pem.encode(), password=None)

        # Load intermediate CA materials if provided
        if intermediate_cert_pem and intermediate_key_pem:
            self._signing_cert = self._x509.load_pem_x509_certificate(intermediate_cert_pem.encode())
            self._signing_key = self._serialization.load_pem_private_key(
                intermediate_key_pem.encode(), password=None
            )
        else:
            # Use root for signing if no intermediate
            self._signing_cert = self._root_cert
            self._signing_key = self._root_key

    def _lazy_import(self):
        """Import cryptography modules on demand."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x25519
        from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

        self._x509 = x509
        self._hashes = hashes
        self._serialization = serialization
        self._ExtensionOID = ExtensionOID
        self._NameOID = NameOID
        self._ExtendedKeyUsageOID = ExtendedKeyUsageOID
        self._dsa = dsa
        self._rsa = rsa
        self._ec = ec
        self._ed25519 = ed25519
        self._ed448 = ed448
        self._x25519 = x25519

    def sign_node_cert(
        self,
        public_key_pem: str,
        node_id: str,
        node_sid: str,
        physical_path: str,
        logicals: List[str],
        ttl_days: int = 365,
        spiffe_trust_domain: str = "naylence.fame",
    ) -> str:
        """
        Sign a SPIFFE-compatible node certificate with SID-based identity.

        Args:
            public_key_pem: Node's public key in PEM format
            node_id: Unique identifier for the node (stored in extension for troubleshooting)
            node_sid: Node's pre-computed SID (base62-encoded, from secure_digest(physical_path))
            physical_path: Physical path - used only for SID verification, NOT stored in cert
            logicals: List of host-like logical addresses this node can serve
                (e.g., ["api.services", "fame.fabric"])
            ttl_days: Certificate validity period in days
            spiffe_trust_domain: SPIFFE trust domain for the SPIFFE ID

        Returns:
            PEM-encoded signed certificate
        """
        import json

        # Load the public key
        public_key = self._serialization.load_pem_public_key(public_key_pem.encode())
        public_key = self._validate_certificate_public_key(public_key)

        # Verify that the provided SID matches the computed one (security check)
        from naylence.fame.util.util import secure_digest

        computed_sid = secure_digest(physical_path)
        if node_sid != computed_sid:
            raise ValueError(
                f"Provided SID {node_sid} does not match computed SID {computed_sid} for physical path"
            )

        # SPIFFE requires empty subject
        subject = self._x509.Name([])

        # SPIFFE ID using base62 SID as the path component (consistent with node.sid)
        spiffe_id = f"spiffe://{spiffe_trust_domain}/nodes/{node_sid}"
        san = self._x509.SubjectAlternativeName([self._x509.UniformResourceIdentifier(spiffe_id)])

        # Validate logical addresses
        from naylence.fame.util.logicals_util import validate_host_logicals

        logicals_valid, logical_error = validate_host_logicals(logicals)
        if not logicals_valid:
            raise ValueError(f"Invalid logical address format: {logical_error}")

        # Build certificate
        now = datetime.datetime.now(datetime.timezone.utc)
        cert_builder = (
            self._x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._signing_cert.subject)
            .public_key(public_key)
            .serial_number(self._x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=ttl_days))
            .add_extension(san, critical=False)
            .add_extension(
                self._x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                self._x509.ExtendedKeyUsage(
                    [
                        self._ExtendedKeyUsageOID.CLIENT_AUTH,
                        self._ExtendedKeyUsageOID.SERVER_AUTH,
                    ]
                ),
                critical=True,
            )
        )

        # Add SID extension (opaque SID string as bytes) - no physical path derivation exposed
        cert_builder = cert_builder.add_extension(
            self._x509.UnrecognizedExtension(
                self._x509.ObjectIdentifier(SID_OID),
                node_sid.encode("utf-8"),  # Store SID string as bytes, completely opaque
            ),
            critical=False,
        )

        # Add node ID extension (for troubleshooting only)
        cert_builder = cert_builder.add_extension(
            self._x509.UnrecognizedExtension(
                self._x509.ObjectIdentifier(NODE_ID_OID),
                node_id.encode("utf-8"),
            ),
            critical=False,
        )

        # Add logical hosts extension
        if logicals:
            logicals_json = json.dumps(logicals).encode("utf-8")
            cert_builder = cert_builder.add_extension(
                self._x509.UnrecognizedExtension(
                    self._x509.ObjectIdentifier(LOGICALS_OID),
                    logicals_json,
                ),
                critical=False,
            )

        # Sign the certificate
        cert = cert_builder.sign(self._signing_key, None)  # type: ignore

        # Return PEM-encoded certificate
        return cert.public_bytes(self._serialization.Encoding.PEM).decode()

    def create_intermediate_ca(
        self,
        public_key_pem: str,
        ca_name: str,
        permitted_paths: List[str],
        ttl_days: int = 1825,  # 5 years default
    ) -> str:
        """
        Create an intermediate CA with DNS name constraints for OpenSSL compatibility.

        Args:
            public_key_pem: Intermediate CA's public key in PEM format
            ca_name: Name for the intermediate CA
            permitted_paths: List of logical prefixes this CA can issue for
            ttl_days: Certificate validity period in days

        Returns:
            PEM-encoded intermediate CA certificate
        """
        public_key = self._serialization.load_pem_public_key(public_key_pem.encode())
        public_key = self._validate_certificate_public_key(public_key)

        subject = self._x509.Name(
            [
                self._x509.NameAttribute(self._NameOID.COMMON_NAME, ca_name),
                self._x509.NameAttribute(self._NameOID.ORGANIZATIONAL_UNIT_NAME, "Fame Intermediate CAs"),
            ]
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        cert_builder = (
            self._x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._root_cert.subject)
            .public_key(public_key)
            .serial_number(self._x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=ttl_days))
        )

        # Add DNS name constraints if permitted paths are specified (OpenSSL compatible)
        if permitted_paths:
            from naylence.fame.util.logging import getLogger
            from naylence.fame.util.logicals_util import get_fame_root

            logger = getLogger(__name__)

            # For OpenSSL compatibility, we use DNS name constraints
            # Use the configurable FAME_ROOT as the base domain
            fame_root = get_fame_root()

            permitted_subtrees = [
                self._x509.DNSName(fame_root)  # This allows all subdomains of the FAME_ROOT
            ]

            name_constraints = self._x509.NameConstraints(
                permitted_subtrees=permitted_subtrees,
                excluded_subtrees=None,
            )
            cert_builder = cert_builder.add_extension(name_constraints, critical=True)

            logger.debug(
                "created_intermediate_ca_with_dns_name_constraints",
                ca_name=ca_name,
                permitted_paths=permitted_paths,
                dns_constraint=fame_root,
                fame_root=fame_root,
                openssl_compatible=True,
            )

        cert_builder = cert_builder.add_extension(
            self._x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).add_extension(
            self._x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # Sign with root CA
        cert = cert_builder.sign(self._root_key, None)  # type: ignore

        return cert.public_bytes(self._serialization.Encoding.PEM).decode()

    def _validate_certificate_public_key(self, public_key):
        """
        Validate that the public key is suitable for X.509 certificates.

        Args:
            public_key: The public key to validate

        Returns:
            The public key, properly typed for certificate use

        Raises:
            ValueError: If the key type is not supported for certificates
        """
        # Check if it's a supported certificate key type
        if isinstance(
            public_key,
            (
                self._dsa.DSAPublicKey
                | self._rsa.RSAPublicKey
                | self._ec.EllipticCurvePublicKey
                | self._ed25519.Ed25519PublicKey
                | self._ed448.Ed448PublicKey
                | self._x25519.X25519PublicKey
            ),
        ):
            return public_key
        else:
            # Extract the actual type name for the error
            key_type = type(public_key).__name__
            raise ValueError(
                f"Public key type {key_type} is not supported for X.509 certificates. "
                f"Supported types: RSA, DSA, ECDSA, Ed25519, Ed448, X25519"
            )


def create_test_ca() -> tuple[str, str]:
    """
    Create a test root CA for development/testing.

    Returns:
        Tuple of (root_cert_pem, root_key_pem)
    """
    require_crypto()
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    # Generate root CA key
    root_key = ed25519.Ed25519PrivateKey.generate()

    # Create root CA certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Fame Test Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Naylence Fame"),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=7300))  # 20 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(root_key, None)
    )

    # Convert to PEM
    root_cert_pem = root_cert.public_bytes(serialization.Encoding.PEM).decode()
    root_key_pem = root_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    return root_cert_pem, root_key_pem


def extract_spiffe_id_from_cert(cert_pem: str) -> Optional[str]:
    """
    Extract SPIFFE ID from certificate SAN.

    Args:
        cert_pem: Certificate in PEM format

    Returns:
        SPIFFE ID string or None if not found
    """
    require_crypto()
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        # Type check to ensure we have a SubjectAlternativeName extension
        if isinstance(san_ext.value, x509.SubjectAlternativeName):
            for name in san_ext.value:
                if isinstance(name, x509.UniformResourceIdentifier):
                    uri = name.value
                    if uri.startswith("spiffe://"):
                        return uri
    except x509.ExtensionNotFound:
        pass

    return None


def extract_sid_from_cert(cert_input: Union[str, x509.Certificate]) -> Optional[bytes]:
    """
    Extract raw SID bytes from certificate extension.

    Args:
        cert_input: Either a PEM string or a cryptography.x509.Certificate object

    Returns:
        SID bytes or None if not found
    """
    require_crypto()
    from cryptography import x509

    # Handle both PEM string and certificate object
    if isinstance(cert_input, str):
        cert = x509.load_pem_x509_certificate(cert_input.encode())
    else:
        # Assume it's already a certificate object
        cert = cert_input

    try:
        ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(SID_OID))
        # For UnrecognizedExtension, the actual bytes are in ext.value.value
        if isinstance(ext.value, x509.UnrecognizedExtension):
            return ext.value.value  # type: ignore
        return None
    except x509.ExtensionNotFound:
        return None


def extract_node_id_from_cert(cert_input: Union[str, x509.Certificate]) -> Optional[str]:
    """
    Extract node ID from certificate extension.

    Args:
        cert_input: Either a PEM string or a cryptography.x509.Certificate object

    Returns:
        Node ID string or None if not found
    """
    require_crypto()
    from cryptography import x509

    # Handle both PEM string and certificate object
    if isinstance(cert_input, str):
        cert = x509.load_pem_x509_certificate(cert_input.encode())
    else:
        # Assume it's already a certificate object
        cert = cert_input

    try:
        ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(NODE_ID_OID))
        # For UnrecognizedExtension, the actual bytes are in ext.value.value
        if isinstance(ext.value, x509.UnrecognizedExtension):
            return ext.value.value.decode("utf-8")  # type: ignore
        return None
    except x509.ExtensionNotFound:
        return None


def extract_logical_hosts_from_cert(cert_input: Union[str, x509.Certificate]) -> List[str]:
    """
    Extract logical hosts from certificate private extension.

    Args:
        cert_input: Either a PEM string or a cryptography.x509.Certificate object

    Returns:
        List of logical host addresses, empty if none found
    """
    import json

    require_crypto()
    from cryptography import x509

    # Handle both PEM string and certificate object
    if isinstance(cert_input, str):
        cert = x509.load_pem_x509_certificate(cert_input.encode())
    else:
        # Assume it's already a certificate object
        cert = cert_input

    try:
        ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(LOGICALS_OID))
        # For UnrecognizedExtension, the actual bytes are in ext.value.value
        if isinstance(ext.value, x509.UnrecognizedExtension):
            return json.loads(ext.value.value.decode("utf-8"))  # type: ignore
        return []
    except x509.ExtensionNotFound:
        return []


def extract_sid_from_spiffe_id(spiffe_id: str) -> Optional[str]:
    """
    Extract the SID string from a SPIFFE ID.

    Args:
        spiffe_id: SPIFFE ID in format spiffe://trust-domain/nodes/<sid>

    Returns:
        SID string (base62-encoded) or None if not a valid node SPIFFE ID
    """
    if not spiffe_id.startswith("spiffe://"):
        return None

    # Parse spiffe://trust-domain/nodes/<sid>
    parts = spiffe_id.split("/")
    if len(parts) >= 4 and parts[3] == "nodes" and len(parts) >= 5:
        return parts[4]  # The SID string (base62-encoded)

    return None


def verify_cert_sid_integrity(cert_pem: str, physical_path: str) -> bool:
    """
    Verify that the SID in the certificate matches the expected physical path.
    Note: This requires knowing the physical path, which should only be available
    server-side for verification purposes.

    Args:
        cert_pem: Certificate in PEM format
        physical_path: The expected physical path to verify against

    Returns:
        True if SID matches computed hash of physical path, False otherwise
    """
    sid_bytes = extract_sid_from_cert(cert_pem)
    if sid_bytes is None:
        return False

    # Decode the SID from the certificate
    try:
        cert_sid = sid_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return False

    # Compute expected SID from physical path and compare
    from naylence.fame.util.util import secure_digest

    expected_sid = secure_digest(physical_path)
    return cert_sid == expected_sid

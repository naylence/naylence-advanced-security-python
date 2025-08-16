"""Tests for real cryptographic operations without mocking."""

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from naylence.fame.core.protocol.envelope import FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame, KeyRequestFrame
from naylence.fame.security.crypto.key_factories.ed25519_key_factory import create_ed25519_keypair
from naylence.fame.security.crypto.key_factories.rsa_key_factory import create_rsa_keypair
from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider
from naylence.fame.security.keys.key_provider import get_key_provider
from naylence.fame.security.keys.key_store import get_key_store
from naylence.fame.security.signing.eddsa_envelope_signer import EdDSAEnvelopeSigner
from naylence.fame.security.signing.eddsa_envelope_verifier import EdDSAEnvelopeVerifier
from naylence.fame.util.util import secure_digest


class TestRealCryptoOperations:
    """Test real cryptographic operations end-to-end."""

    def test_rsa_key_generation_and_usage(self):
        """Test real RSA key generation and JWKS creation."""
        # Generate real RSA keys
        rsa_keypair = create_rsa_keypair(kid="test-rsa")

        assert rsa_keypair is not None
        assert hasattr(rsa_keypair, "private_pem")
        assert hasattr(rsa_keypair, "public_pem")
        assert hasattr(rsa_keypair, "jwks")

        # Verify JWKS structure
        jwks = rsa_keypair.jwks
        assert "keys" in jwks
        assert len(jwks["keys"]) > 0

        key = jwks["keys"][0]
        assert key["kty"] == "RSA"
        assert key["kid"] == "test-rsa"
        assert "n" in key  # RSA modulus
        assert "e" in key  # RSA exponent

        # Test that we can load the private key
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        private_key = load_pem_private_key(rsa_keypair.private_pem.encode(), password=None)
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert private_key.key_size == 2048

    def test_ed25519_key_generation_and_usage(self):
        """Test real Ed25519 key generation and JWKS creation."""
        # Generate real Ed25519 keys
        ed25519_keypair = create_ed25519_keypair(kid="test-ed25519")

        assert ed25519_keypair is not None
        assert hasattr(ed25519_keypair, "private_pem")
        assert hasattr(ed25519_keypair, "public_pem")
        assert hasattr(ed25519_keypair, "jwks")

        # Verify JWKS structure
        jwks = ed25519_keypair.jwks
        assert "keys" in jwks
        assert len(jwks["keys"]) > 0

        key = jwks["keys"][0]
        assert key["kty"] == "OKP"
        assert key["crv"] == "Ed25519"
        assert key["kid"] == "test-ed25519"
        assert "x" in key  # Public key
        # Note: 'd' (private key) is not included in public JWKS for security

        # Test that we can load the private key
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        private_key = load_pem_private_key(ed25519_keypair.private_pem.encode(), password=None)
        assert isinstance(private_key, ed25519.Ed25519PrivateKey)

    @pytest.mark.asyncio
    async def test_ed25519_signing_and_verification_end_to_end(self):
        """Test complete Ed25519 signing and verification workflow."""
        # Create real Ed25519 keys
        ed25519_keypair = create_ed25519_keypair(kid="test-signer")

        # Setup key store and provider
        key_store = get_key_store()
        key_store._keys.clear()

        # Add the key to the store
        jwk = ed25519_keypair.jwks["keys"][0]
        physical_path = "/test_node"
        sid = secure_digest(physical_path)
        jwk["sid"] = sid
        jwk["physical_path"] = physical_path
        await key_store.add_key(jwk["kid"], jwk)

        # Create crypto provider with the generated keys
        crypto_provider = DefaultCryptoProvider(
            signature_private_pem=ed25519_keypair.private_pem,
            signature_public_pem=ed25519_keypair.public_pem,
            signature_key_id=jwk["kid"],
        )

        # Create signer and verifier
        signer = EdDSAEnvelopeSigner(crypto=crypto_provider)
        key_provider = get_key_provider()
        verifier = EdDSAEnvelopeVerifier(key_provider=key_provider)

        # Create test data
        test_data = {"message": "Hello, cryptographic world!", "number": 42}
        frame = DataFrame(payload=test_data, codec="json")
        envelope = FameEnvelope(frame=frame, sid=sid)

        # Sign the envelope
        signed_envelope = signer.sign_envelope(envelope, physical_path=physical_path)

        # Verify the signature was added
        assert signed_envelope.sec is not None
        assert signed_envelope.sec.sig is not None
        assert signed_envelope.sec.sig.kid == jwk["kid"]
        # Note: alg field may not be set by default in some implementations

        # Verify the signature
        verification_result = await verifier.verify_envelope(signed_envelope)
        assert verification_result is True

    def test_cross_crypto_key_interoperability(self):
        """Test that different crypto providers can work with the same keys."""
        # Generate keys
        ed25519_keypair = create_ed25519_keypair(kid="interop-test")

        # Create two different crypto providers with the same keys
        provider1 = DefaultCryptoProvider(
            signature_private_pem=ed25519_keypair.private_pem,
            signature_public_pem=ed25519_keypair.public_pem,
            signature_key_id="interop-test",
        )

        provider2 = DefaultCryptoProvider(
            signature_private_pem=ed25519_keypair.private_pem,
            signature_public_pem=ed25519_keypair.public_pem,
            signature_key_id="interop-test",
        )

        # Both should produce the same JWKS
        jwks1 = provider1.get_jwks()
        jwks2 = provider2.get_jwks()

        # Keys should be identical
        key1 = jwks1["keys"][0]
        key2 = jwks2["keys"][0]

        assert key1["kid"] == key2["kid"]
        assert key1["kty"] == key2["kty"]
        assert key1["crv"] == key2["crv"]
        assert key1["x"] == key2["x"]  # Public key should match

    def test_multiple_key_types_coexistence(self):
        """Test that RSA and EdDSA keys can coexist in the same system."""
        # Generate both types of keys
        rsa_keypair = create_rsa_keypair(kid="rsa-key")
        ed25519_keypair = create_ed25519_keypair(kid="ed25519-key")

        # Setup key store
        key_store = get_key_store()
        key_store._keys.clear()

        # Add both keys to the store
        rsa_jwk = rsa_keypair.jwks["keys"][0]
        ed25519_jwk = ed25519_keypair.jwks["keys"][0]

        key_store._keys["rsa-key"] = rsa_jwk
        key_store._keys["ed25519-key"] = ed25519_jwk

        # Verify both keys are stored and retrievable
        stored_rsa = key_store._keys["rsa-key"]
        stored_ed25519 = key_store._keys["ed25519-key"]

        assert stored_rsa is not None
        assert stored_ed25519 is not None
        assert stored_rsa["kty"] == "RSA"
        assert stored_ed25519["kty"] == "OKP"
        assert stored_ed25519["crv"] == "Ed25519"

    def test_envelope_signing_with_real_keys(self):
        """Test envelope signing using real generated keys."""
        # Generate real keys
        ed25519_keypair = create_ed25519_keypair(kid="envelope-test")

        # Create crypto provider
        crypto_provider = DefaultCryptoProvider(
            signature_private_pem=ed25519_keypair.private_pem,
            signature_public_pem=ed25519_keypair.public_pem,
            signature_key_id="envelope-test",
        )

        # Create signer
        signer = EdDSAEnvelopeSigner(crypto=crypto_provider)

        # Test different frame types
        frames_to_test = [
            DataFrame(payload={"test": "data"}, codec="json"),
            KeyRequestFrame(kid="test-key"),
        ]

        for frame in frames_to_test:
            envelope = FameEnvelope(frame=frame, sid="test-sid")

            # Sign the envelope
            signed_envelope = signer.sign_envelope(envelope, physical_path="/test")

            # Verify signature was added
            assert signed_envelope.sec is not None
            assert signed_envelope.sec.sig is not None
            assert signed_envelope.sec.sig.kid == "envelope-test"
            # Note: alg field may not be set by default in some implementations
            assert len(signed_envelope.sec.sig.val) > 0  # Signature should not be empty

    def test_key_factory_parameter_variations(self):
        """Test key factories with different parameters."""
        # Test RSA with different kids
        rsa1 = create_rsa_keypair(kid="rsa-1")
        rsa2 = create_rsa_keypair(kid="rsa-2")
        rsa_empty = create_rsa_keypair(kid="")
        rsa_default = create_rsa_keypair()  # Should use 'dev' as default

        assert rsa1.jwks["keys"][0]["kid"] == "rsa-1"
        assert rsa2.jwks["keys"][0]["kid"] == "rsa-2"
        assert rsa_empty.jwks["keys"][0]["kid"] == ""
        assert rsa_default.jwks["keys"][0]["kid"] == "dev"

        # Test Ed25519 with different kids
        ed1 = create_ed25519_keypair(kid="ed-1")
        ed2 = create_ed25519_keypair(kid="ed-2")
        ed_empty = create_ed25519_keypair(kid="")
        ed_default = create_ed25519_keypair()  # Should use 'dev' as default

        assert ed1.jwks["keys"][0]["kid"] == "ed-1"
        assert ed2.jwks["keys"][0]["kid"] == "ed-2"
        assert ed_empty.jwks["keys"][0]["kid"] == ""
        assert ed_default.jwks["keys"][0]["kid"] == "dev"

        # All keys should be different
        keys = [rsa1, rsa2, ed1, ed2]
        private_keys = [k.private_pem for k in keys]
        public_keys = [k.public_pem for k in keys]

        # All private keys should be unique
        assert len(set(private_keys)) == len(private_keys)
        # All public keys should be unique
        assert len(set(public_keys)) == len(public_keys)

    def test_cryptographic_properties(self):
        """Test that generated keys have proper cryptographic properties."""
        # Test RSA key properties
        rsa_keypair = create_rsa_keypair(kid="property-test-rsa")

        from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

        # Load and verify RSA key
        rsa_private = load_pem_private_key(rsa_keypair.private_pem.encode(), password=None)
        rsa_public = load_pem_public_key(rsa_keypair.public_pem.encode())

        assert isinstance(rsa_private, rsa.RSAPrivateKey)
        assert isinstance(rsa_public, rsa.RSAPublicKey)
        assert rsa_private.key_size == 2048
        assert rsa_private.public_key().public_numbers().e == 65537  # Standard exponent

        # Test Ed25519 key properties
        ed25519_keypair = create_ed25519_keypair(kid="property-test-ed25519")

        # Load and verify Ed25519 key
        ed25519_private = load_pem_private_key(ed25519_keypair.private_pem.encode(), password=None)
        ed25519_public = load_pem_public_key(ed25519_keypair.public_pem.encode())

        assert isinstance(ed25519_private, ed25519.Ed25519PrivateKey)
        assert isinstance(ed25519_public, ed25519.Ed25519PublicKey)

        # Test that the private key can generate the corresponding public key
        derived_public = ed25519_private.public_key()
        original_public_bytes = ed25519_public.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        derived_public_bytes = derived_public.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        assert original_public_bytes == derived_public_bytes

    def test_signature_verification_with_real_crypto(self):
        """Test signature creation and verification using real cryptographic operations."""
        # This test ensures that our signing and verification actually work
        # with real cryptographic libraries, not just mocks

        # Generate real Ed25519 key
        ed25519_keypair = create_ed25519_keypair(kid="real-crypto-test")

        # Create a message to sign
        message = b"This is a test message for cryptographic verification"

        # Sign using cryptography library directly
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        private_key = load_pem_private_key(ed25519_keypair.private_pem.encode(), password=None)
        signature = private_key.sign(message)

        # Verify using cryptography library directly
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        public_key = load_pem_public_key(ed25519_keypair.public_pem.encode())

        # This should not raise an exception if the signature is valid
        try:
            public_key.verify(signature, message)
            verification_success = True
        except Exception:
            verification_success = False

        assert verification_success, "Real cryptographic signature verification failed"

        # Test that a modified message fails verification
        modified_message = b"This is a MODIFIED test message for cryptographic verification"
        try:
            public_key.verify(signature, modified_message)
            tamper_detection = False
        except Exception:
            tamper_detection = True

        assert tamper_detection, "Signature verification should fail for tampered messages"


@pytest.mark.asyncio
async def test_async_signature_verification():
    """Test that async signature verification works with real keys."""
    # Generate real keys
    ed25519_keypair = create_ed25519_keypair(kid="async-test")

    # Setup key infrastructure
    key_store = get_key_store()
    key_store._keys.clear()

    jwk = ed25519_keypair.jwks["keys"][0]
    physical_path = "/async_test_node"
    sid = secure_digest(physical_path)
    jwk["sid"] = sid
    jwk["physical_path"] = physical_path
    await key_store.add_key(jwk["kid"], jwk)

    # Create crypto provider and signing infrastructure
    crypto_provider = DefaultCryptoProvider(
        signature_private_pem=ed25519_keypair.private_pem,
        signature_public_pem=ed25519_keypair.public_pem,
        signature_key_id=jwk["kid"],
    )

    signer = EdDSAEnvelopeSigner(crypto=crypto_provider)
    key_provider = get_key_provider()
    verifier = EdDSAEnvelopeVerifier(key_provider=key_provider)

    # Create and sign envelope
    frame = DataFrame(payload={"async": "test", "data": [1, 2, 3]}, codec="json")
    envelope = FameEnvelope(frame=frame, sid=sid)

    signed_envelope = signer.sign_envelope(envelope, physical_path=physical_path)

    # Verify signature asynchronously
    is_valid = await verifier.verify_envelope(signed_envelope)
    assert is_valid, "Signature verification should succeed with real keys"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from naylence.fame.security.crypto.crypto_utils import sealed_decrypt, sealed_encrypt


def test_sealed_encrypt_decrypt_roundtrip():
    # Generate recipient static keypair
    recip_priv = X25519PrivateKey.generate()
    recip_pub = recip_priv.public_key().public_bytes(
        encoding=__import__(
            "cryptography.hazmat.primitives.serialization"
        ).hazmat.primitives.serialization.Encoding.Raw,
        format=__import__(
            "cryptography.hazmat.primitives.serialization"
        ).hazmat.primitives.serialization.PublicFormat.Raw,
    )
    # Message
    msg = b"hello, Naylence!"
    # Encrypt
    blob = sealed_encrypt(msg, recip_pub)
    # Decrypt
    recovered = sealed_decrypt(blob, recip_priv)
    assert recovered == msg

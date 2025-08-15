#!/usr/bin/env python3
"""
Comprehensive test for the async X25519EncryptionManager.

Verifies that:
* envelopes are encrypted/decrypted when a key exists in the key-store
* encryption headers carry the correct KID
* graceful handling when the requested key is absent
"""

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from naylence.fame.core import FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.security.encryption.encryption_manager import EncryptionStatus
from naylence.fame.security.encryption.sealed.x25519_encryption_manager import X25519EncryptionManager
from naylence.fame.security.keys.key_provider import get_key_provider
from naylence.fame.security.keys.key_store import get_key_store


@pytest.fixture(autouse=True)
async def clean_key_store():
    """Clear global key store before and after each test to ensure isolation."""
    # Clear before test
    key_store = get_key_store()
    key_store._keys.clear()

    # Also reset the global singleton to ensure clean state
    import naylence.fame.security.keys.key_store as ks_module

    ks_module._instance = None

    yield

    # Clear after test
    key_store = get_key_store()
    key_store._keys.clear()

    # Reset singleton again
    ks_module._instance = None


@pytest.mark.asyncio
async def test_encryption_with_key_provider() -> None:
    # ── Arrange ────────────────────────────────────────────────────────────────
    mgr = X25519EncryptionManager(key_provider=get_key_provider())

    # generate an arbitrary X25519 key-pair and register it in the in-mem key-store
    prv = X25519PrivateKey.generate()
    pub = prv.public_key()
    kid = "test-enc-kid-123"

    x_val = (
        base64.urlsafe_b64encode(
            pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        .decode()
        .rstrip("=")
    )

    ks = get_key_store()
    await ks.add_key(
        kid,
        {
            "kid": kid,
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "x": x_val,
            "encryption_private_pem": prv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode(),
            "encryption_public_pem": pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
        },
    )

    # ── Act / Assert (happy path) ──────────────────────────────────────────────
    plain_env = FameEnvelope(frame=DataFrame(payload="Hello!", codec="json"))

    enc_res = await mgr.encrypt_envelope(
        plain_env,
        opts={
            "recip_pub": pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            "recip_kid": kid,
        },
    )
    assert enc_res.status is EncryptionStatus.OK
    enc_env = enc_res.envelope
    assert enc_env and enc_env.sec and enc_env.sec.enc and enc_env.sec.enc.kid == kid

    dec_env = await mgr.decrypt_envelope(enc_env)
    assert isinstance(dec_env.frame, DataFrame)
    assert dec_env.frame.payload == "Hello!"
    assert dec_env.frame.codec == "json"

    # ── Act / Assert (missing-key fallback) ────────────────────────────────────
    plain_env2 = FameEnvelope(frame=DataFrame(payload="Bye!", codec="json"))
    enc_res2 = await mgr.encrypt_envelope(
        plain_env2,
        opts={
            "recip_pub": pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
            "recip_kid": "non-existent-kid",
        },
    )
    assert enc_res2.status is EncryptionStatus.OK  # encryption succeeded
    enc_env2 = enc_res2.envelope
    assert enc_env2 is not None, "Encryption result should have an envelope"

    # Decryption should raise because we deliberately lack the private key
    with pytest.raises(Exception):
        await mgr.decrypt_envelope(enc_env2)

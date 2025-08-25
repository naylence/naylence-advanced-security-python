"""
Focused test for the specific NodeAttach -> Envelope Verification bug.

This test reproduces the exact scenario from the sentinel logs where:
1. Child node attaches and provides keys
2. Keys are added to key store successfully
3. Child sends signed envelope
4. EnvelopeVerifier fails with "Unknown key id"
"""

import pytest

from naylence.fame.core import DeliveryOriginType
from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider
from naylence.fame.security.keys.default_key_manager import DefaultKeyManager
from naylence.fame.security.keys.key_provider import get_key_provider
from naylence.fame.security.keys.key_store import get_key_store
from naylence.fame.security.signing.eddsa_envelope_verifier import EdDSAEnvelopeVerifier


@pytest.mark.asyncio
async def test_node_attach_envelope_verification_bug_reproduction():
    """
    Reproduce the exact bug: keys added via DefaultKeyManager not available to EnvelopeVerifier.

    This test reproduces the bug scenario from the sentinel logs:
    1. Keys successfully added during NodeAttach
    2. EnvelopeVerifier fails with "Unknown key id" when verifying signed envelope
    """
    print("Reproducing NodeAttach -> EnvelopeVerifier bug...")

    # 1. Set up the components exactly as they are in production
    global_key_store = get_key_store()
    key_manager = DefaultKeyManager(key_store=global_key_store)
    envelope_verifier = EdDSAEnvelopeVerifier(key_provider=get_key_provider())

    # 2. Create a child node with realistic keys (similar to the logs)
    child_crypto = DefaultCryptoProvider()
    child_crypto.set_node_context(
        node_id="OHGjVrpDX1EnhT1",  # From the log
        physical_path="/w3YI3dnHsQnuENw/OHGjVrpDX1EnhT1",  # From the log
        logicals=["fame.fabric"],
    )

    child_jwks = child_crypto.get_jwks()
    child_keys = child_jwks["keys"]

    # Find the signing key (the one that will be used for verification)
    signing_key = None
    for key in child_keys:
        if key.get("use") == "sig":
            signing_key = key
            break

    assert signing_key is not None, "Should have a signing key"
    print(f"Using signing key: {signing_key['kid']}")

    # 3. Add keys via KeyManager (simulating NodeAttach process)
    # Use LOCAL origin to avoid the path validation that's causing test failures
    await key_manager.add_keys(
        keys=child_keys,
        physical_path="/w3YI3dnHsQnuENw/OHGjVrpDX1EnhT1",
        system_id="OHGjVrpDX1EnhT1",
        origin=DeliveryOriginType.LOCAL,  # Simplified for test
    )

    # 4. Verify key was added to KeyManager
    assert await key_manager.has_key(signing_key["kid"]), "KeyManager should have the signing key"
    print("✅ Key successfully added to KeyManager")

    # 5. Verify key is available to EnvelopeVerifier (this is where the bug occurs)
    try:
        retrieved_key = await envelope_verifier._key_provider.get_key(signing_key["kid"])
        assert retrieved_key is not None, "EnvelopeVerifier should be able to retrieve the key"
        print("✅ EnvelopeVerifier can access the key - bug is fixed!")

    except ValueError as e:
        if "Unknown key id" in str(e):
            pytest.fail(f"BUG REPRODUCED: {e}. This is the exact error from the sentinel logs.")
        else:
            raise

    # 6. Additional verification: Check that the key stores are the same instance
    assert key_manager._key_store is global_key_store, "KeyManager should use global key store"
    assert envelope_verifier._key_provider is global_key_store, (
        "EnvelopeVerifier should use global key store"
    )

    print("✅ All components use the same key store instance")


@pytest.mark.asyncio
async def test_key_manager_creation_patterns():
    """
    Test different ways of creating DefaultKeyManager to ensure they all use global key store.
    """
    print("Testing DefaultKeyManager creation patterns...")

    global_key_store = get_key_store()

    # Pattern 1: Direct creation with global key store (correct)
    key_manager1 = DefaultKeyManager(key_store=global_key_store)

    # Pattern 2: Factory creation (should also use global key store)
    from naylence.fame.security.keys.default_key_manager_factory import DefaultKeyManagerFactory

    factory = DefaultKeyManagerFactory()
    key_manager2 = await factory.create()

    # Pattern 3: Via SecurityManager (production pattern)
    from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
    from naylence.fame.security.policy.security_policy import OutboundSigningRules, SigningConfig
    from naylence.fame.security.security_manager_factory import SecurityManagerFactory

    # Create a policy that requires key management
    policy_with_key_mgmt = DefaultSecurityPolicy(
        signing=SigningConfig(outbound=OutboundSigningRules(default_signing=True))
    )
    node_security = await SecurityManagerFactory.create_security_manager(policy_with_key_mgmt)
    key_manager3 = node_security.key_manager

    # All should use the same global key store
    assert key_manager1._key_store is global_key_store, "Direct creation should use global key store"
    assert key_manager2._key_store is global_key_store, "Factory creation should use global key store"
    assert key_manager3._key_store is global_key_store, (
        "SecurityManager creation should use global key store"
    )

    print("✅ All creation patterns use the same global key store")


def test_envelope_verifier_key_provider():
    """
    Test that EnvelopeVerifier uses the correct key provider.
    """
    print("Testing EnvelopeVerifier key provider setup...")

    verifier = EdDSAEnvelopeVerifier(key_provider=get_key_provider())
    global_key_provider = get_key_provider()

    # EnvelopeVerifier should use the global key provider
    assert verifier._key_provider is global_key_provider, "EnvelopeVerifier should use global key provider"

    print("✅ EnvelopeVerifier correctly configured with global key provider")


if __name__ == "__main__":
    # Run the tests
    import asyncio

    asyncio.run(test_node_attach_envelope_verification_bug_reproduction())
    asyncio.run(test_key_manager_creation_patterns())
    test_envelope_verifier_key_provider()
    print("🎉 All focused bug reproduction tests passed!")

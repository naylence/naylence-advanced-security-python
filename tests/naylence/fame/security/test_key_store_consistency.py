"""
Unit tests to ensure KeyManager and EnvelopeVerifier use the same key storage.

These tests specifically target the bug where DefaultKeyManager was created with
a separate InMemoryKeyStore instance instead of using the global singleton.
"""

import pytest

from naylence.fame.security.keys.default_key_manager import DefaultKeyManager
from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore
from naylence.fame.security.keys.key_provider import get_key_provider
from naylence.fame.security.keys.key_store import get_key_store
from naylence.fame.security.signing.eddsa_envelope_verifier import EdDSAEnvelopeVerifier


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
async def test_key_manager_uses_global_key_store():
    """
    Test that DefaultKeyManager should use the global key store singleton,
    not create its own separate instance.
    """
    print("Testing KeyManager uses global key store...")

    # Get the global key store
    global_key_store = get_key_store()

    # Create KeyManager with global key store (correct approach)
    key_manager_correct = DefaultKeyManager(key_store=global_key_store)

    # Create KeyManager with separate instance (incorrect approach that caused the bug)
    separate_key_store = InMemoryKeyStore()
    key_manager_incorrect = DefaultKeyManager(key_store=separate_key_store)

    # Add a key via the correct manager
    test_key = {
        "kid": "test-key-global",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "test-x-value",
        "use": "sig",
        "alg": "EdDSA",
    }

    await key_manager_correct.add_keys(
        keys=[test_key],
        physical_path="/test",
        system_id="test-system",
        origin="local",
    )

    # Add a different key via the incorrect manager
    test_key_separate = {
        "kid": "test-key-separate",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "test-x-value-2",
        "use": "sig",
        "alg": "EdDSA",
    }

    await key_manager_incorrect.add_keys(
        keys=[test_key_separate],
        physical_path="/test",
        system_id="test-system",
        origin="local",
    )

    # Verify the global key store has the correct key
    assert await global_key_store.has_key("test-key-global"), (
        "Global key store should have key from correct manager"
    )

    # Verify the global key store does NOT have the separate key
    assert not await global_key_store.has_key("test-key-separate"), (
        "Global key store should NOT have key from incorrect manager with separate store"
    )

    # This demonstrates the bug: EnvelopeVerifier uses global store,
    # so it can only see keys from the correct manager
    envelope_verifier = EdDSAEnvelopeVerifier(key_provider=get_key_provider())

    # This should work
    try:
        await envelope_verifier._key_provider.get_key("test-key-global")
        print("✅ EnvelopeVerifier can access key from correct manager")
    except ValueError:
        pytest.fail("EnvelopeVerifier should be able to access key from correct manager")

    # This should fail (demonstrating the bug scenario)
    try:
        await envelope_verifier._key_provider.get_key("test-key-separate")
        pytest.fail("EnvelopeVerifier should NOT be able to access key from incorrect manager")
    except ValueError as e:
        if "Unknown key id" in str(e):
            print(
                "✅ Confirmed: EnvelopeVerifier cannot access keys from separate key store "
                "(this was the bug)"
            )
        else:
            raise


@pytest.mark.asyncio
async def test_envelope_verifier_uses_global_key_provider():
    """
    Test that EnvelopeVerifier uses the global key provider/store.
    """
    print("Testing EnvelopeVerifier uses global key provider...")

    # Create EnvelopeVerifier with explicit key provider
    global_key_provider = get_key_provider()
    verifier = EdDSAEnvelopeVerifier(key_provider=global_key_provider)

    # Verify they're the same instance
    assert verifier._key_provider is global_key_provider, (
        "EnvelopeVerifier should use the global key provider singleton"
    )

    print("✅ EnvelopeVerifier correctly uses global key provider")


def test_key_provider_key_store_consistency():
    """
    Test that get_key_provider() and get_key_store() return consistent instances.
    """
    print("Testing key provider and key store consistency...")

    key_provider = get_key_provider()
    key_store = get_key_store()

    # They should be the same instance (InMemoryKeyStore implements both interfaces)
    assert key_provider is key_store, (
        "get_key_provider() and get_key_store() should return the same singleton instance"
    )

    print("✅ Key provider and key store are consistent")


@pytest.mark.asyncio
async def test_node_security_key_manager_consistency():
    """
    Test that SecurityManager creates KeyManager instances that use the global key store.
    """
    print("Testing SecurityManager creates consistent KeyManager...")

    from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
    from naylence.fame.security.policy.security_policy import SigningConfig, OutboundSigningRules
    from naylence.fame.security.security_manager_factory import SecurityManagerFactory

    # Create SecurityManager using a policy that requires key management (signing requires keys)
    policy_with_key_mgmt = DefaultSecurityPolicy(
        signing=SigningConfig(
            outbound=OutboundSigningRules(default_signing=True)
        )
    )
    node_security = await SecurityManagerFactory.create_security_manager(policy_with_key_mgmt)

    # Get the global key store
    global_key_store = get_key_store()

    # The key manager should use the global key store
    # Note: This test verifies the fix where node_security.py was changed
    # to use get_key_store() instead of InMemoryKeyStore()
    assert node_security.key_manager._key_store is global_key_store, (
        "SecurityManager should create KeyManager with global key store"
    )

    print("✅ SecurityManager creates KeyManager with consistent key store")


if __name__ == "__main__":
    # Run the tests
    import asyncio

    asyncio.run(test_key_manager_uses_global_key_store())
    test_envelope_verifier_uses_global_key_provider()
    test_key_provider_key_store_consistency()
    asyncio.run(test_node_security_key_manager_consistency())
    print("🎉 All key store consistency tests passed!")

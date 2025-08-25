"""
Test to verify that key exchange is only required when the policy requires encryption or signing.
"""

import pytest

from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.policy.security_policy import (
    CryptoLevel,
    EncryptionConfig,
    SignaturePolicy,
    SigningConfig,
)
from naylence.fame.security.security_manager_factory import SecurityManagerFactory
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
from naylence.fame.tracking.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory


@pytest.mark.asyncio
async def test_key_exchange_required_for_encryption_or_signing():
    """Test that key exchange is required if and only if the policy requires encryption or signing."""

    # Test 1: Policy with encryption requires key exchange
    encryption_config = EncryptionConfig()
    encryption_config.outbound.default_level = CryptoLevel.SEALED

    encryption_policy = DefaultSecurityPolicy(encryption=encryption_config)
    encryption_requirements = encryption_policy.requirements()

    assert encryption_requirements.require_key_exchange is True
    assert encryption_requirements.encryption_required is True

    encryption_security = await SecurityManagerFactory.create_security_manager(encryption_policy)
    assert encryption_security.key_manager is not None

    # Test 2: Policy with signing requires key exchange
    signing_config = SigningConfig()
    signing_config.outbound.default_signing = True

    signing_policy = DefaultSecurityPolicy(signing=signing_config)
    signing_requirements = signing_policy.requirements()

    assert signing_requirements.require_key_exchange is True
    assert signing_requirements.signing_required is True

    signing_security = await SecurityManagerFactory.create_security_manager(signing_policy)
    assert signing_security.key_manager is not None

    # Test 3: Policy with both encryption and signing requires key exchange
    both_policy = DefaultSecurityPolicy(encryption=encryption_config, signing=signing_config)
    both_requirements = both_policy.requirements()

    assert both_requirements.require_key_exchange is True
    assert both_requirements.encryption_required is True
    assert both_requirements.signing_required is True

    both_security = await SecurityManagerFactory.create_security_manager(both_policy)
    assert both_security.key_manager is not None

    # Test 4: Policy with neither encryption nor signing doesn't require key exchange
    no_crypto_encryption_config = EncryptionConfig()
    no_crypto_encryption_config.outbound.default_level = CryptoLevel.PLAINTEXT
    no_crypto_encryption_config.inbound.allow_sealed = False
    no_crypto_encryption_config.inbound.allow_channel = False
    no_crypto_encryption_config.response.minimum_response_level = CryptoLevel.PLAINTEXT

    no_crypto_signing_config = SigningConfig()
    no_crypto_signing_config.outbound.default_signing = False
    no_crypto_signing_config.outbound.sign_sensitive_operations = False
    no_crypto_signing_config.outbound.sign_if_recipient_expects = False
    no_crypto_signing_config.inbound.signature_policy = SignaturePolicy.DISABLED
    no_crypto_signing_config.response.mirror_request_signing = False
    no_crypto_signing_config.response.always_sign_responses = False
    no_crypto_signing_config.response.sign_error_responses = False

    no_crypto_policy = DefaultSecurityPolicy(
        encryption=no_crypto_encryption_config, signing=no_crypto_signing_config
    )
    no_crypto_requirements = no_crypto_policy.requirements()

    assert no_crypto_requirements.require_key_exchange is False
    assert no_crypto_requirements.encryption_required is False
    assert no_crypto_requirements.signing_required is False

    no_crypto_security = await SecurityManagerFactory.create_security_manager(no_crypto_policy)
    assert no_crypto_security.key_manager is None

    # Test 5: FameNode respects the policy-driven key manager
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    storage_provider = InMemoryStorageProvider()

    # Create envelope tracker for first node
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

    node_with_crypto = FameNode(
        system_id="test_crypto",
        security_manager=encryption_security,
        storage_provider=storage_provider,
        node_meta_store=InMemoryKVStore[NodeMeta](NodeMeta),
        delivery_tracker=delivery_tracker,
    )
    assert node_with_crypto._security_manager.key_manager is not None

    storage_provider2 = InMemoryStorageProvider()

    # Create envelope tracker for second node
    delivery_tracker_factory2 = DefaultDeliveryTrackerFactory()
    delivery_tracker2 = await delivery_tracker_factory2.create(storage_provider=storage_provider2)

    node_without_crypto = FameNode(
        system_id="test_no_crypto",
        security_manager=no_crypto_security,
        storage_provider=storage_provider2,
        node_meta_store=InMemoryKVStore[NodeMeta](NodeMeta),
        delivery_tracker=delivery_tracker2,
    )
    assert node_without_crypto._security_manager.key_manager is None

    print("✓ Key exchange is required if and only if the policy requires encryption or signing")


if __name__ == "__main__":
    test_key_exchange_required_for_encryption_or_signing()
    print("All tests passed!")

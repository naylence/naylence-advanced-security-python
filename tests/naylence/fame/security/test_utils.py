"""
Test utilities for security component testing.

This module contains helper functions that were previously private methods
in DefaultSecurityManager but are needed for comprehensive testing
of algorithm preferences and component creation.
"""

from typing import Any, Callable, List, Optional

from naylence.fame.security.encryption.encryption_manager import EncryptionManager
from naylence.fame.security.signing.envelope_signer import EnvelopeSigner
from naylence.fame.security.signing.envelope_verifier import EnvelopeVerifier


def get_preferred_signing_algorithms(requirements) -> List[str]:
    """Extract preferred signing algorithms from requirements, with backward compatibility."""
    # New list-based preference (preferred)
    if hasattr(requirements, "preferred_signing_algorithms"):
        return list(requirements.preferred_signing_algorithms)
    # Old single algorithm preference (backward compatibility)
    elif hasattr(requirements, "preferred_signing_algorithm"):
        return [requirements.preferred_signing_algorithm]
    # Default fallback
    else:
        return ["EdDSA"]


def get_preferred_encryption_algorithms(requirements) -> List[str]:
    """Extract preferred encryption algorithms from requirements, with backward compatibility."""
    # New list-based preference (preferred)
    if hasattr(requirements, "preferred_encryption_algorithms"):
        return list(requirements.preferred_encryption_algorithms)
    # Old single algorithm preference (backward compatibility)
    elif hasattr(requirements, "preferred_encryption_algorithm"):
        return [requirements.preferred_encryption_algorithm]
    # Default fallback
    else:
        return ["X25519"]


def create_default_signer(algorithms: List[str], signing_config) -> Optional[EnvelopeSigner]:
    """Create default envelope signer based on algorithm preferences."""
    try:
        from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
        from naylence.fame.security.signing.eddsa_envelope_signer import EdDSAEnvelopeSigner

        # For now, we only support EdDSA
        if "EdDSA" in algorithms:
            crypto_provider = get_crypto_provider()
            return EdDSAEnvelopeSigner(crypto=crypto_provider, signing_config=signing_config)
        return None
    except ImportError:
        return None


def create_default_verifier(algorithms: List[str], signing_config) -> Optional[EnvelopeVerifier]:
    """Create default envelope verifier based on algorithm preferences."""
    try:
        from naylence.fame.security.keys.key_provider import get_key_provider
        from naylence.fame.security.signing.eddsa_envelope_verifier import EdDSAEnvelopeVerifier

        # For now, we only support EdDSA
        if "EdDSA" in algorithms:
            key_provider = get_key_provider()
            return EdDSAEnvelopeVerifier(key_provider=key_provider, signing_config=signing_config)
        return None
    except ImportError:
        return None


def create_default_encryption_manager(
    algorithms: List[str], get_secure_channel_manager: Callable[[], Any]
) -> Optional[EncryptionManager]:
    """Create default encryption manager based on algorithm preferences."""
    try:
        from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
        from naylence.fame.security.encryption.composite_encryption_manager import (
            CompositeEncryptionManager,
        )
        from naylence.fame.security.keys.key_provider import get_key_provider

        # Define valid algorithms (based on CompositeEncryptionManager defaults and known algorithms)
        valid_sealed_algorithms = ["X25519", "ECDH-ES+A256GCM", "chacha20-poly1305", "aes-256-gcm"]
        valid_channel_algorithms = ["chacha20-poly1305-channel"]
        all_valid_algorithms = valid_sealed_algorithms + valid_channel_algorithms

        # Filter out unknown algorithms
        filtered_algorithms = [alg for alg in algorithms if alg in all_valid_algorithms]

        # If no valid algorithms, fall back to default CompositeEncryptionManager
        if not filtered_algorithms:
            crypto = get_crypto_provider()
            secure_channel_manager = get_secure_channel_manager()  # Get the actual instance
            return CompositeEncryptionManager(
                secure_channel_manager=secure_channel_manager,
                crypto=crypto,
                key_provider=get_key_provider(),
            )

        # If only X25519, create specialized manager
        if filtered_algorithms == ["X25519"]:
            from naylence.fame.security.encryption.sealed.x25519_encryption_manager import (
                X25519EncryptionManager,
            )

            crypto = get_crypto_provider()
            key_provider = get_key_provider()  # Use singleton for testing
            return X25519EncryptionManager(crypto=crypto, key_provider=key_provider)

        # For multiple algorithms or other combinations, create composite manager
        crypto = get_crypto_provider()

        # Separate sealed vs channel algorithms
        sealed_algorithms = []
        channel_algorithms = []

        for alg in filtered_algorithms:
            if alg in valid_channel_algorithms:
                channel_algorithms.append(alg)
            elif alg in valid_sealed_algorithms:
                sealed_algorithms.append(alg)

        # X25519 is handled specially in CompositeEncryptionManager -
        # it's not in the default sealed algorithms
        # but CompositeEncryptionManager creates an X25519EncryptionManager internally
        secure_channel_manager = get_secure_channel_manager()  # Get the actual instance
        result = CompositeEncryptionManager(
            secure_channel_manager=secure_channel_manager,
            crypto=crypto,
            key_provider=get_key_provider(),  # Add required key_provider
            supported_sealed_algorithms=sealed_algorithms or None,
            supported_channel_algorithms=channel_algorithms or None,
        )
        return result

    except ImportError:
        return None
    except Exception:
        return None

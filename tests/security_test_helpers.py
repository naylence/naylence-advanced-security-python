"""
Helper functions for security tests.
"""

from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.policy.security_policy import (
    SigningConfig, OutboundSigningRules, InboundSigningRules, ResponseSigningRules,
    EncryptionConfig, OutboundEncryptionRules, InboundEncryptionRules, ResponseEncryptionRules,
    SignaturePolicy, CryptoLevel, ViolationAction
)


def create_signing_required_policy():
    """Create a policy that requires signing components."""
    return DefaultSecurityPolicy(
        signing=SigningConfig(
            outbound=OutboundSigningRules(default_signing=True),
            inbound=InboundSigningRules(signature_policy=SignaturePolicy.OPTIONAL),
            response=ResponseSigningRules(mirror_request_signing=True),
        )
    )


def create_encryption_required_policy():
    """Create a policy that requires encryption components."""
    return DefaultSecurityPolicy(
        encryption=EncryptionConfig(
            outbound=OutboundEncryptionRules(default_level=CryptoLevel.CHANNEL),
            inbound=InboundEncryptionRules(
                allow_plaintext=True,
                allow_channel=True,
                allow_sealed=True,
            ),
            response=ResponseEncryptionRules(
                minimum_response_level=CryptoLevel.PLAINTEXT,
                mirror_request_level=True,
            ),
        )
    )


def create_full_security_policy():
    """Create a policy that requires all security components."""
    return DefaultSecurityPolicy(
        signing=SigningConfig(
            outbound=OutboundSigningRules(default_signing=True),
            inbound=InboundSigningRules(signature_policy=SignaturePolicy.OPTIONAL),
            response=ResponseSigningRules(mirror_request_signing=True),
        ),
        encryption=EncryptionConfig(
            outbound=OutboundEncryptionRules(default_level=CryptoLevel.CHANNEL),
            inbound=InboundEncryptionRules(
                allow_plaintext=True,
                allow_channel=True,
                allow_sealed=True,
            ),
            response=ResponseEncryptionRules(
                minimum_response_level=CryptoLevel.PLAINTEXT,
                mirror_request_level=True,
            ),
        )
    )

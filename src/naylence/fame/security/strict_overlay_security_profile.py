"""
Strict Overlay Security Profile

Provides the strict-overlay security profile for advanced security scenarios.
This profile requires X.509 certificate-based signing and supports both
channel and sealed encryption modes.
"""

from naylence.fame.factory import Expressions
from naylence.fame.profile import RegisterProfileOptions, register_profile
from naylence.fame.security.security_manager_factory import (
    SECURITY_MANAGER_FACTORY_BASE_TYPE,
)

ENV_VAR_DEFAULT_ENCRYPTION_LEVEL = "FAME_DEFAULT_ENCRYPTION_LEVEL"
ENV_VAR_AUTHORIZATION_PROFILE = "FAME_AUTHORIZATION_PROFILE"

PROFILE_NAME_STRICT_OVERLAY = "strict-overlay"

STRICT_OVERLAY_PROFILE = {
    "type": "DefaultSecurityManager",
    "security_policy": {
        "type": "DefaultSecurityPolicy",
        "signing": {
            "signing_material": "x509-chain",
            "require_cert_sid_match": True,
            "inbound": {
                "signature_policy": "required",
                "unsigned_violation_action": "nack",
                "invalid_signature_action": "nack",
            },
            "response": {
                "mirror_request_signing": True,
                "always_sign_responses": False,
                "sign_error_responses": True,
            },
            "outbound": {
                "default_signing": True,
                "sign_sensitive_operations": True,
                "sign_if_recipient_expects": True,
            },
        },
        "encryption": {
            "inbound": {
                "allow_plaintext": True,
                "allow_channel": True,
                "allow_sealed": True,
                "plaintext_violation_action": "nack",
                "channel_violation_action": "nack",
                "sealed_violation_action": "nack",
            },
            "response": {
                "mirror_request_level": True,
                "minimum_response_level": "plaintext",
                "escalate_sealed_responses": False,
            },
            "outbound": {
                "default_level": Expressions.env(
                    ENV_VAR_DEFAULT_ENCRYPTION_LEVEL, default="channel"
                ),
                "escalate_if_peer_supports": False,
                "prefer_sealed_for_sensitive": False,
            },
        },
    },
    "authorizer": {
        "type": "AuthorizationProfile",
        "profile": Expressions.env(ENV_VAR_AUTHORIZATION_PROFILE, default="jwt"),
    },
}

_registered = False


def register_strict_overlay_profile() -> None:
    """Register the strict-overlay profile in the profile registry.

    This function is idempotent - it will only register the profile once.
    Call this function to make the strict-overlay profile available for use.
    """
    global _registered
    if _registered:
        return

    register_profile(
        SECURITY_MANAGER_FACTORY_BASE_TYPE,
        PROFILE_NAME_STRICT_OVERLAY,
        STRICT_OVERLAY_PROFILE,
        RegisterProfileOptions(
            source="advanced-security:strict-overlay-security-profile",
            allow_override=True,
        ),
    )
    _registered = True


# Auto-register when module is imported (side-effect import pattern)
register_strict_overlay_profile()

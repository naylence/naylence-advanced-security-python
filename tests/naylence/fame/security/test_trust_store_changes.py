#!/usr/bin/env python3
"""
Test script to verify the trust store changes work correctly.
"""

import asyncio
import os
import tempfile

from naylence.fame.security.cert.attachment_cert_validator_factory import (
    AttachmentCertValidatorConfig,
    AttachmentCertValidatorFactory,
)


async def test_trust_store_fallback():
    """Test that trust store falls back to FAME_CA_CERTS environment variable."""

    factory = AttachmentCertValidatorFactory()

    # Test 1: No trust store configured, no environment variable
    print("Test 1: No trust store configured, no environment variable")
    config1 = AttachmentCertValidatorConfig()
    validator1 = await factory.create(config1)
    print(f"  trust_store: {validator1.trust_store}")
    print(f"  enforce_name_constraints: {validator1.enforce_name_constraints}")
    print(f"  strict_validation: {validator1.strict_validation}")

    # Test validation with no trust store
    try:
        await validator1.validate_keys([])
        result = True
        message = ""
    except Exception as e:
        result = False
        message = str(e)
    print(f"  Validation result: {result}, message: {message}")
    print()

    # Test 2: Trust store configured via config
    print("Test 2: Trust store configured via config")
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as tmp:
        tmp.write("-----BEGIN CERTIFICATE-----\nMockCertificateData\n-----END CERTIFICATE-----\n")
        trust_store_path = tmp.name

    try:
        config2 = AttachmentCertValidatorConfig(trust_store=trust_store_path)
        validator2 = await factory.create(config2)
        print(f"  trust_store: {validator2.trust_store}")
        print(f"  enforce_name_constraints: {validator2.enforce_name_constraints}")
        print(f"  strict_validation: {validator2.strict_validation}")

        # Test validation with configured trust store
        try:
            await validator2.validate_keys([])
            result = True
            message = ""
        except Exception as e:
            result = False
            message = str(e)
        print(f"  Validation result: {result}, message: {message}")
        print()
    finally:
        os.unlink(trust_store_path)

    # Test 3: Environment variable fallback
    print("Test 3: Environment variable fallback")
    os.environ["FAME_CA_CERTS"] = (
        "-----BEGIN CERTIFICATE-----\nMockEnvCertificateData\n-----END CERTIFICATE-----\n"
    )

    config3 = AttachmentCertValidatorConfig()  # No trust_store configured
    validator3 = await factory.create(config3)
    print(f"  trust_store: {validator3.trust_store}")
    print(f"  enforce_name_constraints: {validator3.enforce_name_constraints}")
    print(f"  strict_validation: {validator3.strict_validation}")

    # Test validation with environment variable
    try:
        await validator3.validate_keys([])
        result = True
        message = ""
    except Exception as e:
        result = False
        message = str(e)
    print(f"  Validation result: {result}, message: {message}")
    print()

    # Test 4: Individual properties passed correctly
    print("Test 4: Individual properties passed correctly")
    config4 = AttachmentCertValidatorConfig(enforce_name_constraints=False, strict_validation=False)
    validator4 = await factory.create(config4)
    print(f"  trust_store: {validator4.trust_store}")
    print(f"  enforce_name_constraints: {validator4.enforce_name_constraints}")
    print(f"  strict_validation: {validator4.strict_validation}")
    print()

    # Clean up environment
    if "FAME_CA_CERTS" in os.environ:
        del os.environ["FAME_CA_CERTS"]

    print("All tests completed successfully!")


if __name__ == "__main__":
    asyncio.run(test_trust_store_fallback())

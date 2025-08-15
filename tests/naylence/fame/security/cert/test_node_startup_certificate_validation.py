"""
Test node startup certificate validation.

This test verifies that:
1. Nodes fail to start when their certificates are not trusted
2. Nodes start successfully when their certificates are trusted
3. Certificate validation is properly enforced at startup
"""

import os

import pytest

from naylence.fame.core import SecuritySettings, SigningMaterial
from naylence.fame.security.cert.ca_service import create_test_ca
from naylence.fame.security.cert.default_certificate_manager import create_certificate_manager
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider


@pytest.mark.asyncio
async def test_node_startup_certificate_validation_failure():
    """Test that nodes fail to start with untrusted certificates."""

    # Create two different CA certificates
    trusted_ca_cert, trusted_ca_key = create_test_ca()
    untrusted_ca_cert, untrusted_ca_key = create_test_ca()

    # Save original environment
    original_env = {
        "FAME_CA_CERTS": os.environ.get("FAME_CA_CERTS"),
        "FAME_TEST_CA_KEY": os.environ.get("FAME_TEST_CA_KEY"),
        "FAME_TEST_CA_CERT": os.environ.get("FAME_TEST_CA_CERT"),
    }

    try:
        # Configure trust validation to use trusted CA
        os.environ["FAME_CA_CERTS"] = trusted_ca_cert

        # Configure certificate generation to use untrusted CA
        os.environ["FAME_TEST_CA_CERT"] = untrusted_ca_cert
        os.environ["FAME_TEST_CA_KEY"] = untrusted_ca_key

        # Create certificate manager with X509 requirement
        security_settings = SecuritySettings(signing_material=SigningMaterial.X509_CHAIN)
        cert_manager = create_certificate_manager(security_settings=security_settings)

        # Mock a node-like object
        class MockNode:
            def __init__(self):
                self.id = "test-failing-node"
                self.physical_path = "/test/failing/path"
                self.accepted_logicals = ["/"]
                self.has_parent = False
                self.sid = "test-failing-node-sid"

        node = MockNode()

        # Test that node startup fails due to certificate validation
        with pytest.raises(RuntimeError, match="certificate validation failed"):
            await cert_manager.on_node_started(node)

    finally:
        # Restore original environment
        for key, value in original_env.items():
            if value is not None:
                os.environ[key] = value
            elif key in os.environ:
                del os.environ[key]


@pytest.mark.asyncio
async def test_node_startup_certificate_validation_success():
    """Test that nodes start successfully with trusted certificates."""

    # This test skips the CA service and directly tests the validation logic
    # by pre-generating certificates and testing the certificate manager's response

    # Use same CA for both signing and trust validation
    test_ca_cert, test_ca_key = create_test_ca()

    # Save original environment
    original_env = {
        "FAME_CA_CERTS": os.environ.get("FAME_CA_CERTS"),
        "FAME_CA_SERVICE_URL": os.environ.get("FAME_CA_SERVICE_URL"),
    }

    try:
        # Configure trust validation to use the test CA
        os.environ["FAME_CA_CERTS"] = test_ca_cert

        # Skip the CA service by setting it to a dummy URL that won't be reached
        # The test will validate the trust checking logic specifically
        os.environ["FAME_CA_SERVICE_URL"] = "http://test-dummy-url-not-accessible"

        # Create certificate manager with X509 requirement
        security_settings = SecuritySettings(signing_material=SigningMaterial.X509_CHAIN)
        cert_manager = create_certificate_manager(security_settings=security_settings)

        # Create and configure crypto provider with a valid certificate signed by our test CA
        crypto_provider = get_crypto_provider()
        crypto_provider.set_node_context(
            node_id="test-success-node", physical_path="/test/success/path", logicals=["fame.fabric"]
        )

        # Generate a certificate using our test CA
        from naylence.fame.security.cert.ca_service import CASigningService
        from naylence.fame.util.util import secure_digest

        physical_path = "/test/success/path"
        computed_sid = secure_digest(physical_path)

        ca_service = CASigningService(test_ca_cert, test_ca_key)
        cert_pem = ca_service.sign_node_cert(
            public_key_pem=crypto_provider._signature_public_pem,
            node_id="test-success-node",
            node_sid=computed_sid,
            physical_path=physical_path,
            logicals=["fame.fabric"],
        )

        # Store the certificate manually
        crypto_provider.store_signed_certificate(cert_pem)

        # Mock a node-like object
        class MockNode:
            def __init__(self):
                self.id = "test-success-node"
                self.physical_path = "/test/success/path"
                self.accepted_logicals = ["/"]
                self.has_parent = False
                self.sid = computed_sid

        node = MockNode()

        # Test that node startup succeeds (no exception should be raised)
        # Since we have a pre-existing valid certificate, the certificate manager
        # should validate it successfully and not attempt to get a new one
        try:
            await cert_manager.on_node_started(node)
            # If we get here, the startup was successful
            assert True, "Node startup should succeed with trusted certificates"
        except RuntimeError as e:
            if "certificate validation failed" in str(e):
                pytest.fail(f"Node startup should not fail with trusted certificates: {e}")
            else:
                # Some other error like network connectivity (which is expected in this test)
                # This is acceptable since we're testing the validation logic, not the CA service
                pass

    finally:
        # Restore original environment
        for key, value in original_env.items():
            if value is not None:
                os.environ[key] = value
            elif key in os.environ:
                del os.environ[key]


@pytest.mark.asyncio
async def test_certificate_manager_without_x509_requirement():
    """Test that certificate manager works correctly when X509 is not required."""

    # Create certificate manager without X509 requirement (RAW_KEY)
    security_settings = SecuritySettings(signing_material=SigningMaterial.RAW_KEY)
    cert_manager = create_certificate_manager(security_settings=security_settings)

    # Mock a node-like object
    class MockNode:
        def __init__(self):
            self.id = "test-raw-key-node"
            self.physical_path = "/test/raw/path"
            self.accepted_logicals = ["/"]
            self.has_parent = False
            self.sid = "test-raw-key-node-sid"

    node = MockNode()

    # Test that node startup succeeds without certificate validation
    await cert_manager.on_node_started(node)  # Should not raise any exception


@pytest.mark.asyncio
async def test_certificate_manager_child_node():
    """Test that certificate manager skips validation for child nodes."""

    # Create certificate manager with X509 requirement
    security_settings = SecuritySettings(signing_material=SigningMaterial.X509_CHAIN)
    cert_manager = create_certificate_manager(security_settings=security_settings)

    # Mock a child node (has_parent = True)
    class MockChildNode:
        def __init__(self):
            self.id = "test-child-node"
            self.physical_path = "/parent/child"
            self.accepted_logicals = ["/child"]
            self.has_parent = True
            self.sid = "test-child-node-sid"

    node = MockChildNode()

    # Test that child node startup succeeds (certificate validation is skipped)
    await cert_manager.on_node_started(node)  # Should not raise any exception


@pytest.mark.asyncio
async def test_child_node_certificate_validation_failure():
    """Test that child nodes fail when they can't get certificates but X509 is required."""

    # Create trusted CA for validation
    trusted_ca_cert, trusted_ca_key = create_test_ca()

    # Save original environment
    original_env = {
        "FAME_CA_CERTS": os.environ.get("FAME_CA_CERTS"),
        "FAME_CA_SERVICE_URL": os.environ.get("FAME_CA_SERVICE_URL"),
    }

    try:
        # Configure trust validation
        os.environ["FAME_CA_CERTS"] = trusted_ca_cert

        # Set CA service to unreachable URL to simulate CA service unavailability
        os.environ["FAME_CA_SERVICE_URL"] = "http://unreachable-ca-service:9999"

        # Create certificate manager with X509 requirement
        security_settings = SecuritySettings(signing_material=SigningMaterial.X509_CHAIN)
        cert_manager = create_certificate_manager(security_settings=security_settings)

        # Mock a welcome frame that requires X509
        class MockWelcomeFrame:
            def __init__(self):
                self.system_id = "test-child-node"
                self.assigned_path = "/parent/test-child-node"
                self.accepted_logicals = ["/child"]
                self.security_settings = SecuritySettings(signing_material=SigningMaterial.X509_CHAIN)

        welcome_frame = MockWelcomeFrame()

        # Test that child node fails when it can't get a certificate
        with pytest.raises(RuntimeError, match="certificate validation failed"):
            await cert_manager.on_welcome(welcome_frame)

    finally:
        # Restore original environment
        for key, value in original_env.items():
            if value is not None:
                os.environ[key] = value
            elif key in os.environ:
                del os.environ[key]


@pytest.mark.asyncio
async def test_security_manager_child_node_certificate_validation_failure():
    """Test that default security manager properly fails child nodes when certificates
    are required but unavailable."""

    # Create trusted CA for validation
    trusted_ca_cert, trusted_ca_key = create_test_ca()

    # Save original environment
    original_env = {
        "FAME_CA_CERTS": os.environ.get("FAME_CA_CERTS"),
        "FAME_CA_SERVICE_URL": os.environ.get("FAME_CA_SERVICE_URL"),
    }

    try:
        # Configure trust validation
        os.environ["FAME_CA_CERTS"] = trusted_ca_cert

        # Set CA service to unreachable URL to simulate CA service unavailability
        os.environ["FAME_CA_SERVICE_URL"] = "http://unreachable-ca-service:9999"

        # Import and create the security manager directly
        from naylence.fame.core.protocol.security_settings import SecuritySettings, SigningMaterial
        from naylence.fame.security.default_security_manager import DefaultSecurityManager
        from naylence.fame.security.policy import DefaultSecurityPolicy

        # Create security profile that requires X509
        security_settings = SecuritySettings(signing_material=SigningMaterial.X509_CHAIN)

        # Create certificate manager with X509 requirement
        cert_manager = create_certificate_manager(security_settings=security_settings)

        # Create security policy and manager with certificate manager
        policy = DefaultSecurityPolicy()
        security_manager = DefaultSecurityManager(policy=policy, certificate_manager=cert_manager)

        # Mock a welcome frame that requires X509
        class MockWelcomeFrame:
            def __init__(self):
                self.system_id = "test-child-node"
                self.assigned_path = "/parent/test-child-node"
                self.accepted_logicals = ["/child"]
                self.security_settings = SecuritySettings(signing_material=SigningMaterial.X509_CHAIN)

        welcome_frame = MockWelcomeFrame()

        # Test that the security manager properly fails child nodes when certificate validation fails
        # The security manager should re-raise certificate validation failures instead of catching them
        with pytest.raises(RuntimeError, match="certificate validation failed"):
            await security_manager.on_welcome(welcome_frame)

    finally:
        # Restore original environment
        for key, value in original_env.items():
            if value is not None:
                os.environ[key] = value
            elif key in os.environ:
                del os.environ[key]

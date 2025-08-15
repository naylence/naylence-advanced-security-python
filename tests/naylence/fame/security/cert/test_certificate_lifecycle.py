#!/usr/bin/env python3
"""
Test script to demonstrate the new lifecycle-aware certificate generation
that solves the timing issues with node context dependencies.
"""


def test_certificate_lifecycle():
    """Test the certificate lifecycle with proper node context and external CA flow."""

    from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider
    from naylence.fame.util.util import secure_digest

    print("=== Testing Certificate Lifecycle Management ===\n")

    # 1. Create crypto provider (no certificate generated yet)
    print("1. Creating CryptoProvider (before node context)...")
    crypto = DefaultCryptoProvider()

    print(f"   ✓ Signature key ID: {crypto.signature_key_id}")
    print(f"   ✓ Has node context: {crypto.has_node_context()}")
    print(f"   ✓ Certificate available: {crypto.node_certificate_pem() is not None}")

    assert not crypto.has_node_context(), "Should not have node context initially"
    assert crypto.node_certificate_pem() is None, "Should not have certificate initially"

    # 2. Set node context (no automatic certificate generation)
    print("\n2. Setting node context...")
    node_id = "test-node-123"
    physical_path = "/us-east-1/rack-42/node-123"
    logicals = ["node-123.agents.us-east-1", "node-123.compute.us-east-1"]

    crypto.set_node_context(node_id, physical_path, logicals)

    print(f"   ✓ Node ID: {node_id}")
    print(f"   ✓ Physical path: {physical_path}")
    print(f"   ✓ Logicals: {logicals}")
    print(f"   ✓ Has node context: {crypto.has_node_context()}")
    print(f"   ✓ Certificate available: {crypto.node_certificate_pem() is not None}")

    assert crypto.has_node_context(), "Should have node context after setting"
    # Note: No automatic certificate generation anymore - use CA service flow
    assert crypto.node_certificate_pem() is None, "Should not auto-generate certificate (use CA service)"

    # 3. Simulate CA service flow - create CSR and store certificate
    print("\n3. Simulating CA service flow...")

    # Create CSR (part of CA service flow)
    csr_pem = crypto.create_csr(node_id=node_id, physical_path=physical_path, logicals=logicals)
    print(f"   ✓ CSR created: {len(csr_pem)} bytes")

    # For testing, create a simple test certificate and store it
    # In real scenarios, this would come from the CA service
    try:
        from naylence.fame.security.cert.ca_service import CASigningService, create_test_ca

        # Create test CA and sign certificate
        root_cert_pem, root_key_pem = create_test_ca()
        ca_service = CASigningService(root_cert_pem, root_key_pem)

        node_sid = secure_digest(physical_path)
        cert_pem = ca_service.sign_node_cert(
            public_key_pem=crypto.signing_public_pem,
            node_id=node_id,
            node_sid=node_sid,
            physical_path=physical_path,
            logicals=logicals,
        )

        # Store the signed certificate
        crypto.store_signed_certificate(cert_pem)
        print(f"   ✓ Certificate signed and stored via CA service: {len(cert_pem)} bytes")

    except ImportError:
        # Fallback: create a simple test certificate for testing
        test_cert_pem = """-----BEGIN CERTIFICATE-----
MIIBOzCB5qADAgECAhBnZL8A/RcL5LEE3xBl1OwCMAUGAytlcDATMREwDwYDVQQD
DAhUZXN0IENlcnQwHhcNMjQwNzA4MDAwMDAwWhcNMjQwNzA5MDAwMDAwWjATMREw
DwYDVQQDDAhUZXN0IENlcnQwKjAFBgMrZXADIQAzN2QsP3zOGKJYhOcZMiQCZBvp
X9FE9cjyGzNGQZpB6aNQME4wHQYDVR0OBBYEFM7w5hYbZ2R9Bm7oQq7w0oAbfzYJ
MB8GA1UdIwQYMBaAFM7w5hYbZ2R9Bm7oQq7w0oAbfzYJMAwGA1UdEwQFMAMBAf8w
BQYDK2VwA0EAkUz8w4jO2E7I5oP9oGWKn4j7U8mOkR0f5N3zE1yBhBQoGVlQ7sEL
5L9Rv5K1g2gY6L8sL1qE5bF5q7D2mO2L5g==
-----END CERTIFICATE-----"""
        crypto.store_signed_certificate(test_cert_pem)
        print(f"   ✓ Test certificate stored: {len(test_cert_pem)} bytes")

    # 4. Verify certificate context and content
    print("\n4. Verifying certificate content...")
    cert_pem = crypto.node_certificate_pem()
    context = crypto.get_certificate_context()

    assert context is not None, "Should have certificate context"
    assert context["node_id"] == node_id, "Context should contain correct node ID"
    assert context["physical_path"] == physical_path, "Context should contain correct physical path"
    assert context["logicals"] == logicals, "Context should contain correct logicals"
    assert cert_pem is not None, "Should have certificate after CA service flow"

    # Verify SID calculation
    expected_sid = secure_digest(physical_path)
    assert context["node_sid"] == expected_sid, (
        f"SID should be calculated from physical path: {expected_sid}"
    )

    print(f"   ✓ Node ID in context: {context['node_id']}")
    print(f"   ✓ Physical path in context: {context['physical_path']}")
    print(f"   ✓ Node SID: {context['node_sid']}")
    print(f"   ✓ Certificate length: {len(cert_pem)} bytes")

    # 4. Test certificate in JWK format
    print("\n4. Testing certificate-enabled JWK...")
    node_jwk = crypto.node_jwk()

    assert "kid" in node_jwk, "JWK should have key ID"
    assert "x5c" in node_jwk, "JWK should have certificate chain"
    assert len(node_jwk["x5c"]) > 0, "Should have at least one certificate in chain"

    print(f"   ✓ JWK kid: {node_jwk['kid']}")
    print(f"   ✓ JWK has x5c: {'x5c' in node_jwk}")
    print(f"   ✓ Certificate chain length: {len(node_jwk['x5c'])}")

    # 5. Test certificate SID extraction
    print("\n5. Testing certificate SID extraction...")
    try:
        from cryptography import x509

        from naylence.fame.security.cert.util import sid_from_cert

        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        extracted_sid = sid_from_cert(cert)

        print(f"   ✓ Extracted SID from certificate: {extracted_sid}")
        assert extracted_sid == expected_sid, f"Certificate SID should match calculated SID: {expected_sid}"

    except ImportError:
        print("   ⚠ Cryptography not available, skipping SID extraction test")

    print("\n✅ Certificate lifecycle test passed!")


def test_direct_attach_scenario():
    """Test the direct attach scenario where certificate must be generated before handshake."""

    from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider
    from naylence.fame.util.util import secure_digest

    print("=== Testing Direct Attach Certificate Scenario ===\n")

    # Scenario: Child node wants to attach directly to a parent
    parent_physical_path = "/us-east-1/sentinel"
    child_logicals = ["worker-node.workers.us-east-1"]

    print("1. Creating child node crypto provider...")
    child_crypto = DefaultCryptoProvider()
    child_id = child_crypto.signature_key_id

    # In real scenarios, the child physical path would come from the welcome frame
    # For this test, we'll compute it as parent_path + "/" + child_id
    child_physical_path = f"{parent_physical_path.rstrip('/')}/{child_id}"

    print(f"   ✓ Child node ID: {child_id}")
    print(f"   ✓ Parent physical path: {parent_physical_path}")
    print(f"   ✓ Child physical path: {child_physical_path}")
    print(f"   ✓ Child logicals: {child_logicals}")

    # 2. Prepare for direct attach (this happens before NodeAttachFrame)
    print("\n2. Preparing certificate for direct attach...")
    child_crypto.prepare_for_attach(child_id, child_physical_path, child_logicals)

    # 3. Since self-signing is removed, manually provision certificate via CA service
    print("\n3. Provisioning certificate via CA service...")
    from naylence.fame.security.cert.ca_service import CASigningService, create_test_ca

    # Create CA service for testing
    ca_cert_pem, ca_key_pem = create_test_ca()
    ca_service = CASigningService(ca_cert_pem, ca_key_pem)

    # Sign certificate for the child node
    cert_pem = ca_service.sign_node_cert(
        public_key_pem=child_crypto.signing_public_pem,
        node_id=child_id,
        node_sid=secure_digest(child_physical_path),
        physical_path=child_physical_path,
        logicals=child_logicals,
    )

    # Store certificate
    child_crypto.store_signed_certificate(cert_pem)

    context = child_crypto.get_certificate_context()
    expected_child_sid = secure_digest(child_physical_path)

    print(f"   ✓ Child physical path: {child_physical_path}")
    print(f"   ✓ Computed child SID: {expected_child_sid}")
    print(f"   ✓ Has certificate: {child_crypto.node_certificate_pem() is not None}")

    assert context is not None, "Should have certificate context"
    assert context["node_id"] == child_id, "Should use child ID as node ID"
    assert context["physical_path"] == child_physical_path, "Should use provided child path"
    assert context["node_sid"] == expected_child_sid, "Should compute correct SID"

    # 4. Simulate sending certificate in NodeAttachFrame
    print("\n4. Simulating NodeAttachFrame with certificate...")
    node_jwk = child_crypto.node_jwk()

    # This JWK would be included in NodeAttachFrame.keys
    assert "x5c" in node_jwk, "JWK should include certificate for direct attach"
    print("   ✓ Certificate ready for NodeAttachFrame")
    print(f"   ✓ JWK kid: {node_jwk['kid']}")
    print(f"   ✓ Has x5c certificate: {'x5c' in node_jwk}")

    print("\n✅ Direct attach certificate scenario test passed!")


def test_certificate_lifecycle_with_multiple_providers():
    """Test that multiple crypto providers can share the same CA but have different certificates."""

    from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider

    print("=== Testing Multiple Providers with Shared CA ===\n")

    # Create multiple providers
    node1_crypto = DefaultCryptoProvider()
    node2_crypto = DefaultCryptoProvider()

    print("1. Created two crypto providers...")
    print(f"   ✓ Node 1 key ID: {node1_crypto.signature_key_id}")
    print(f"   ✓ Node 2 key ID: {node2_crypto.signature_key_id}")

    # Set different contexts
    node1_crypto.set_node_context("node-1", "/datacenter/rack-1/node-1", ["/region-1/service-a"])
    node2_crypto.set_node_context("node-2", "/datacenter/rack-2/node-2", ["/region-1/service-b"])

    print("\n2. Set different node contexts...")

    # 3. Provision certificates via CA service
    print("\n3. Provisioning certificates via CA service...")
    from naylence.fame.security.cert.ca_service import CASigningService, create_test_ca
    from naylence.fame.util.util import secure_digest

    # Create shared CA service for testing
    ca_cert_pem, ca_key_pem = create_test_ca()
    ca_service = CASigningService(ca_cert_pem, ca_key_pem)

    # Sign certificate for node 1
    cert1_pem = ca_service.sign_node_cert(
        public_key_pem=node1_crypto.signing_public_pem,
        node_id="node-1",
        node_sid=secure_digest("/datacenter/rack-1/node-1"),
        physical_path="/datacenter/rack-1/node-1",
        logicals=["service-a.region-1"],
    )
    node1_crypto.store_signed_certificate(cert1_pem)

    # Sign certificate for node 2
    cert2_pem = ca_service.sign_node_cert(
        public_key_pem=node2_crypto.signing_public_pem,
        node_id="node-2",
        node_sid=secure_digest("/datacenter/rack-2/node-2"),
        physical_path="/datacenter/rack-2/node-2",
        logicals=["service-b.region-1"],
    )
    node2_crypto.store_signed_certificate(cert2_pem)

    # Get certificates
    cert1 = node1_crypto.node_certificate_pem()
    cert2 = node2_crypto.node_certificate_pem()
    jwk1 = node1_crypto.node_jwk()
    jwk2 = node2_crypto.node_jwk()

    assert cert1 is not None, "Node 1 should have certificate"
    assert cert2 is not None, "Node 2 should have certificate"
    assert cert1 != cert2, "Certificates should be different"
    assert jwk1["kid"] != jwk2["kid"], "Key IDs should be different"

    print(f"   ✓ Node 1 certificate: {len(cert1)} bytes")
    print(f"   ✓ Node 2 certificate: {len(cert2)} bytes")
    print(f"   ✓ Certificates are different: {cert1 != cert2}")

    # Verify they can use the same CA for verification
    try:
        from cryptography import x509

        from naylence.fame.security.cert.util import logicals_from_cert, sid_from_cert

        cert1_obj = x509.load_pem_x509_certificate(cert1.encode())
        cert2_obj = x509.load_pem_x509_certificate(cert2.encode())

        sid1 = sid_from_cert(cert1_obj)
        sid2 = sid_from_cert(cert2_obj)
        paths1 = logicals_from_cert(cert1_obj)
        paths2 = logicals_from_cert(cert2_obj)

        print("\n3. Certificate verification...")
        print(f"   ✓ Node 1 SID: {sid1}")
        print(f"   ✓ Node 2 SID: {sid2}")
        print(f"   ✓ Node 1 logicals: {paths1}")
        print(f"   ✓ Node 2 logicals: {paths2}")

        assert sid1 != sid2, "SIDs should be different"
        assert paths1 != paths2, "Logicals should be different"

    except ImportError:
        print("   ⚠ Cryptography not available, skipping certificate verification")

    print("\n✅ Multiple providers test passed!")


def main():
    """Run all tests."""
    try:
        print("Testing Lifecycle-Aware Certificate Generation\n")

        # Run tests
        test_certificate_lifecycle()
        print("\n" + "=" * 60 + "\n")
        test_direct_attach_scenario()
        print("\n" + "=" * 60 + "\n")
        test_certificate_lifecycle_with_multiple_providers()

        print("\n🎉 All certificate lifecycle tests passed!")
        print("✅ Certificate generation is now properly aligned with node lifecycle")
        print("✅ Direct attach scenarios are supported")
        print("✅ Multiple nodes can share CA while having unique certificates")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return False

    return True


if __name__ == "__main__":
    import sys

    success = main()
    sys.exit(0 if success else 1)

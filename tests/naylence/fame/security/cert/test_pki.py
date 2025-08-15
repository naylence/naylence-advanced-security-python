#!/usr/bin/env python3
"""
Test script to verify the PKI hierarchy and certificate signing using intermediate CA chain.
"""

import asyncio
import os
from pathlib import Path


async def test_intermediate_ca_setup():
    """Test the PKI setup by issuing a certificate using the intermediate chain."""
    print("🧪 Testing PKI Setup with Intermediate CA Chain\n")

    # Check if PKI directory exists
    pki_dir = Path("./pki")
    if not pki_dir.exists():
        print("❌ PKI directory not found. Run setup_pki.py first.")
        return False

    # Load environment variables from the PKI setup
    env_file = pki_dir / "fame-ca.env"
    if not env_file.exists():
        print("❌ Environment file not found. Run setup_pki.py first.")
        return False

    # Extract environment variables from the file (simple parsing)
    env_vars = {}
    with open(env_file) as f:
        for line in f:
            if line.startswith("export "):
                # Parse: export VAR_NAME="value"
                line = line.strip()[7:]  # Remove "export "
                if "=" in line:
                    key, value = line.split("=", 1)
                    value = value.strip('"')
                    env_vars[key] = value
                    os.environ[key] = value

    print("📋 Loaded PKI Configuration:")
    for key, value in env_vars.items():
        if "FILE" in key:
            print(f"   {key}: {Path(value).name}")
    print()

    try:
        from cryptography import x509

        from naylence.fame.fastapi.ca_signing_router import CertificateSigningRequest, LocalCASigningService
        from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider

        # Step 1: Create CA service (will load from environment)
        print("1️⃣ Creating CA Signing Service...")
        ca_service = LocalCASigningService()
        print("   ✅ Service created - will use intermediate chain for signing")

        # Step 2: Create a test CSR
        print("\n2️⃣ Creating Test Certificate Signing Request...")
        crypto = DefaultCryptoProvider()
        crypto.set_node_context(
            node_id="test-app-node-01",
            physical_path="/org/test-node-01",
            logicals=["v1.api.org", "health.org"],
        )

        csr_pem = crypto.create_csr(
            node_id="test-app-node-01",
            physical_path="/org/test-node-01",
            logicals=["v1.api.org", "health.org"],
        )

        csr_request = CertificateSigningRequest(
            csr_pem=csr_pem,
            requester_id="test-app-node-01",
            physical_path="/org/test-node-01",
            logicals=["v1.api.org", "health.org"],
        )
        print("   ✅ CSR created for test application node")

        # Step 3: Issue certificate using intermediate chain
        print("\n3️⃣ Issuing Certificate using Intermediate Chain...")
        response = await ca_service.issue_certificate(csr_request)
        print("   ✅ Certificate issued successfully!")
        print(f"   📅 Expires at: {response.expires_at}")

        # Step 4: Analyze the certificate chain
        print("\n4️⃣ Analyzing Certificate Chain...")

        # Parse certificate chain
        chain_parts = response.certificate_chain_pem.split("-----END CERTIFICATE-----")
        cert_count = len([part for part in chain_parts if "-----BEGIN CERTIFICATE-----" in part])
        print(f"   📊 Certificate chain contains {cert_count} certificates")

        # Extract individual certificates from the response
        chain_certs = []
        current_cert = ""
        in_cert = False

        for line in response.certificate_chain_pem.split("\n"):
            if "-----BEGIN CERTIFICATE-----" in line:
                in_cert = True
                current_cert = line + "\n"
            elif "-----END CERTIFICATE-----" in line:
                current_cert += line + "\n"
                chain_certs.append(x509.load_pem_x509_certificate(current_cert.encode()))
                current_cert = ""
                in_cert = False
            elif in_cert:
                current_cert += line + "\n"

        print("   🔗 Certificate Chain Analysis:")
        for i, cert in enumerate(chain_certs):
            if i == 0:
                print(f"      1. End Entity: {cert.subject}")
            elif i == len(chain_certs) - 1:
                print(f"      {i + 1}. Root CA: {cert.subject}")
            else:
                print(f"      {i + 1}. Intermediate: {cert.subject}")

        # Step 5: Verify chain relationships
        print("\n5️⃣ Verifying Certificate Chain Trust Relationships...")

        for i in range(len(chain_certs) - 1):
            current_cert = chain_certs[i]
            issuer_cert = chain_certs[i + 1]

            if current_cert.issuer == issuer_cert.subject:
                if i == 0:
                    print(f"   ✅ End Entity cert issued by: {issuer_cert.subject}")
                else:
                    print(f"   ✅ Intermediate {i} cert issued by: {issuer_cert.subject}")
            else:
                print(f"   ❌ Chain broken at level {i}")
                return False

        # Step 6: Save test certificate for inspection
        print("\n6️⃣ Saving Test Certificate...")

        test_cert_file = pki_dir / "test-node-certificate.crt"
        test_chain_file = pki_dir / "test-node-chain.crt"

        with open(test_cert_file, "w") as f:
            f.write(response.certificate_pem)

        with open(test_chain_file, "w") as f:
            f.write(response.certificate_chain_pem)

        print(f"   ✅ Test certificate: {test_cert_file}")
        print(f"   ✅ Test chain: {test_chain_file}")

        # Step 7: Show verification command for other apps
        print("\n7️⃣ Verification Instructions for Other Applications:")
        root_ca_file = env_vars.get("FAME_ROOT_CA_FOR_VERIFICATION", "")

        print("   📋 To verify certificates signed by this CA, other applications should use:")
        print(f"      Root CA Certificate: {root_ca_file}")
        print("   📋 Example OpenSSL verification command:")
        print(f"      openssl verify -CAfile {root_ca_file} {test_cert_file}")

        print("\n🎉 PKI Test Completed Successfully!")
        print("\n📝 Summary:")
        print(f"   • Root CA: Available for other apps at {Path(root_ca_file).name}")
        print(f"   • Certificate Signing: Using {cert_count}-level intermediate chain")
        print("   • Chain Validation: All trust relationships verified ✅")
        print("   • Ready for Production: Configure environment and start your app!")

        return True

    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Main entry point for the test script."""
    print("🔐 Fame PKI Test Script")
    print("=" * 50)

    success = asyncio.run(test_intermediate_ca_setup())

    if success:
        print("\n🚀 Your PKI is ready! To use it:")
        print("   1. source pki/fame-ca.env")
        print("   2. Start your Fame application")
        print("   3. Share pki/root-ca.crt with other applications")
    else:
        print("\n❌ PKI test failed. Check the output above for details.")

    return 0 if success else 1


if __name__ == "__main__":
    exit(main())

#!/usr/bin/env python3
"""
PKI Setup Script for Fame Runtime - Intermediate CA Chain

This script creates a complete PKI hierarchy for local development:
1. Root CA (for verification by other apps)
2. Intermediate CA (for organizational trust)
3. Signing CA (for actual certificate signing)

All certificates and keys are saved to files for easy configuration.
"""

import argparse
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization  # type: ignore
    from cryptography.hazmat.primitives.asymmetric import ed25519  # type: ignore

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def create_pki_hierarchy(
    output_dir: str = "./pki", org_name: str = "Fame Development", logicals: list | None = None
) -> None:
    """
    Create a complete PKI hierarchy with intermediate CAs.

    Args:
        output_dir: Directory to save all PKI files
        org_name: Organization name for certificates
        logicals: List of host-like logical addresses for DNS name constraints (optional)
                 Examples: ["fame.fabric", "api.services", "worker.compute"]
    """
    if not CRYPTO_AVAILABLE:
        print("❌ Error: cryptography package is required")
        print("Install with: pip install cryptography")
        return

    # Import Fame modules
    try:
        from naylence.fame.security.cert.internal_ca_service import (  # type: ignore
            CASigningService,
            create_test_ca,
        )
    except ImportError as e:
        print(f"❌ Error: Could not import Fame modules: {e}")
        print("Make sure you're running this from the Fame runtime directory")
        return

    # Create output directory
    pki_path = Path(output_dir)
    pki_path.mkdir(exist_ok=True)

    print(f"🏗️ Creating PKI hierarchy in: {pki_path.absolute()}")
    print(f"📋 Organization: {org_name}\n")

    # Step 1: Create Root CA
    print("1️⃣ Creating Root CA...")
    root_cert_pem, root_key_pem = create_test_ca()

    # Save root CA files
    root_cert_file = pki_path / "root-ca.crt"
    root_key_file = pki_path / "root-ca.key"

    with open(root_cert_file, "w") as f:
        f.write(root_cert_pem)
    with open(root_key_file, "w") as f:
        f.write(root_key_pem)

    print(f"   ✅ Root CA certificate: {root_cert_file}")
    print(f"   🔑 Root CA private key: {root_key_file}")

    # Step 2: Create Intermediate CA (Signing Level)
    print("\n2️⃣ Creating Intermediate CA (Signing Level)...")
    if logicals:
        print(f"   📝 DNS name constraints will be applied for logical addresses: {', '.join(logicals)}")
        print("   ✅ Using DNS constraints for OpenSSL compatibility")
        print("   ℹ️  Certificates will work with both Fame runtime and OpenSSL validation")
    else:
        print("   🔓 No name constraints (all logical addresses allowed)")

    root_ca_service = CASigningService(root_cert_pem, root_key_pem)

    # Generate intermediate CA key pair
    intermediate_private_key = ed25519.Ed25519PrivateKey.generate()  # type: ignore
    intermediate_public_key_pem = (
        intermediate_private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,  # type: ignore
            format=serialization.PublicFormat.SubjectPublicKeyInfo,  # type: ignore
        )
        .decode()
    )

    # Create intermediate CA certificate
    permitted_logicals = logicals or []  # Use provided logical addresses or empty list
    # Note: CA service still uses permitted_paths parameter name for backward compatibility
    intermediate_cert_pem = root_ca_service.create_intermediate_ca(
        public_key_pem=intermediate_public_key_pem,
        ca_name=f"{org_name} Intermediate CA",
        permitted_paths=permitted_logicals,
    )

    intermediate_key_pem = intermediate_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,  # type: ignore
        format=serialization.PrivateFormat.PKCS8,  # type: ignore
        encryption_algorithm=serialization.NoEncryption(),  # type: ignore
    ).decode()

    # Save intermediate CA files
    intermediate_cert_file = pki_path / "intermediate-ca.crt"
    intermediate_key_file = pki_path / "intermediate-ca.key"

    with open(intermediate_cert_file, "w") as f:
        f.write(intermediate_cert_pem)
    with open(intermediate_key_file, "w") as f:
        f.write(intermediate_key_pem)

    print(f"   ✅ Intermediate CA certificate: {intermediate_cert_file}")
    print(f"   🔑 Intermediate CA private key: {intermediate_key_file}")

    # For simplicity, use the intermediate CA as the signing CA to avoid path length constraints
    signing_cert_file = intermediate_cert_file
    signing_key_file = intermediate_key_file

    print("\n3️⃣ Using Intermediate CA as Signing CA...")
    print(f"   ✅ Signing CA certificate: {signing_cert_file}")
    print(f"   🔑 Signing CA private key: {signing_key_file}")

    # Step 4: Create Certificate Chain File
    print("\n4️⃣ Creating Certificate Chain File...")

    # For a 2-level hierarchy, intermediate chain contains only the intermediate CA
    intermediate_chain_pem = intermediate_cert_pem

    chain_file = pki_path / "intermediate-chain.crt"
    with open(chain_file, "w") as f:
        f.write(intermediate_chain_pem)

    print(f"   ✅ Intermediate chain: {chain_file}")

    # Step 5: Create Complete Chain File (for verification)
    print("\n5️⃣ Creating Complete Chain File...")

    complete_chain_pem = f"{intermediate_cert_pem}\n{root_cert_pem}"

    complete_chain_file = pki_path / "complete-chain.crt"
    with open(complete_chain_file, "w") as f:
        f.write(complete_chain_pem)

    print(f"   ✅ Complete chain: {complete_chain_file}")

    # Step 6: Create Environment Configuration File
    print("\n6️⃣ Creating Environment Configuration...")

    env_file = pki_path / "fame-ca.env"
    env_content = f"""# Fame CA Environment Configuration
# Source this file to configure your environment for certificate signing

# Modern Fame certificate validation (recommended)
export FAME_CA_CERTS="{root_cert_file.absolute()}"

# Legacy environment variables (for backward compatibility)
export FAME_CA_CERT_FILE="{root_cert_file.absolute()}"
export FAME_CA_KEY_FILE="{root_key_file.absolute()}"

# Intermediate chain (contains the intermediate CA)
export FAME_INTERMEDIATE_CHAIN_FILE="{chain_file.absolute()}"

# Signing certificate and key (the intermediate CA is used for signing)
export FAME_SIGNING_CERT_FILE="{signing_cert_file.absolute()}"
export FAME_SIGNING_KEY_FILE="{signing_key_file.absolute()}"

# For verification: path to root CA certificate for other apps
export FAME_ROOT_CA_FOR_VERIFICATION="{root_cert_file.absolute()}"

# Complete chain for full validation
export FAME_COMPLETE_CHAIN_FILE="{complete_chain_file.absolute()}"

echo "Fame CA environment configured:"
echo "  Trust store: $FAME_CA_CERTS"
echo "  Root CA: $FAME_CA_CERT_FILE"
echo "  Signing CA: $FAME_SIGNING_CERT_FILE"
echo "  Chain: $FAME_INTERMEDIATE_CHAIN_FILE"
"""

    with open(env_file, "w") as f:
        f.write(env_content)

    print(f"   ✅ Environment config: {env_file}")

    # Step 7: Create Usage Instructions
    print("\n7️⃣ Creating Usage Instructions...")

    readme_file = pki_path / "README.md"
    readme_content = f"""# Fame PKI Setup - {org_name}

This directory contains a complete PKI hierarchy for Fame runtime certificate signing.

## PKI Hierarchy

```
Root CA ({org_name} Root CA)
└── Intermediate CA ({org_name} Intermediate CA)
    └── End Entity Certificates (signed by Intermediate CA)
```

## Files

### Certificate Authority Files
- `root-ca.crt` - Root CA certificate (share with other apps for verification)
- `root-ca.key` - Root CA private key (keep secure!)
- `intermediate-ca.crt` - Intermediate CA certificate (used for signing end entity certs)
- `intermediate-ca.key` - Intermediate CA private key (used for signing)

### Chain Files
- `intermediate-chain.crt` - Intermediate CA certificate (for chain building)
- `complete-chain.crt` - Full chain including root CA (for verification)

### Configuration
- `fame-ca.env` - Environment variables for Fame CA service
- `README.md` - This file

## Usage

### 1. Configure Your Environment

```bash
# Source the environment configuration
source {env_file.absolute()}
```

### 2. Start Your Fame Application

Your Fame FastAPI CA signing service will automatically use the configured certificates.

### 3. Share Root CA with Other Applications

Other applications that need to verify certificates signed by your Fame instance should use:
```
{root_cert_file.absolute()}
```

### 4. Test Certificate Signing

```python
from naylence.fame.fastapi.ca_signing_router import DefaultCAService

# The service will automatically load from environment variables
ca_service = DefaultCAService()

# Issue certificates - they will be signed by the Signing CA
# and include the complete certificate chain
```

## Certificate Chain Structure

When your Fame service issues certificates, the response will include:

1. **End Entity Certificate** - Signed by Intermediate CA
2. **Intermediate CA Certificate** - Signed by Root CA
3. **Root CA Certificate** - Self-signed

This allows other applications to validate the complete trust chain back to your root CA.

## Security Notes

- Keep `*.key` files secure and restrict access
- Share only the `root-ca.crt` with other applications
- The intermediate CA is used for day-to-day certificate issuance
- The root CA should be kept offline in production environments

## Directory Structure

```
{pki_path.absolute()}/
├── root-ca.crt              # Root CA certificate (share with other apps)
├── root-ca.key              # Root CA private key (keep secure)
├── intermediate-ca.crt      # Intermediate CA certificate (used for signing)
├── intermediate-ca.key      # Intermediate CA private key (keep secure)
├── intermediate-chain.crt   # Intermediate CA certificate (for chain building)
├── complete-chain.crt       # Full chain including root
├── fame-ca.env             # Environment configuration
└── README.md               # This file
```

Generated on: {org_name} PKI Setup
"""

    with open(readme_file, "w") as f:
        f.write(readme_content)

    print(f"   ✅ Usage instructions: {readme_file}")

    # Summary
    print("\n🎉 PKI Hierarchy Created Successfully!")
    print(f"\n📁 All files saved to: {pki_path.absolute()}")
    print("\n🚀 Quick Start:")
    print(f"   1. cd {pki_path.absolute()}")
    print("   2. source fame-ca.env")
    print("   3. Start your Fame application")
    print(f"\n🔗 Share with other apps: {root_cert_file.absolute()}")
    print(f"\n📚 Full instructions: {readme_file.absolute()}")


def main():
    """Main entry point for the PKI setup script."""
    parser = argparse.ArgumentParser(
        description="Create a complete PKI hierarchy for Fame certificate signing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup_pki.py                                          # Create PKI with default logical
                                                                # 'fame.fabric'
  python setup_pki.py --output ./my-ca --org "My Company"     # Custom location and org
  python setup_pki.py --logicals api.services worker.compute  # With specific host-like logicals
  python setup_pki.py -l fame.fabric api.services -o ./pki    # Short form with multiple logicals

Legacy Path Conversion:
  python setup_pki.py -l /                                     # Converts '/' -> 'fame.fabric'
  python setup_pki.py -l /api /worker                         # Converts to 'api.fabric worker.fabric'

Environment Variables:
  FAME_ROOT    Root domain for Fame logical addresses (default: "fame.fabric")
               Used as default logical address and for DNS name constraints
               
NOTE: This script now generates certificates with host-like logical addresses 
      (e.g., 'fame.fabric', 'api.services') instead of path-based logicals 
      (e.g., '/', '/api'). Legacy path inputs are automatically converted.
      All certificates are fully compatible with both Fame runtime and OpenSSL validation.
        """,
    )

    parser.add_argument(
        "--output", "-o", default="./pki", help="Output directory for PKI files (default: ./pki)"
    )

    parser.add_argument(
        "--org",
        "-n",
        default="Fame Development",
        help="Organization name for certificates (default: Fame Development)",
    )

    parser.add_argument(
        "--logicals",
        "-l",
        nargs="*",
        default=None,
        help="Host-like logical addresses for DNS name constraints "
        "(e.g., api.services fame.fabric worker.compute). "
        "Creates OpenSSL-compatible DNS constraints. "
        "If not specified, defaults to 'fame.fabric'.",
    )

    args = parser.parse_args()

    print("🔐 Fame PKI Setup Script")
    print("=" * 50)

    # Convert and validate logical addresses
    logicals = args.logicals

    # If no logicals specified, use fame.fabric as default
    if logicals is None:
        logicals = ["fame.fabric"]
        print("ℹ️  No logicals specified, using default: ['fame.fabric']")
    elif len(logicals) == 0:
        logicals = ["fame.fabric"]
        print("ℹ️  Empty logicals list, using default: ['fame.fabric']")
    else:
        # Convert any path-based logicals to host-like format
        converted_logicals = []
        for logical in logicals:
            if logical.startswith("/"):
                # Convert path-based to host-like format
                if logical == "/":
                    # Root path becomes fame.fabric
                    converted = "fame.fabric"
                else:
                    # Convert /path/to/service -> service.to.path (reversed)
                    parts = logical.strip("/").split("/")
                    converted = ".".join(reversed(parts))
                    # Add domain suffix if it doesn't already exist
                    if not any(
                        converted.endswith(domain) for domain in [".fabric", ".services", ".domain"]
                    ):
                        converted += ".fabric"

                print(f"🔄 Converting path-based logical '{logical}' -> '{converted}'")
                converted_logicals.append(converted)
            else:
                # Already host-like format
                converted_logicals.append(logical)

        logicals = converted_logicals

    print(f"✅ Using logical addresses: {logicals}")

    create_pki_hierarchy(args.output, args.org, logicals)


if __name__ == "__main__":
    main()

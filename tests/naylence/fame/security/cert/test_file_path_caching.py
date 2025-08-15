#!/usr/bin/env python3
"""
Test certificate caching with file paths like the real application.
"""

import hashlib
import logging
import tempfile
from pathlib import Path

from naylence.fame.security.cert.certificate_cache import cache_stats, clear_cache
from naylence.fame.security.cert.util import public_key_from_x5c
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider

# Set up comprehensive logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")


def test_file_path_caching():
    """Test caching when using file paths instead of PEM content."""
    print("=== Testing File Path Based Caching ===")

    # Clear cache to start fresh
    clear_cache()
    print(f"Initial cache stats: {cache_stats()}")

    # Get crypto provider and set up node context
    crypto_provider = get_crypto_provider()

    # Set node context to enable certificate generation
    crypto_provider.set_node_context(
        node_id="test-file-cache-node",
        physical_path="/test/file-cache-path",
        logicals=["file-cache-logical.test"],
    )

    # Get the CA certificate and create a temporary file
    ca_cert_pem, ca_key_pem = crypto_provider._get_ca_credentials()
    if not ca_cert_pem:
        print("❌ No CA certificate available - cannot test")
        return

    # Get x5c from node certificate
    node_jwk = crypto_provider.node_jwk()
    if "x5c" not in node_jwk:
        print("❌ No x5c in node JWK - cannot test")
        return

    x5c = node_jwk["x5c"]
    print(f"Generated certificate chain with {len(x5c)} certificates")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Write CA certificate to a file
        ca_file = Path(temp_dir) / "ca_cert.pem"
        ca_file.write_text(ca_cert_pem)

        print(f"CA certificate file: {ca_file}")

        # Test 1: Multiple calls with same file path should hit cache
        print("\n--- Test 1: File path caching ---")

        for i in range(3):
            print(f"\nFile path call {i + 1}:")
            try:
                result = public_key_from_x5c(
                    x5c=x5c,
                    trust_store_pem=str(ca_file),  # File path, not PEM content
                    enforce_name_constraints=False,
                )
                print(f"Result type: {type(result)}")
                print(f"Cache stats: {cache_stats()}")
            except Exception as e:
                print(f"Error: {e}")

        # Test 2: Same content in different file should generate same cache key
        print("\n--- Test 2: Same content, different file path ---")

        ca_file_2 = Path(temp_dir) / "ca_cert_copy.pem"
        ca_file_2.write_text(ca_cert_pem)  # Same content, different path

        try:
            result = public_key_from_x5c(
                x5c=x5c,
                trust_store_pem=str(ca_file_2),  # Different file path, same content
                enforce_name_constraints=False,
            )
            print(f"Result type: {type(result)}")
            print(f"Cache stats: {cache_stats()}")
        except Exception as e:
            print(f"Error: {e}")

        # Test 3: Mix file path and PEM content
        print("\n--- Test 3: Mix file path and PEM content ---")

        try:
            result = public_key_from_x5c(
                x5c=x5c,
                trust_store_pem=ca_cert_pem,  # PEM content directly
                enforce_name_constraints=False,
            )
            print(f"Result type: {type(result)}")
            print(f"Cache stats: {cache_stats()}")
        except Exception as e:
            print(f"Error: {e}")


def test_cache_key_analysis():
    """Analyze cache key generation for debugging."""
    print("\n=== Cache Key Analysis ===")

    crypto_provider = get_crypto_provider()
    crypto_provider.set_node_context(
        node_id="test-analysis-node",
        physical_path="/test/analysis-path",
        logicals=["analysis-logical.test"],
    )

    ca_cert_pem, _ = crypto_provider._get_ca_credentials()
    x5c = crypto_provider.node_jwk()["x5c"]

    # Simulate what happens in different scenarios
    with tempfile.TemporaryDirectory() as temp_dir:
        ca_file = Path(temp_dir) / "ca.pem"
        ca_file.write_text(ca_cert_pem)

        # Scenario 1: File path
        chain_bytes = b"".join(cert.encode() for cert in x5c)
        trust_store_content = ca_file.read_bytes()
        trust_store_hash_file = hashlib.sha256(trust_store_content).digest()
        cache_key_file = b"||".join([chain_bytes, trust_store_hash_file])

        # Scenario 2: PEM content
        trust_store_hash_pem = hashlib.sha256(ca_cert_pem.encode("utf-8")).digest()
        cache_key_pem = b"||".join([chain_bytes, trust_store_hash_pem])

        print(f"Chain bytes length: {len(chain_bytes)}")
        print(f"Trust store hash (file content): {trust_store_hash_file.hex()[:16]}")
        print(f"Trust store hash (pem string): {trust_store_hash_pem.hex()[:16]}")
        print(f"Cache key hash (file): {hashlib.sha256(cache_key_file).hexdigest()[:16]}")
        print(f"Cache key hash (pem): {hashlib.sha256(cache_key_pem).hexdigest()[:16]}")

        # They should be the same if file content == PEM string
        if trust_store_hash_file == trust_store_hash_pem:
            print("✅ File content and PEM string produce same hash")
        else:
            print("❌ File content and PEM string produce different hashes")
            print(f"   File bytes: {len(trust_store_content)}")
            print(f"   PEM bytes: {len(ca_cert_pem.encode('utf-8'))}")


if __name__ == "__main__":
    test_file_path_caching()
    test_cache_key_analysis()
    print("\n=== File Path Test Complete ===")

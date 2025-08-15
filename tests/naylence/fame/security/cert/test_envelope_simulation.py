#!/usr/bin/env python3
"""
Test to simulate the exact scenario from the user's logs -
multiple envelope validations with the same certificate.
"""

import logging
import tempfile
from pathlib import Path

from naylence.fame.security.cert.certificate_cache import cache_stats, clear_cache
from naylence.fame.security.cert.util import public_key_from_x5c
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider

# Set up comprehensive logging to match application format
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)-8s] %(message)s")


def simulate_envelope_processing():
    """
    Simulate processing multiple envelopes with the same certificate,
    which is what happens in the real Fame runtime.
    """
    print("=== Simulating Multiple Envelope Processing ===")

    # Clear cache to start fresh
    clear_cache()
    print(f"Initial cache stats: {cache_stats()}")

    # Set up crypto provider and certificate
    crypto_provider = get_crypto_provider()
    crypto_provider.set_node_context(
        node_id="Oxn7YRD0Acc3rbK",  # Same node ID from user's logs
        physical_path="/test/envelope-path",
        logicals=["envelope-logical.test"],
    )

    # Get CA and node certificate
    ca_cert_pem, _ = crypto_provider._get_ca_credentials()
    node_jwk = crypto_provider.node_jwk()
    x5c = node_jwk["x5c"]

    # Create temporary trust store file like the real application
    with tempfile.TemporaryDirectory() as temp_dir:
        trust_store_file = Path(temp_dir) / "ca_trust_store.pem"
        trust_store_file.write_text(ca_cert_pem)

        print(f"Using trust store file: {trust_store_file}")
        print("Certificate serial from logs: 173519140657702405379323644843501938054869619772")
        print("Certificate kid from logs: Oxn7YRD0Acc3rbK")

        # Simulate processing multiple envelopes in rapid succession
        envelope_ids = ["FCbYyShYDirCm0r", "Jm11FDDYkOMDKyP", "zLeH3e9MEobfecM"]

        for i, envelope_id in enumerate(envelope_ids, 1):
            print(f"\n📨 Processing envelope {i}/3 (ID: {envelope_id})")
            print(f"   trace_id=l92280SmtAOFKF4 ctx_envp_id={envelope_id}")

            try:
                # This simulates the exact call made by eddsa_envelope_verifier.py
                public_key_from_x5c(
                    x5c=x5c,
                    trust_store_pem=str(trust_store_file),  # File path like in real app
                    enforce_name_constraints=False,
                    return_cert=False,
                )

                print("   ✅ Certificate validation completed")
                print(f"   📈 Cache stats: {cache_stats()}")

            except Exception as e:
                print(f"   ❌ Error: {e}")

        print(f"\n🎯 Final cache stats: {cache_stats()}")

        # Additional test: simulate the second validation path that happens
        # in the real application (inbound_signature_verified)
        print("\n📨 Simulating secondary validation path...")

        try:
            public_key_from_x5c(
                x5c=x5c,
                trust_store_pem=str(trust_store_file),
                enforce_name_constraints=False,
                return_cert=False,
            )

            print("   ✅ Secondary validation completed")
            print(f"   📈 Final cache stats: {cache_stats()}")

        except Exception as e:
            print(f"   ❌ Error: {e}")


def demonstrate_cache_effectiveness():
    """Show the cache effectiveness with clear metrics."""
    print("\n=== Cache Effectiveness Demonstration ===")

    # Clear and reset
    clear_cache()

    crypto_provider = get_crypto_provider()
    crypto_provider.set_node_context(
        node_id="demo-node", physical_path="/demo/path", logicals=["logical.demo"]
    )

    ca_cert_pem, _ = crypto_provider._get_ca_credentials()
    x5c = crypto_provider.node_jwk()["x5c"]

    with tempfile.TemporaryDirectory() as temp_dir:
        trust_store_file = Path(temp_dir) / "demo_ca.pem"
        trust_store_file.write_text(ca_cert_pem)

        validation_count = 10

        print(f"🔄 Performing {validation_count} identical certificate validations...")
        print("   (In the old code, this would trigger trust anchor validation each time)")
        print("   (With caching, only the first should trigger trust anchor validation)")

        for i in range(validation_count):
            public_key_from_x5c(
                x5c=x5c, trust_store_pem=str(trust_store_file), enforce_name_constraints=False
            )

            if i == 0:
                print("   1️⃣ First validation: Should see 'trust_anchor_validation_start'")
            elif i == 1:
                print("   2️⃣ Second validation: Should see cache HIT, no trust anchor validation")
            elif i == validation_count - 1:
                print(f"   🔟 Final validation ({i + 1}): Should still be cache HIT")

        print(f"\n✅ Completed {validation_count} validations")
        print(f"📊 Cache efficiency: {cache_stats()}")

        expected_cache_size = 1  # Should only have one entry for this cert/trust store combo
        actual_cache_size = cache_stats()["size"]

        if actual_cache_size == expected_cache_size:
            print(f"✅ Cache working optimally: {actual_cache_size} entry as expected")
        else:
            print(f"⚠️  Unexpected cache size: {actual_cache_size} (expected {expected_cache_size})")


if __name__ == "__main__":
    simulate_envelope_processing()
    demonstrate_cache_effectiveness()

    print("\n" + "=" * 50)
    print("🔍 DEBUGGING GUIDANCE:")
    print("=" * 50)
    print("Look in the debug logs above for:")
    print("✅ GOOD: 'Certificate cache HIT' messages (shows caching is working)")
    print("❌ BAD: Multiple 'trust_anchor_validation_start' for same cert")
    print("")
    print("The fix ensures:")
    print("• Same certificate + same trust store = cache HIT")
    print("• Different certificates = cache MISS (expected)")
    print("• File paths and PEM content produce same cache keys")
    print("• Trust anchor validation only happens once per unique cert/trust combo")

#!/usr/bin/env python3
"""
Test certificate validation optimization in EdDSAEnvelopeVerifier.

This test verifies that the optimized two-phase certificate handling:
1. Uses caching for trust validation (public key extraction)
2. Uses caching for certificate metadata extraction
3. Only fetches certificate when policy requires it
4. Provides significant performance improvement
"""

import os
import tempfile
import time

from naylence.fame.security.cert.util import get_certificate_metadata_from_x5c, public_key_from_x5c
from naylence.fame.security.policy.security_policy import SigningConfig
from naylence.fame.security.signing.eddsa_envelope_verifier import _load_public_key_from_jwk


def test_optimization_performance(create_test_cert_and_key, SigningMaterial):
    """Test that the optimization provides performance benefits."""
    print("=== Certificate Validation Optimization Test ===\n")

    # Create test certificate and CA
    print("Creating test certificate and CA...")
    x5c, ca_pem, leaf_cert = create_test_cert_and_key

    # Create temporary CA file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as ca_file:
        ca_file.write(ca_pem)
        ca_file_path = ca_file.name

    # Set FAME_CA_CERTS environment variable
    old_ca_certs = os.environ.get("FAME_CA_CERTS")
    os.environ["FAME_CA_CERTS"] = ca_file_path

    try:
        # Create test JWK
        jwk = {"kty": "RSA", "x5c": x5c, "sid": "test-node-123"}

        # Test configurations
        from naylence.fame.security.policy.security_policy import SigningMaterial

        configs = [
            (
                "No cert policy",
                SigningConfig(
                    signing_material=SigningMaterial.X509_CHAIN,
                    require_cert_sid_match=False,
                    require_cert_logical_match=False,
                , SigningMaterial),
            ),
            (
                "SID matching only",
                SigningConfig(
                    signing_material=SigningMaterial.X509_CHAIN,
                    require_cert_sid_match=True,
                    require_cert_logical_match=False,
                ),
            ),
            (
                "Full cert validation",
                SigningConfig(
                    signing_material=SigningMaterial.X509_CHAIN,
                    require_cert_sid_match=True,
                    require_cert_logical_match=True,
                ),
            ),
        ]

        for config_name, config in configs:
            print(f"\n--- Testing: {config_name} ---")

            # Clear any existing cache
            from naylence.fame.security.cert.certificate_cache import _TRUST_CACHE, _TRUST_LOCK

            with _TRUST_LOCK:
                _TRUST_CACHE.clear()

            # Warm up run
            print("Performing warm-up run...")
            result = _load_public_key_from_jwk(jwk, config)
            print(f"Warm-up result type: {type(result)}")

            # Performance test - multiple calls
            num_calls = 10
            print(f"Testing {num_calls} consecutive calls...")

            start_time = time.time()
            for i in range(num_calls):
                result = _load_public_key_from_jwk(jwk, config)
            end_time = time.time()

            total_time = end_time - start_time
            avg_time = total_time / num_calls

            print(f"Total time: {total_time:.4f}s")
            print(f"Average time per call: {avg_time:.4f}s")
            print(f"Calls per second: {1 / avg_time:.2f}")

            # Analyze result
            if isinstance(result, tuple):
                public_key, certificate = result
                print("Returned: (public_key, certificate)")

                # Extract metadata to verify it works
                from naylence.fame.security.cert.util import sid_from_cert

                sid = sid_from_cert(certificate)
                print(f"Certificate SID: {sid}")
            else:
                print("Returned: public_key only")

        print("\n=== Direct Function Comparison ===")

        # Compare old vs new approach directly
        print("\nOld approach (return_cert=True, bypasses cache):")

        # Clear cache
        from naylence.fame.security.cert.certificate_cache import _TRUST_CACHE, _TRUST_LOCK

        with _TRUST_LOCK:
            _TRUST_CACHE.clear()

        start_time = time.time()
        for i in range(5):
            pub_key, cert = public_key_from_x5c(x5c, trust_store_pem=ca_file_path, return_cert=True)
        old_time = time.time() - start_time
        print(f"5 calls with return_cert=True: {old_time:.4f}s ({old_time / 5:.4f}s per call)")

        print("\nNew approach (separate caching):")

        # Clear cache
        with _TRUST_LOCK:
            _TRUST_CACHE.clear()

        start_time = time.time()
        for i in range(5):
            # Phase 1: Get public key (cached)
            public_key_from_x5c(x5c, trust_store_pem=ca_file_path, return_cert=False)
            # Phase 2: Get metadata (cached separately)
            metadata = get_certificate_metadata_from_x5c(x5c, trust_store_pem=ca_file_path)
            metadata["certificate"]
        new_time = time.time() - start_time
        print(f"5 calls with separate functions: {new_time:.4f}s ({new_time / 5:.4f}s per call)")

        improvement = ((old_time - new_time) / old_time) * 100
        print(f"\nPerformance improvement: {improvement:.1f}%")
        print(f"Speedup factor: {old_time / new_time:.1f}x")

    finally:
        # Restore original environment variable
        if old_ca_certs is not None:
            os.environ["FAME_CA_CERTS"] = old_ca_certs
        else:
            os.environ.pop("FAME_CA_CERTS", None)

        # Clean up temp file
        os.unlink(ca_file_path)


def test_cache_analysis(create_test_cert_and_key):
    """Analyze cache behavior in detail."""
    print("\n=== Cache Behavior Analysis ===")

    # Enable detailed logging
    import logging

    logging.basicConfig(level=logging.DEBUG)

    # Create test data
    x5c, ca_pem, leaf_cert = create_test_cert_and_key

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as ca_file:
        ca_file.write(ca_pem)
        ca_file_path = ca_file.name

    # Set FAME_CA_CERTS environment variable
    old_ca_certs = os.environ.get("FAME_CA_CERTS")
    os.environ["FAME_CA_CERTS"] = ca_file_path

    try:
        print("\nTesting cache behavior with separate functions...")

        # Clear cache
        from naylence.fame.security.cert.certificate_cache import _TRUST_CACHE, _TRUST_LOCK

        with _TRUST_LOCK:
            _TRUST_CACHE.clear()
        print(f"Cache cleared. Size: {len(_TRUST_CACHE)}")

        # First call - should populate cache
        print("\n--- First call (cache miss expected) ---")
        pub_key = public_key_from_x5c(x5c, trust_store_pem=ca_file_path, return_cert=False)
        print(f"Cache size after public key call: {len(_TRUST_CACHE)}")

        metadata = get_certificate_metadata_from_x5c(x5c, trust_store_pem=ca_file_path)
        print(f"Cache size after metadata call: {len(_TRUST_CACHE)}")

        # Second call - should hit cache
        print("\n--- Second call (cache hit expected) ---")
        pub_key2 = public_key_from_x5c(x5c, trust_store_pem=ca_file_path, return_cert=False)
        metadata2 = get_certificate_metadata_from_x5c(x5c, trust_store_pem=ca_file_path)

        # Verify results are equivalent
        print(f"\nResults equivalent: {pub_key == pub_key2}")
        print(f"Metadata SID: {metadata['sid']} == {metadata2['sid']}")
        print(f"Metadata paths: {metadata['logicals']} == {metadata2['logicals']}")

    finally:
        # Restore original environment variable
        if old_ca_certs is not None:
            os.environ["FAME_CA_CERTS"] = old_ca_certs
        else:
            os.environ.pop("FAME_CA_CERTS", None)

        # Clean up temp file
        os.unlink(ca_file_path)


if __name__ == "__main__":
    test_optimization_performance()
    test_cache_analysis()
    print("\n=== Optimization Test Complete ===")

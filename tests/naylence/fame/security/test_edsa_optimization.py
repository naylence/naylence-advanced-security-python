import os
import tempfile


def test_eddsa_optimization(create_test_cert_and_key):
    """Test EdDSA envelope verifier with certificate optimization."""
    print("=== EdDSA Envelope Verifier Optimization Test ===\n")

    # Create test certificate and JWK
    x5c, ca_pem, leaf_cert = create_test_cert_and_key

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as ca_file:
        ca_file.write(ca_pem)
        ca_file_path = ca_file.name

    # Set FAME_CA_CERTS environment variable
    old_ca_certs = os.environ.get("FAME_CA_CERTS")
    os.environ["FAME_CA_CERTS"] = ca_file_path

    try:
        # Create test JWK
        jwk = {"kty": "RSA", "x5c": x5c, "sid": "test-node-123", "use": "sig"}

        from naylence.fame.security.policy.security_policy import SigningConfig, SigningMaterial
        from naylence.fame.security.signing.eddsa_envelope_verifier import _load_public_key_from_jwk

        # Test different signing configurations
        configs = [
            (
                "No cert validation",
                SigningConfig(
                    signing_material=SigningMaterial.X509_CHAIN,
                    require_cert_sid_match=False,
                    require_cert_logical_match=False,
                ),
            ),
            (
                "SID validation",
                SigningConfig(
                    signing_material=SigningMaterial.X509_CHAIN,
                    require_cert_sid_match=True,
                    require_cert_logical_match=False,
                ),
            ),
            (
                "Full validation",
                SigningConfig(
                    signing_material=SigningMaterial.X509_CHAIN,
                    require_cert_sid_match=True,
                    require_cert_logical_match=True,
                ),
            ),
        ]

        for config_name, config in configs:
            print(f"--- Testing: {config_name} ---")

            # Clear cache
            from naylence.fame.security.cert.certificate_cache import _TRUST_CACHE, _TRUST_LOCK

            with _TRUST_LOCK:
                _TRUST_CACHE.clear()

            print("First call (should populate cache):")
            result1 = _load_public_key_from_jwk(jwk, config)
            print(f"Result type: {type(result1)}")

            if isinstance(result1, tuple):
                pub_key, cert = result1
                print(f"  Public key: {type(pub_key)}")
                print(f"  Certificate: {type(cert)}")

                # Test certificate functions
                from naylence.fame.security.cert.util import sid_from_cert

                sid = sid_from_cert(cert)
                print(f"  SID: {sid}")
            else:
                print(f"  Public key only: {type(result1)}")

            with _TRUST_LOCK:
                cache_size_after_first = len(_TRUST_CACHE)
            print(f"Cache size after first call: {cache_size_after_first}")

            print("\nSecond call (should hit cache):")
            result2 = _load_public_key_from_jwk(jwk, config)

            with _TRUST_LOCK:
                cache_size_after_second = len(_TRUST_CACHE)
            print(f"Cache size after second call: {cache_size_after_second}")

            # Verify results are equivalent
            print(f"Results equivalent: {type(result1) is type(result2)}")

            if isinstance(result1, tuple) and isinstance(result2, tuple):
                pub1, cert1 = result1
                pub2, cert2 = result2
                print(f"Public keys equivalent: {pub1.public_numbers() == pub2.public_numbers()}")
                print(f"Certificates equivalent: {cert1.serial_number == cert2.serial_number}")
            elif not isinstance(result1, tuple) and not isinstance(result2, tuple):
                try:
                    print(f"Public keys equivalent: {result1.public_numbers() == result2.public_numbers()}") # type: ignore
                except AttributeError:
                    print(f"Public keys equivalent: {result1 == result2}")

            print()

    finally:
        # Restore original environment variable
        if old_ca_certs is not None:
            os.environ["FAME_CA_CERTS"] = old_ca_certs
        else:
            os.environ.pop("FAME_CA_CERTS", None)

        # Clean up temp file
        os.unlink(ca_file_path)

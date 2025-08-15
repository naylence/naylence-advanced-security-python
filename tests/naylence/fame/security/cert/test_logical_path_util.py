#!/usr/bin/env python3
"""
Test logical DNS hostname conversion and validation.

This test verifies the new logical utilities for DNS-compatible
certificate name constraints and OpenSSL validation.
"""

import pytest

from naylence.fame.util.logicals_util import (
    create_logical_uri,
    extract_logical_from_uri,
    get_fame_root,
    hostname_to_logical,
    logical_to_hostname,
    logicals_to_hostnames,
    validate_logical,
    validate_logical_segment,
)


class TestLogicalPathSegmentValidation:
    """Test individual path segment validation."""

    def test_valid_segments(self):
        """Test valid DNS-compatible segments."""
        valid_segments = [
            "p1",
            "path1",
            "node-123",
            "us-east-1",
            "worker-node",
            "a1b2c3",
            "123abc",
            "segment123",
            "api-v1",
        ]

        for segment in valid_segments:
            is_valid, error = validate_logical_segment(segment)
            assert is_valid, f"Segment '{segment}' should be valid: {error}"
            assert error is None

    def test_invalid_segments(self):
        """Test invalid segments."""
        invalid_segments = [
            "",  # Empty
            "-start",  # Starts with hyphen
            "end-",  # Ends with hyphen
            "mid--dle",  # Double hyphen
            "has.dot",  # Contains dot
            "has_under",  # Contains underscore
            "has/slash",  # Contains slash
            "has space",  # Contains space
            "a" * 64,  # Too long (>63 chars)
        ]

        for segment in invalid_segments:
            is_valid, error = validate_logical_segment(segment)
            assert not is_valid, f"Segment '{segment}' should be invalid"
            assert error is not None


class TestLogicalPathValidation:
    """Test complete logical validation."""

    def test_valid_paths(self):
        """Test valid logicals."""
        valid_paths = [
            "/",  # Root path - special case
            "/p1",
            "/p1/p2",
            "/p1/p2/p3",
            "/us-east-1/workers/node-123",
            "/api/v1/endpoints",
            "/datacenter1/rack42/node001",
        ]

        for path in valid_paths:
            is_valid, error = validate_logical(path)
            assert is_valid, f"Path '{path}' should be valid: {error}"

    def test_invalid_paths(self):
        """Test invalid logicals."""
        invalid_paths = [
            "",  # Empty
            "no-slash",  # Doesn't start with /
            "/-start",  # Segment starts with hyphen
            "/end-",  # Segment ends with hyphen
            "/has.dot",  # Contains dot
            "/has_under",  # Contains underscore
        ]

        for path in invalid_paths:
            is_valid, error = validate_logical(path)
            assert not is_valid, f"Path '{path}' should be invalid"


class TestPathHostnameConversion:
    """Test logical to hostname conversion."""

    def test_path_to_hostname_conversion(self):
        """Test converting paths to hostnames."""
        test_cases = [
            ("/", get_fame_root()),  # Special case: root path -> FAME_ROOT
            ("/p1", "p1"),
            ("/p1/p2", "p2.p1"),
            ("/p1/p2/p3", "p3.p2.p1"),
            ("/us-east-1/workers/node-123", "node-123.workers.us-east-1"),
        ]

        for path, expected_hostname in test_cases:
            hostname = logical_to_hostname(path)
            assert hostname == expected_hostname, f"Expected {expected_hostname}, got {hostname}"

    def test_hostname_to_path_conversion(self):
        """Test converting hostnames back to paths."""
        test_cases = [
            (get_fame_root(), "/"),  # Special case: FAME_ROOT hostname -> root path
            ("p1", "/p1"),
            ("p2.p1", "/p1/p2"),
            ("p3.p2.p1", "/p1/p2/p3"),
            ("node-123.workers.us-east-1", "/us-east-1/workers/node-123"),
        ]

        for hostname, expected_path in test_cases:
            path = hostname_to_logical(hostname)
            assert path == expected_path, f"Expected {expected_path}, got {path}"

    def test_roundtrip_conversion(self):
        """Test that path -> hostname -> path is identity."""
        test_paths = [
            "/",  # Root path special case
            "/p1",
            "/p1/p2",
            "/p1/p2/p3",
            "/us-east-1/workers/node-123",
            "/api/v1/endpoints",
        ]

        for original_path in test_paths:
            hostname = logical_to_hostname(original_path)
            converted_path = hostname_to_logical(hostname)
            assert converted_path == original_path, (
                f"Roundtrip failed: {original_path} -> {hostname} -> {converted_path}"
            )


class TestPathListConversion:
    """Test converting lists of paths."""

    def test_paths_to_hostnames(self):
        """Test converting multiple paths to hostnames."""
        paths = ["/p1/p2", "/q1/q2/q3", "/single"]
        expected = ["p2.p1", "q3.q2.q1", "single"]

        hostnames = logicals_to_hostnames(paths)
        assert hostnames == expected


class TestURICreation:
    """Test URI creation for certificates."""

    def test_create_path_notation_uri(self):
        """Test creating URIs in path notation."""
        test_cases = [("/", "naylence:///"), ("/p1/p2/p3", "naylence:///p1/p2/p3")]

        for path, expected_uri in test_cases:
            uri = create_logical_uri(path, use_hostname_notation=False)
            assert uri == expected_uri

    def test_create_hostname_notation_uri(self):
        """Test creating URIs in hostname notation."""
        test_cases = [("/", f"naylence://{get_fame_root()}/"), ("/p1/p2/p3", "naylence://p3.p2.p1/")]

        for path, expected_uri in test_cases:
            uri = create_logical_uri(path, use_hostname_notation=True)
            assert uri == expected_uri

    def test_extract_path_from_path_uri(self):
        """Test extracting paths from path notation URIs."""
        test_cases = [("naylence:///", "/"), ("naylence:///p1/p2/p3", "/p1/p2/p3")]

        for uri, expected_path in test_cases:
            path = extract_logical_from_uri(uri)
            assert path == expected_path

    def test_extract_path_from_hostname_uri(self):
        """Test extracting paths from hostname notation URIs."""
        test_cases = [(f"naylence://{get_fame_root()}/", "/"), ("naylence://p3.p2.p1/", "/p1/p2/p3")]

        for uri, expected_path in test_cases:
            path = extract_logical_from_uri(uri)
            assert path == expected_path

    def test_extract_invalid_uri(self):
        """Test extracting from invalid URIs."""
        invalid_uris = [
            "http://example.com",
            "naylence-invalid://test",
            "not-a-uri",
        ]

        for uri in invalid_uris:
            path = extract_logical_from_uri(uri)
            assert path is None


class TestValidationIntegration:
    """Test integration with validation."""


def test_dns_hostname_length_limits():
    """Test DNS hostname length limits."""
    # Test maximum length constraint - use shorter segments that fit within 253 chars
    # 3 segments of 60 chars each: 60 + 1 + 60 + 1 + 60 = 182 chars (well under 253)
    long_segments = ["a" * 60] * 3  # 3 segments of 60 chars each
    long_path = "/" + "/".join(long_segments)

    # This should be valid as each segment is <= 63 chars and total hostname <= 253 chars
    is_valid, error = validate_logical(long_path)
    assert is_valid, f"Long path should be valid: {error}"

    # Convert to hostname and check total length
    hostname = logical_to_hostname(long_path)
    assert len(hostname) <= 253, f"Hostname too long: {len(hostname)} chars"

    # Test case that exceeds 253 characters total
    # 4 segments of 63 chars each would give us: 63*4 + 3 = 255 chars (exceeds 253)
    too_long_segments = ["a" * 63] * 4  # 4 segments of 63 chars each
    too_long_path = "/" + "/".join(too_long_segments)

    # This should be invalid due to total hostname length
    is_valid, error = validate_logical(too_long_path)
    assert not is_valid, "Too long path should be invalid"
    assert "253 characters" in error, f"Error should mention 253 character limit: {error}"


def test_openssl_compatibility_examples():
    """Test examples that should work with OpenSSL name constraints."""
    # These paths should convert to valid hostnames for name constraints
    test_paths = [
        "/us-east-1/api",  # -> api.us-east-1
        "/prod/workers/node1",  # -> node1.workers.prod
        "/datacenter1/rack42",  # -> rack42.datacenter1
    ]

    for path in test_paths:
        # Validate path syntax
        is_valid, error = validate_logical(path)
        assert is_valid, f"Path {path} should be valid: {error}"

        # Convert to hostname notation
        hostname = logical_to_hostname(path)

        # Create hostname-based URI for certificate
        hostname_uri = create_logical_uri(path, use_hostname_notation=True)
        assert hostname_uri == f"naylence://{hostname}/"

        # Verify we can extract the original path
        extracted_path = extract_logical_from_uri(hostname_uri)
        assert extracted_path == path


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

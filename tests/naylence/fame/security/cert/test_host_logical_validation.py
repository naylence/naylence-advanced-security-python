#!/usr/bin/env python3
"""
Test the updated host logical validation with wildcard support.
"""

import pytest

from naylence.fame.util.logicals_util import validate_host_logical, validate_host_logicals


class TestHostLogicalValidation:
    """Test cases for host logical validation with wildcard support."""

    def test_valid_wildcard_patterns(self):
        """Test that valid wildcard patterns are accepted."""
        test_cases = [
            ("*.fame.fabric", "Valid leftmost wildcard"),
            ("*.api.services", "Valid leftmost wildcard with multiple segments"),
            ("*.sub.domain.com", "Valid wildcard with multi-segment base"),
        ]

        for logical, description in test_cases:
            is_valid, error = validate_host_logical(logical)
            assert is_valid, f"{description}: {logical} should be valid but got error: {error}"

    def test_valid_non_wildcard_patterns(self):
        """Test that valid non-wildcard patterns are accepted."""
        test_cases = [
            ("api.services", "Valid non-wildcard host"),
            ("fame.fabric", "Valid base domain"),
            ("node123.fame.fabric", "Valid specific host"),
        ]

        for logical, description in test_cases:
            is_valid, error = validate_host_logical(logical)
            assert is_valid, f"{description}: {logical} should be valid but got error: {error}"

    def test_invalid_wildcard_patterns(self):
        """Test that invalid wildcard patterns are rejected."""
        test_cases = [
            ("fame.*.fabric", "Wildcard not in leftmost position"),
            ("api.services.*", "Wildcard in rightmost position"),
            ("*.*.fabric", "Multiple wildcards"),
            ("*", "Wildcard only"),
            ("*.", "Wildcard with no base domain"),
        ]

        for logical, description in test_cases:
            is_valid, error = validate_host_logical(logical)
            assert not is_valid, f"{description}: {logical} should be invalid but validation passed"
            assert error, f"Expected error message for invalid logical: {logical}"

    def test_invalid_hostnames(self):
        """Test that invalid hostnames are rejected."""
        test_cases = [
            ("", "Empty string"),
            ("-api.services", "Starts with hyphen"),
            ("api..services", "Double dots"),
            ("api.services-", "Ends with hyphen"),
        ]

        for logical, description in test_cases:
            is_valid, error = validate_host_logical(logical)
            assert not is_valid, f"{description}: {logical} should be invalid but validation passed"
            assert error, f"Expected error message for invalid logical: {logical}"

    def test_batch_validation_valid_list(self):
        """Test batch validation with valid logicals."""
        valid_logicals = ["api.services", "*.fame.fabric", "node1.test.domain"]
        is_valid, error = validate_host_logicals(valid_logicals)
        assert is_valid, f"Valid logicals should pass batch validation: {error}"

    def test_batch_validation_invalid_list(self):
        """Test batch validation with invalid logicals."""
        invalid_logicals = ["api.services", "fame.*.fabric", "node1.test.domain"]
        is_valid, error = validate_host_logicals(invalid_logicals)
        assert not is_valid, "Invalid logicals should fail batch validation"
        assert error, "Expected error message for invalid logicals"

    def test_edge_cases(self):
        """Test edge cases for host logical validation."""
        edge_cases = [
            ("*.x", True, "Minimal valid wildcard"),
            ("x", True, "Single character domain"),
            ("*.fame", True, "Wildcard with short base"),
            ("a.b.c.d.e", True, "Many segments"),
            ("*.a.b.c.d", True, "Wildcard with many segments"),
        ]

        for logical, should_be_valid, description in edge_cases:
            is_valid, error = validate_host_logical(logical)
            if should_be_valid:
                assert is_valid, f"{description}: {logical} should be valid but got error: {error}"
            else:
                assert not is_valid, f"{description}: {logical} should be invalid but validation passed"


if __name__ == "__main__":
    pytest.main([__file__])

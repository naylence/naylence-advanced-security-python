#!/usr/bin/env python3
"""
Test the welcome service validation with wildcard logical addresses.

This test specifically validates that the welcome service can handle
wildcard logical addresses like '*.fame.fabric' correctly.
"""

import pytest

from naylence.fame.util.logicals_util import validate_host_logicals


class TestWelcomeServiceWildcardValidation:
    """Test wildcard validation in welcome service context."""

    def test_wildcard_logical_validation_for_welcome_service(self):
        """Test that wildcard logicals pass validation for welcome service."""
        # These are typical wildcard logicals that a sentinel might request
        wildcard_logicals = [
            "*.fame.fabric",
            "*.api.services",
            "*.compute.cluster",
            "*.data.fabric",
        ]

        # Should all be valid
        is_valid, error = validate_host_logicals(wildcard_logicals)
        assert is_valid, f"Wildcard logicals should be valid but got error: {error}"

    def test_mixed_wildcard_and_concrete_logicals(self):
        """Test that a mix of wildcard and concrete logicals is valid."""
        mixed_logicals = [
            "api.services",  # Concrete
            "*.fame.fabric",  # Wildcard
            "node1.test.domain",  # Concrete
            "*.compute.cluster",  # Wildcard
        ]

        is_valid, error = validate_host_logicals(mixed_logicals)
        assert is_valid, f"Mixed logicals should be valid but got error: {error}"

    def test_invalid_wildcard_patterns_rejected(self):
        """Test that invalid wildcard patterns are properly rejected."""
        invalid_logicals = [
            "api.services",
            "fame.*.fabric",  # Invalid: wildcard not in leftmost position
            "node1.test.domain",
        ]

        is_valid, error = validate_host_logicals(invalid_logicals)
        assert not is_valid, "Invalid wildcard pattern should be rejected"
        assert "not in leftmost position" in error

    def test_sentinel_typical_wildcard_logicals(self):
        """Test typical wildcard logicals that a sentinel would request."""
        # These are the types of logicals a sentinel typically requests
        sentinel_logicals = [
            "*.fame.fabric",  # Pool for general services
            "*.api.services",  # Pool for API services
            "fame.fabric",  # Concrete base domain
            "admin.fame.fabric",  # Concrete admin endpoint
        ]

        is_valid, error = validate_host_logicals(sentinel_logicals)
        assert is_valid, f"Sentinel logicals should be valid but got error: {error}"

    def test_welcome_service_compatibility(self):
        """Test that the validation is compatible with welcome service usage."""
        # Test the exact pattern that was failing: *.fame.fabric
        failing_logical = "*.fame.fabric"

        # Test single logical
        from naylence.fame.util.logicals_util import validate_host_logical

        is_valid, error = validate_host_logical(failing_logical)
        assert is_valid, f"'*.fame.fabric' should be valid but got error: {error}"

        # Test in a list (as the welcome service would)
        logicals_list = [failing_logical]
        is_valid, error = validate_host_logicals(logicals_list)
        assert is_valid, f"List with '*.fame.fabric' should be valid but got error: {error}"

    def test_edge_cases_for_wildcard_validation(self):
        """Test edge cases in wildcard validation."""
        test_cases = [
            # Valid cases
            ("*.a", True, "Single character base domain"),
            ("*.a.b", True, "Multi-segment short domains"),
            ("*.very-long-subdomain.example.com", True, "Long subdomain with hyphens"),
            # Invalid cases
            ("*", False, "Wildcard only"),
            ("*.", False, "Wildcard with no domain"),
            ("*..", False, "Wildcard with empty segments"),
            ("*.a.", False, "Trailing dot after domain"),
        ]

        from naylence.fame.util.logicals_util import validate_host_logical

        for logical, should_be_valid, description in test_cases:
            is_valid, error = validate_host_logical(logical)
            if should_be_valid:
                assert is_valid, f"{description}: '{logical}' should be valid but got: {error}"
            else:
                assert not is_valid, f"{description}: '{logical}' should be invalid but validation passed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""
Test for JSONRPCResponse serialization in encryption managers.

This test ensures that Pydantic models like JSONRPCResponse can be properly
serialized for encryption without causing JSON serialization errors.
"""

import json

import pytest

from naylence.fame.core import DataFrame, FameEnvelope
from naylence.fame.core.rpc.types import JSONRPCResponse
from naylence.fame.security.encryption.sealed.x25519_encryption_manager import _make_json_serializable


def test_jsonrpc_response_serialization():
    """Test that JSONRPCResponse objects can be serialized for encryption."""
    # Create a test JSONRPCResponse (common in RPC scenarios)
    response = JSONRPCResponse(jsonrpc="2.0", id="test123", result={"answer": 42, "status": "success"})

    # Test the serialization helper function
    serializable = _make_json_serializable(response)

    # Should be a dictionary now
    assert isinstance(serializable, dict)
    assert serializable["jsonrpc"] == "2.0"
    assert serializable["id"] == "test123"
    assert serializable["result"]["answer"] == 42

    # Should be JSON serializable
    try:
        json_str = json.dumps(serializable)
        assert len(json_str) > 0
        print("✅ JSONRPCResponse serialization test passed!")
    except TypeError as e:
        if "not JSON serializable" in str(e):
            pytest.fail(f"JSONRPCResponse serialization failed: {e}")
        else:
            raise


def test_various_payload_types_serialization():
    """Test serialization with various payload types."""
    payloads_to_test = [
        JSONRPCResponse(jsonrpc="2.0", id="test", result={"data": "value"}),
        {"simple": "dict"},
        "string_payload",
        42,
        [1, 2, 3],
        {"nested": {"deep": {"value": True}}},
    ]

    for i, payload in enumerate(payloads_to_test):
        try:
            serializable = _make_json_serializable(payload)
            json_str = json.dumps(serializable)
            assert len(json_str) > 0
            print(f"✅ Payload type {type(payload).__name__} serialized successfully")
        except Exception as e:
            pytest.fail(f"Failed to serialize payload type {type(payload).__name__}: {e}")


def test_encryption_manager_serialization_path():
    """Test the serialization path in the encryption manager without actual encryption."""
    # Create a test JSONRPCResponse
    response = JSONRPCResponse(jsonrpc="2.0", id="test123", result={"answer": 42, "status": "success"})

    # Create an envelope with the JSONRPCResponse as payload
    frame = DataFrame(payload=response, codec="json")
    envelope = FameEnvelope(frame=frame)

    # Test the serialization that happens in the encryption manager
    assert isinstance(envelope.frame, DataFrame), "Frame should be a DataFrame"
    original_codec = envelope.frame.codec
    payload = envelope.frame.payload

    # Convert to JSON-serializable form (this is what was failing before)
    serializable_payload = _make_json_serializable(payload)

    payload_with_codec = {"original_codec": original_codec, "payload": serializable_payload}

    # This should not raise a JSON serialization error
    try:
        payload_bytes = json.dumps(payload_with_codec).encode("utf-8")
        assert len(payload_bytes) > 0
        print("✅ Encryption manager serialization path test passed!")
    except TypeError as e:
        if "not JSON serializable" in str(e):
            pytest.fail(f"Encryption serialization path failed: {e}")
        else:
            raise

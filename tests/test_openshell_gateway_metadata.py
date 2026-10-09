"""Tests for validating OpenShell gateway metadata before deployment."""
import json

import pytest

from scripts.verify_openshell_gateway_metadata import validate_endpoint, validate_metadata_file


def test_accepts_official_gateway_endpoint_field():
    endpoint = "https://openshell.example.com:8443"
    assert validate_endpoint({"gateway_endpoint": endpoint}) == endpoint


def test_accepts_legacy_endpoint_field_for_compatibility():
    endpoint = "https://openshell.example.com"
    assert validate_endpoint({"endpoint": endpoint}) == endpoint


@pytest.mark.parametrize("endpoint", [
    "http://openshell.example.com",
    "https://localhost:8443",
    "https://api.localhost",
    "https://127.0.0.1:8443",
    "https://0.0.0.0:8443",
    "https://[::1]:8443",
    "https://user:password@openshell.example.com",
    "https://openshell.example.com:99999",
    "https://openshell.example.com/path?token=secret",
])
def test_rejects_unsafe_or_malformed_gateway_endpoints(endpoint):
    with pytest.raises(ValueError):
        validate_endpoint({"gateway_endpoint": endpoint})


def test_rejects_missing_or_non_object_metadata():
    with pytest.raises(ValueError):
        validate_endpoint({"name": "gateway"})
    with pytest.raises(ValueError):
        validate_endpoint([])


def test_metadata_file_is_size_bounded_and_parsed(tmp_path):
    path = tmp_path / "metadata.json"
    path.write_text(json.dumps({"gateway_endpoint": "https://openshell.example.com"}), encoding="utf-8")
    assert validate_metadata_file(path) == "https://openshell.example.com"
    path.write_bytes(b" " * (64 * 1024 + 1))
    with pytest.raises(ValueError, match="size limit"):
        validate_metadata_file(path)

#!/usr/bin/env python3
"""Validate OpenShell active-gateway metadata before production deployment."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

MAX_METADATA_BYTES = 64 * 1024
MAX_ENDPOINT_LENGTH = 2048


def validate_endpoint(metadata: object) -> str:
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be a JSON object")
    endpoint = metadata.get("gateway_endpoint")
    if endpoint is None:
        endpoint = metadata.get("endpoint")  # Legacy metadata compatibility.
    if not isinstance(endpoint, str) or not endpoint or len(endpoint) > MAX_ENDPOINT_LENGTH:
        raise ValueError("gateway_endpoint must be a bounded URL string")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in endpoint):
        raise ValueError("gateway_endpoint contains control characters")
    try:
        parsed = urlsplit(endpoint)
        hostname = parsed.hostname
        port = parsed.port  # Access validates malformed/out-of-range ports.
    except ValueError as exc:
        raise ValueError("gateway_endpoint URL is malformed") from exc
    if (
        parsed.scheme.lower() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("gateway_endpoint must be a credential-free HTTPS URL")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("gateway_endpoint port is invalid")
    host = hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("gateway_endpoint must not target localhost")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (address.is_loopback or address.is_unspecified):
        raise ValueError("gateway_endpoint must not target a loopback or unspecified address")
    return endpoint


def validate_metadata_file(path: str | Path) -> str:
    raw = Path(path).read_bytes()
    if len(raw) > MAX_METADATA_BYTES:
        raise ValueError("metadata file exceeds size limit")
    try:
        metadata = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("metadata file is not valid UTF-8 JSON") from exc
    return validate_endpoint(metadata)


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: verify_openshell_gateway_metadata.py PATH", file=sys.stderr)
        return 2
    try:
        validate_metadata_file(sys.argv[1])
    except (OSError, ValueError) as exc:
        print(f"Invalid OpenShell gateway metadata: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

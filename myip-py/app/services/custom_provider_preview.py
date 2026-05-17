from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException

from app.services.admin_config import normalize_custom_provider_preview
from app.services.ip_lookup import IPInfo, IPLookupUnavailable

ALLOWED_TRANSFORMS = {"string", "bool", "int", "float", "asn_int"}


class GenericJSONLookupProvider:
    def __init__(self, provider: dict[str, Any], timeout_seconds: float | None = None) -> None:
        self.provider = normalize_custom_provider_preview({**provider, "timeout_seconds": timeout_seconds or provider.get("timeout_seconds")})

    def lookup(self, ip: str) -> IPInfo:
        preview = _run_custom_provider_request(ip, self.provider)
        normalized = preview["normalized"]
        payload: dict[str, Any] = {"ip": ip, "provider": self.provider["id"]}
        for field, value in normalized.items():
            if field == "asn" and isinstance(value, int):
                payload[field] = f"AS{value}"
            elif field in IPInfo.model_fields:
                payload[field] = value
        info = IPInfo(**payload)
        info.field_sources = {
            field: f"{self.provider['id']}:{path}"
            for field, path in preview["field_sources"].items()
            if field in IPInfo.model_fields
        }
        return info


def preview_custom_provider(payload: dict[str, Any]) -> dict[str, Any]:
    ip = _valid_ip(payload.get("ip"))
    provider = normalize_custom_provider_preview(payload.get("provider"))
    try:
        return _run_custom_provider_request(ip, provider)
    except IPLookupUnavailable as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


def _run_custom_provider_request(ip: str, provider: dict[str, Any]) -> dict[str, Any]:
    transforms = _normalize_transforms(provider.get("transforms", {}))
    url = _safe_preview_url(provider["endpoint"], ip)
    try:
        with httpx.Client(timeout=provider.get("timeout_seconds") or 8.0, follow_redirects=False) as client:
            response = client.get(url)
            response.raise_for_status()
            raw = response.json()
    except httpx.HTTPError as exc:
        raise IPLookupUnavailable(f"custom provider request failed: {exc}") from exc
    except ValueError as exc:
        raise IPLookupUnavailable("custom provider did not return JSON") from exc

    normalized, field_sources, missing_fields = extract_mapped_fields(raw, provider.get("field_paths", {}), transforms)
    return {
        "provider_id": provider["id"],
        "url": url,
        "normalized": normalized,
        "field_sources": field_sources,
        "missing_fields": missing_fields,
        "raw": raw,
    }


def extract_mapped_fields(
    raw: dict[str, Any],
    field_paths: dict[str, list[str]],
    transforms: dict[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, str], list[str]]:
    transforms = transforms or {}
    normalized: dict[str, Any] = {}
    field_sources: dict[str, str] = {}
    missing_fields: list[str] = []
    for field, paths in field_paths.items():
        found = False
        for path in paths:
            exists, value = _json_path(raw, path)
            if exists and value is not None and value != "":
                normalized[field] = _transform_value(value, transforms.get(field, "string"))
                field_sources[field] = path
                found = True
                break
        if not found:
            missing_fields.append(field)
    return normalized, field_sources, missing_fields


def _valid_ip(value: Any) -> str:
    if not isinstance(value, str):
        raise HTTPException(status_code=422, detail="ip must be a string")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="ip must be a valid IP address") from exc


def _normalize_transforms(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail="transforms must be an object")
    transforms = {str(field): str(transform) for field, transform in value.items()}
    unknown = set(transforms.values()) - ALLOWED_TRANSFORMS
    if unknown:
        raise HTTPException(status_code=422, detail=f"unknown transform: {sorted(unknown)}")
    return transforms


def _safe_preview_url(endpoint: str, ip: str) -> str:
    url = endpoint.replace("{ip}", ip)
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise HTTPException(status_code=422, detail="custom provider endpoint must use https")
    if not parsed.hostname:
        raise HTTPException(status_code=422, detail="custom provider endpoint host is required")
    if _is_unsafe_host(parsed.hostname):
        raise HTTPException(status_code=422, detail="unsafe custom provider host is blocked")
    return url


def _is_unsafe_host(hostname: str) -> bool:
    host = hostname.strip().lower().rstrip(".")
    if host in {"localhost", "metadata.google.internal"}:
        return True
    try:
        return _is_unsafe_ip(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    return any(_is_unsafe_ip(ipaddress.ip_address(address[4][0])) for address in addresses)


def _is_unsafe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _json_path(value: Any, path: str) -> tuple[bool, Any]:
    current = value
    for token in _path_tokens(path):
        if isinstance(current, dict) and isinstance(token, str) and token in current:
            current = current[token]
        elif isinstance(current, list) and isinstance(token, int) and 0 <= token < len(current):
            current = current[token]
        else:
            return False, None
    return True, current


def _path_tokens(path: str) -> list[str | int]:
    if not isinstance(path, str) or not path:
        raise HTTPException(status_code=422, detail="json path must be a non-empty string")
    tokens: list[str | int] = []
    for part in path.split("."):
        match = re.fullmatch(r"([^\[\]]+)(?:\[(\d+)\])?", part)
        if not match:
            raise HTTPException(status_code=422, detail=f"unsupported json path: {path}")
        tokens.append(match.group(1))
        if match.group(2) is not None:
            tokens.append(int(match.group(2)))
    return tokens


def _transform_value(value: Any, transform: str) -> Any:
    if transform == "string":
        return str(value)
    if transform == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "1", "yes", "y"}:
                return True
            if normalized in {"false", "0", "no", "n"}:
                return False
        if isinstance(value, int):
            return bool(value)
        raise HTTPException(status_code=422, detail=f"cannot convert value to bool: {value}")
    if transform == "int":
        return int(value)
    if transform == "float":
        return float(value)
    if transform == "asn_int":
        if isinstance(value, int):
            return value
        match = re.search(r"\d+", str(value))
        if not match:
            raise HTTPException(status_code=422, detail=f"cannot convert value to ASN integer: {value}")
        return int(match.group(0))
    raise HTTPException(status_code=422, detail=f"unknown transform: {transform}")

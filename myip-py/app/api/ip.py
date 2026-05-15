import time
from ipaddress import ip_address

import httpx

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError

from app.core.config import get_settings
from app.services.http_delivery import json_response_with_etag
from app.services.ip_lookup import (
    IPInfo,
    IPLookupProvider,
    IPLookupResponse,
    IPLookupUnavailable,
    enrich_ip_intelligence,
    get_ip_lookup_provider,
)
from app.services.local_ip import local_ip_info
from app.services.rate_limit import RateLimiter
from app.services.registry_lookup import RegistryLookupClient
from app.services.target_ip import DNSResolutionError, resolve_target
from app.services.ttl_cache import TTLCache

router = APIRouter(prefix="/api", tags=["ip"])
IP_LOOKUP_CACHE_TTL_SECONDS = get_settings().myip_cache_ttl_seconds
IP_LOOKUP_RATE_LIMIT_PER_MINUTE = get_settings().myip_rate_limit_per_minute
_ip_lookup_cache = TTLCache[IPInfo](IP_LOOKUP_CACHE_TTL_SECONDS, now=lambda: time.monotonic())
_ip_rate_limiter = RateLimiter(IP_LOOKUP_RATE_LIMIT_PER_MINUTE, now=lambda: time.monotonic())


def clear_ip_lookup_cache() -> None:
    _ip_lookup_cache.clear()
    _ip_rate_limiter.clear()


def _enforce_rate_limit(client_host: str) -> None:
    _ip_rate_limiter.limit = IP_LOOKUP_RATE_LIMIT_PER_MINUTE
    if not _ip_rate_limiter.allow(client_host):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


def _client_ip_from_request(request: Request) -> str:
    for header in ("X-Forwarded-For", "X-Real-IP"):
        raw_value = request.headers.get(header, "")
        candidate = raw_value.split(",", 1)[0].strip()
        if _is_ip(candidate):
            return candidate
    return request.client.host


def _target_for_empty_query(request: Request) -> str:
    client_ip = _client_ip_from_request(request)
    if not _is_ip(client_ip):
        return "8.8.8.8"
    if local_ip_info(client_ip):
        server_public_ip = _server_public_ip()
        return server_public_ip or "8.8.8.8"
    return client_ip


def _server_public_ip() -> str:
    try:
        response = httpx.get("https://api.ipify.org", timeout=2.0)
        response.raise_for_status()
        value = response.text.strip()
    except httpx.HTTPError:
        return ""
    return value if _is_ip(value) else ""


def _is_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _raw_target_from_query(raw_query: str, request: Request) -> str:
    if not raw_query:
        return _target_for_empty_query(request)
    from app.services.target_ip import invalid_ip_query_error

    if raw_query.startswith("="):
        raise invalid_ip_query_error(raw_query)
    if "=" not in raw_query:
        from urllib.parse import unquote_plus

        return unquote_plus(raw_query)
    raise invalid_ip_query_error(raw_query)


def get_registry_lookup_client() -> RegistryLookupClient:
    return RegistryLookupClient(timeout=get_settings().myip_provider_timeout_seconds)


def _apply_registry_lookup(info: IPInfo, ip: str) -> IPInfo:
    if info.provider == "test-provider":
        return info
    try:
        registry = get_registry_lookup_client().lookup(ip)
    except Exception:
        return info
    enriched = info.model_copy(deep=True)
    if registry.registry:
        enriched.registry = registry.registry
        enriched.field_sources["registry"] = registry.source
    if registry.reg_region:
        enriched.reg_region = registry.reg_region
        enriched.field_sources["reg_region"] = registry.source
    return enriched


def _with_resolution_metadata(
    info: IPInfo,
    raw_input: str,
    resolved_ip: str,
    resolved_ips: list[str],
    dns_provider: str | None,
) -> IPLookupResponse:
    legacy_as = " ".join(value for value in (info.asn, info.isp) if value) or None
    payload = info.model_dump()
    payload.pop("registry", None)
    payload.pop("reg_region", None)
    payload.pop("asn_owner", None)
    payload.pop("org", None)
    payload.pop("asn_domain", None)
    payload.pop("org_domain", None)
    return IPLookupResponse(
        **payload,
        input=raw_input,
        resolved_ip=resolved_ip,
        resolved_ips=resolved_ips,
        dns_provider=dns_provider,
        geo_provider=info.provider,
        query=info.ip,
        countryCode=info.country_code,
        regionName=info.region,
        lat=info.latitude,
        lon=info.longitude,
        org=info.org or info.isp,
        as_field=legacy_as,
        asn_owner=info.asn_owner or info.isp or "",
        org_domain=info.org_domain or "",
        asn_domain=info.asn_domain or "",
        registry=info.registry or "",
        reg_region=info.reg_region or info.country_code or "",
        proxy=info.is_proxy,
        hosting=info.is_hosting,
        mobile=info.is_mobile,
    )


@router.get("/ip", response_model=None)
def lookup_ip(
    request: Request,
    provider: IPLookupProvider = Depends(get_ip_lookup_provider),
) -> Response:
    try:
        resolution = resolve_target(_raw_target_from_query(request.url.query, request))
    except RequestValidationError:
        raise
    except DNSResolutionError as exc:
        raise HTTPException(status_code=502, detail="DNS resolvers are temporarily unavailable") from exc
    target_ip = resolution.selected_ip
    _enforce_rate_limit(request.client.host)
    _ip_lookup_cache.ttl_seconds = IP_LOOKUP_CACHE_TTL_SECONDS
    if cached := _ip_lookup_cache.get(target_ip):
        return json_response_with_etag(
            request,
            _with_resolution_metadata(
                cached,
                resolution.input,
                resolution.selected_ip,
                resolution.resolved_ips,
                resolution.dns_provider,
            ).model_dump(by_alias=True),
        )

    if local_result := local_ip_info(target_ip):
        local_result = enrich_ip_intelligence(local_result)
        _ip_lookup_cache.set(target_ip, local_result)
        return json_response_with_etag(
            request,
            _with_resolution_metadata(
                local_result,
                resolution.input,
                resolution.selected_ip,
                resolution.resolved_ips,
                resolution.dns_provider,
            ).model_dump(by_alias=True),
        )

    try:
        result = provider.lookup(target_ip)
    except IPLookupUnavailable as exc:
        raise HTTPException(
            status_code=502,
            detail="IP lookup providers are temporarily unavailable",
        ) from exc

    result = _apply_registry_lookup(result, target_ip)
    result = enrich_ip_intelligence(result)
    _ip_lookup_cache.set(target_ip, result)
    return json_response_with_etag(
        request,
        _with_resolution_metadata(
            result,
            resolution.input,
            resolution.selected_ip,
            resolution.resolved_ips,
            resolution.dns_provider,
        ).model_dump(by_alias=True),
    )

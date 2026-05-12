import time

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.config import get_settings
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


def _raw_target_from_query(raw_query: str, client_host: str) -> str:
    if not raw_query:
        return client_host
    if raw_query.startswith("="):
        from urllib.parse import unquote_plus

        return unquote_plus(raw_query[1:])
    if "=" not in raw_query:
        from urllib.parse import unquote_plus

        return unquote_plus(raw_query)
    from app.services.target_ip import invalid_ip_query_error

    raise invalid_ip_query_error(raw_query)


def _with_resolution_metadata(
    info: IPInfo,
    raw_input: str,
    resolved_ip: str,
    resolved_ips: list[str],
    dns_provider: str | None,
) -> IPLookupResponse:
    return IPLookupResponse(
        **info.model_dump(),
        input=raw_input,
        resolved_ip=resolved_ip,
        resolved_ips=resolved_ips,
        dns_provider=dns_provider,
        geo_provider=info.provider,
    )


@router.get("/ip", response_model=IPLookupResponse)
def lookup_ip(
    request: Request,
    provider: IPLookupProvider = Depends(get_ip_lookup_provider),
) -> IPInfo:
    try:
        resolution = resolve_target(_raw_target_from_query(request.url.query, request.client.host))
    except DNSResolutionError as exc:
        raise HTTPException(status_code=502, detail="DNS resolvers are temporarily unavailable") from exc
    target_ip = resolution.selected_ip
    _enforce_rate_limit(request.client.host)
    _ip_lookup_cache.ttl_seconds = IP_LOOKUP_CACHE_TTL_SECONDS
    if cached := _ip_lookup_cache.get(target_ip):
        return _with_resolution_metadata(
            cached,
            resolution.input,
            resolution.selected_ip,
            resolution.resolved_ips,
            resolution.dns_provider,
        )

    if local_result := local_ip_info(target_ip):
        local_result = enrich_ip_intelligence(local_result)
        _ip_lookup_cache.set(target_ip, local_result)
        return _with_resolution_metadata(
            local_result,
            resolution.input,
            resolution.selected_ip,
            resolution.resolved_ips,
            resolution.dns_provider,
        )

    try:
        result = provider.lookup(target_ip)
    except IPLookupUnavailable as exc:
        raise HTTPException(
            status_code=502,
            detail="IP lookup providers are temporarily unavailable",
        ) from exc

    result = enrich_ip_intelligence(result)
    _ip_lookup_cache.set(target_ip, result)
    return _with_resolution_metadata(
        result,
        resolution.input,
        resolution.selected_ip,
        resolution.resolved_ips,
        resolution.dns_provider,
    )

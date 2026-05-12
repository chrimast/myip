import time

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.config import get_settings
from app.services.ip_lookup import IPInfo, IPLookupProvider, IPLookupUnavailable, get_ip_lookup_provider
from app.services.local_ip import local_ip_info
from app.services.rate_limit import RateLimiter
from app.services.target_ip import target_ip_from_query
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


@router.get("/ip", response_model=IPInfo)
def lookup_ip(
    request: Request,
    provider: IPLookupProvider = Depends(get_ip_lookup_provider),
) -> IPInfo:
    target_ip = target_ip_from_query(request.url.query, request.client.host)
    _enforce_rate_limit(request.client.host)
    _ip_lookup_cache.ttl_seconds = IP_LOOKUP_CACHE_TTL_SECONDS
    if cached := _ip_lookup_cache.get(target_ip):
        return cached

    if local_result := local_ip_info(target_ip):
        _ip_lookup_cache.set(target_ip, local_result)
        return local_result

    try:
        result = provider.lookup(target_ip)
    except IPLookupUnavailable as exc:
        raise HTTPException(
            status_code=502,
            detail="IP lookup providers are temporarily unavailable",
        ) from exc

    _ip_lookup_cache.set(target_ip, result)
    return result

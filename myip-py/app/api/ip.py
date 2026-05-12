import time
from ipaddress import IPv4Address, IPv6Address, ip_address
from urllib.parse import unquote_plus

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError

from app.core.config import get_settings
from app.services.ip_lookup import IPInfo, IPLookupProvider, IPLookupUnavailable, get_ip_lookup_provider
from app.services.local_ip import local_ip_info
from app.services.rate_limit import RateLimiter
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


def _invalid_ip_query_error(raw_ip: str) -> RequestValidationError:
    return RequestValidationError(
        [
            {
                "type": "ip_any_address",
                "loc": ("query", "ip"),
                "msg": "value is not a valid IPv4 or IPv6 address",
                "input": raw_ip,
            }
        ]
    )


def _target_ip_from_request(request: Request, ip: IPv4Address | IPv6Address | None) -> str:
    if ip:
        return str(ip)

    raw_query = request.url.query
    if raw_query.startswith("="):
        raw_ip = unquote_plus(raw_query[1:])
        try:
            return str(ip_address(raw_ip))
        except ValueError as exc:
            raise _invalid_ip_query_error(raw_ip) from exc

    if raw_query and "=" not in raw_query:
        raw_ip = unquote_plus(raw_query)
        try:
            return str(ip_address(raw_ip))
        except ValueError as exc:
            raise _invalid_ip_query_error(raw_ip) from exc

    return request.client.host


@router.get("/ip", response_model=IPInfo)
def lookup_ip(
    request: Request,
    ip: IPv4Address | IPv6Address | None = Query(default=None),
    provider: IPLookupProvider = Depends(get_ip_lookup_provider),
) -> IPInfo:
    target_ip = _target_ip_from_request(request, ip)
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

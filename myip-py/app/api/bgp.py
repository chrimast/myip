import time
from urllib.parse import unquote_plus

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from app.services.bgp import BGPTopology, ASNNode, fetch_bgp_topology, limit_bgp_topology
from app.services.admin_config import read_provider_config
from app.services.ip_lookup import get_ip_lookup_provider
from app.services.rate_limit import RateLimiter
from app.services.target_ip import DNSResolutionError, resolve_target

router = APIRouter(prefix="/api", tags=["bgp"])
BGP_CACHE_TTL_SECONDS = 300
BGP_RATE_LIMIT_PER_MINUTE = 60
_bgp_topology_cache: dict[int, tuple[float, BGPTopology]] = {}
_bgp_rate_limiter = RateLimiter(BGP_RATE_LIMIT_PER_MINUTE, now=lambda: time.monotonic())


def clear_bgp_topology_cache() -> None:
    _bgp_topology_cache.clear()
    _bgp_rate_limiter.clear()


def _runtime_settings() -> dict:
    config = read_provider_config()
    return config.get("runtime_settings", {}) if config.get("exists") else {}


def _enforce_bgp_rate_limit(request: Request, runtime_settings: dict) -> None:
    rate_limit = runtime_settings.get("rate_limit", {})
    if rate_limit.get("bgp_enabled", False) is False:
        return
    _bgp_rate_limiter.limit = int(rate_limit.get("bgp_per_minute") or BGP_RATE_LIMIT_PER_MINUTE)
    if not _bgp_rate_limiter.allow(request.client.host):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


def _parse_asn(raw_asn: str | None) -> int:
    cleaned = (raw_asn or "").strip().upper().removeprefix("AS")
    try:
        asn = int(cleaned)
    except ValueError:
        return 0
    return asn if asn > 0 else 0


def _target_from_request(request: Request) -> tuple[str, int]:
    raw_query = request.url.query
    if not raw_query:
        return "", 0
    target_part = raw_query.split("&", 1)[0].strip()
    if target_part.startswith("="):
        return "", 0
    if "=" in target_part:
        return "", 0
    target = unquote_plus(target_part).strip()
    asn = _parse_asn(target)
    if asn:
        return "", asn
    return target, 0


def resolve_asn_from_target(request: Request, value: str) -> int:
    try:
        resolution = resolve_target(value)
    except DNSResolutionError:
        return 0
    info = get_ip_lookup_provider().lookup(resolution.selected_ip)
    return _parse_asn(info.asn)


def _external_links(asn: int) -> dict[str, str]:
    return {
        "bgp_tools": f"https://bgp.tools/as/{asn}#connectivity",
        "bgp_he": f"https://bgp.he.net/AS{asn}#_graph4",
    }


def _ensure_external_links(topology: BGPTopology) -> BGPTopology:
    if not topology.external_links:
        topology.external_links = _external_links(topology.asn)
    return topology


@router.get("/bgp", response_model=None)
def lookup_bgp(request: Request, limit: int | None = None):
    runtime_settings = _runtime_settings()
    bgp_settings = runtime_settings.get("bgp", {})
    cache_settings = runtime_settings.get("cache", {})
    if bgp_settings.get("enabled", True) is False:
        return JSONResponse({"ok": False, "error": "bgp graph disabled"}, status_code=503)
    target, asn_num = _target_from_request(request)
    if not asn_num:
        if not target:
            return JSONResponse({"ok": False, "error": "invalid target"}, status_code=400)
        asn_num = resolve_asn_from_target(request, target)
        if not asn_num:
            return JSONResponse({"ok": False, "error": "asn not found"}, status_code=400)

    max_limit = int(bgp_settings.get("max_upstream_limit") or 50)
    default_limit = int(bgp_settings.get("default_upstream_limit") or 20)
    limit = max(1, min(limit if limit is not None else default_limit, max_limit))
    cache_enabled = cache_settings.get("bgp_enabled", True)
    cache_ttl = int(cache_settings.get("bgp_ttl_seconds") or bgp_settings.get("cache_ttl_seconds") or BGP_CACHE_TTL_SECONDS)
    now = time.monotonic()
    cached = _bgp_topology_cache.get(asn_num)
    if cache_enabled and cached is not None:
        cached_at, topology = cached
        if now - cached_at <= cache_ttl:
            return {"ok": True, "asn": asn_num, "data": limit_bgp_topology(topology, limit)}

    _enforce_bgp_rate_limit(request, runtime_settings)
    try:
        topology = _ensure_external_links(fetch_bgp_topology(asn_num, limit))
    except Exception as exc:
        if cached is not None:
            return {
                "ok": True,
                "asn": asn_num,
                "stale": True,
                "error": str(exc),
                "data": limit_bgp_topology(cached[1], limit),
            }
        return {
            "ok": False,
            "status": "error",
            "http_status": 200,
            "asn": asn_num,
            "error": str(exc),
            "external_links": _external_links(asn_num),
        }

    if cache_enabled:
        _bgp_topology_cache[asn_num] = (now, topology)
    return {"ok": True, "asn": asn_num, "data": limit_bgp_topology(topology, limit)}

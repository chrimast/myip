import time
from urllib.parse import parse_qs, unquote_plus

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from app.services.bgp import BGPTopology, ASNNode, fetch_bgp_topology, limit_bgp_topology
from app.services.ip_lookup import get_ip_lookup_provider
from app.services.target_ip import DNSResolutionError, resolve_target

router = APIRouter(prefix="/api", tags=["bgp"])
BGP_CACHE_TTL_SECONDS = 300
_bgp_topology_cache: dict[int, tuple[float, BGPTopology]] = {}


def clear_bgp_topology_cache() -> None:
    _bgp_topology_cache.clear()


def _parse_asn(raw_asn: str | None) -> int:
    cleaned = (raw_asn or "").strip().upper().removeprefix("AS")
    try:
        asn = int(cleaned)
    except ValueError:
        return 0
    return asn if asn > 0 else 0


def _target_from_request(request: Request) -> str:
    raw_query = request.url.query
    params = parse_qs(raw_query, keep_blank_values=True)
    if target := (params.get("ip") or params.get("q")):
        return target[0].strip()
    if raw_query.startswith("="):
        return unquote_plus(raw_query[1:]).strip()
    if raw_query and "=" not in raw_query:
        return unquote_plus(raw_query).strip()
    return ""


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
def lookup_bgp(request: Request, asn: str | None = Query(None), limit: int = 80):
    asn_num = _parse_asn(asn)
    if asn is not None and not asn_num:
        return JSONResponse({"ok": False, "error": "invalid asn"}, status_code=400)
    if not asn_num:
        target = _target_from_request(request)
        if not target:
            return JSONResponse({"ok": False, "error": "invalid target"}, status_code=400)
        asn_num = resolve_asn_from_target(request, target)
        if not asn_num:
            return JSONResponse({"ok": False, "error": "asn not found"}, status_code=400)

    limit = max(1, min(limit, 300))
    now = time.monotonic()
    cached = _bgp_topology_cache.get(asn_num)
    if cached is not None:
        cached_at, topology = cached
        if now - cached_at <= BGP_CACHE_TTL_SECONDS:
            return {"ok": True, "asn": asn_num, "data": limit_bgp_topology(topology, limit)}

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

    _bgp_topology_cache[asn_num] = (now, topology)
    return {"ok": True, "asn": asn_num, "data": limit_bgp_topology(topology, limit)}

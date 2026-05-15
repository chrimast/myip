from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass

import httpx
from fastapi import Request, Response

VIS_NETWORK_URLS = (
    "https://cdn.jsdelivr.net/npm/vis-network/standalone/umd/vis-network.min.js",
    "https://unpkg.com/vis-network/standalone/umd/vis-network.min.js",
)
VIS_NETWORK_USER_AGENT = "myip/1.0 (+vis-cache)"
VIS_NETWORK_TIMEOUT_SECONDS = 10.0


@dataclass
class VisNetworkCache:
    data: bytes = b""
    content_type: str = ""
    etag: str = ""
    cached_at: float = 0.0


_vis_cache = VisNetworkCache()
_vis_lock = threading.Lock()


def clear_vis_network_cache() -> None:
    with _vis_lock:
        _vis_cache.data = b""
        _vis_cache.content_type = ""
        _vis_cache.etag = ""
        _vis_cache.cached_at = 0.0


def vis_network_response(request: Request) -> Response:
    cached = _cached_response(request)
    if cached is not None:
        return cached

    last_error: Exception | None = None
    for url in VIS_NETWORK_URLS:
        try:
            response = httpx.get(
                url,
                headers={"User-Agent": VIS_NETWORK_USER_AGENT},
                timeout=VIS_NETWORK_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            last_error = exc
            continue
        if not response.content:
            last_error = ValueError("empty CDN response")
            continue
        content_type = response.headers.get("Content-Type") or "application/javascript; charset=utf-8"
        etag = f'W/"{hashlib.sha1(response.content).hexdigest()}"'
        with _vis_lock:
            _vis_cache.data = response.content
            _vis_cache.content_type = content_type
            _vis_cache.etag = etag
            _vis_cache.cached_at = time.time()
        return _response_from_cache(request, response.content, content_type, etag)

    return Response(
        f"vis-network unavailable: {last_error}",
        status_code=502,
        media_type="text/plain",
    )


def _cached_response(request: Request) -> Response | None:
    with _vis_lock:
        data = _vis_cache.data
        content_type = _vis_cache.content_type
        etag = _vis_cache.etag
    if not data:
        return None
    return _response_from_cache(request, data, content_type, etag)


def _response_from_cache(request: Request, data: bytes, content_type: str, etag: str) -> Response:
    headers = {"ETag": etag, "Cache-Control": "public, max-age=604800"}
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    return Response(data, media_type=content_type, headers=headers)

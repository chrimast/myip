from __future__ import annotations

import gzip
import hashlib
import json
from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class GZipMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        if "gzip" not in request.headers.get("accept-encoding", ""):
            return response
        if response.status_code in (204, 304) or response.headers.get("content-encoding"):
            return response
        body = b"".join([chunk async for chunk in response.body_iterator])
        gzipped = gzip.compress(body)
        headers = dict(response.headers)
        headers.pop("content-length", None)
        headers["Content-Encoding"] = "gzip"
        headers["Content-Length"] = str(len(gzipped))
        headers["Vary"] = _add_vary(headers.get("Vary"), "Accept-Encoding")
        return Response(
            content=gzipped,
            status_code=response.status_code,
            headers=headers,
            media_type=response.media_type,
        )


def json_response_with_etag(request: Request, payload: object) -> Response:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    etag = f'"{hashlib.sha1(body).hexdigest()}"'
    if etag in request.headers.get("if-none-match", ""):
        return Response(status_code=304, headers={"ETag": etag, "Vary": "If-None-Match"})
    return Response(
        content=body,
        media_type="application/json",
        headers={"ETag": etag, "Vary": "If-None-Match"},
    )


def _add_vary(existing: str | None, value: str) -> str:
    if not existing:
        return value
    values = [part.strip() for part in existing.split(",") if part.strip()]
    if value.lower() not in {part.lower() for part in values}:
        values.append(value)
    return ", ".join(values)

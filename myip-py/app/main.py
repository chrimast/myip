from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from starlette.responses import Response

from app.api.bgp import router as bgp_router
from app.api.ip import router as ip_router
from app.services.http_delivery import GZipMiddleware
from app.services.vis_network import clear_vis_network_cache, vis_network_response
from pathlib import Path

app = FastAPI(title="myip-py", version="0.1.0")
app.add_middleware(GZipMiddleware)
STATIC_DIR = Path(__file__).parent / "static"
INDEX_HTML = STATIC_DIR / "index.html"


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML.read_text(encoding="utf-8")


@app.get("/vis-network.min.js")
def vis_network(request: Request) -> Response:
    return vis_network_response(request)


@app.middleware("http")
async def add_production_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path != "/vis-network.min.js":
        response.headers["Cache-Control"] = "no-store"
    return response


app.include_router(ip_router)
app.include_router(bgp_router)

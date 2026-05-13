from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse
from starlette.responses import Response

from app.api.bgp import router as bgp_router
from app.api.health import router as health_router
from app.api.ip import router as ip_router

app = FastAPI(title="myip-py", version="0.1.0")
STATIC_DIR = Path(__file__).parent / "static"
INDEX_HTML = STATIC_DIR / "index.html"
VIS_NETWORK_JS = STATIC_DIR / "vendor" / "vis-network.min.js"


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML.read_text(encoding="utf-8")


@app.get("/vis-network.min.js")
def vis_network() -> FileResponse:
    return FileResponse(VIS_NETWORK_JS, media_type="application/javascript")


@app.middleware("http")
async def add_production_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


app.include_router(health_router)
app.include_router(ip_router)
app.include_router(bgp_router)

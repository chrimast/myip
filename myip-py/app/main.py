from pathlib import Path
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from starlette.responses import Response

from app.api.admin import router as admin_router
from app.api.bgp import router as bgp_router
from app.api.ip import router as ip_router
from app.core.config import Settings, get_settings
from app.services.admin_auth import (
    admin_auth_enabled,
    admin_credentials_match,
    admin_login_page,
    admin_login_response,
    admin_logout_response,
    session_is_valid,
)
from app.services.http_delivery import GZipMiddleware
from app.services.vis_network import clear_vis_network_cache, vis_network_response

app = FastAPI(title="myip-py", version="0.1.0")
app.add_middleware(GZipMiddleware)
STATIC_DIR = Path(__file__).parent / "static"
INDEX_HTML = STATIC_DIR / "index.html"
ADMIN_HTML = STATIC_DIR / "admin.html"


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML.read_text(encoding="utf-8")


@app.get("/static/{asset_path:path}")
def static_asset(asset_path: str) -> Response:
    target = (STATIC_DIR / asset_path).resolve()
    static_root = STATIC_DIR.resolve()
    if not target.is_file() or static_root not in target.parents:
        return JSONResponse({"detail": "Not found"}, status_code=404)
    return FileResponse(target)


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request, settings: Settings = Depends(get_settings)) -> Response:
    if admin_auth_enabled(settings) and not session_is_valid(request, settings):
        return admin_login_page()
    return HTMLResponse(ADMIN_HTML.read_text(encoding="utf-8"))


@app.exception_handler(401)
def auth_error_handler(request: Request, exc) -> Response:
    if request.url.path.startswith("/api/admin"):
        return JSONResponse({"detail": getattr(exc, "detail", "Admin authentication required")}, status_code=401)
    return admin_login_page()


@app.post("/admin/login")
async def admin_login(request: Request, settings: Settings = Depends(get_settings)) -> Response:
    body = (await request.body()).decode("utf-8")
    form = parse_qs(body)
    username = form.get("username", [""])[0]
    password = form.get("password", [""])[0]
    if not admin_auth_enabled(settings):
        return admin_login_response(settings)
    if admin_credentials_match(username, password, settings):
        return admin_login_response(settings)
    return admin_login_page()


@app.post("/admin/logout")
def admin_logout() -> Response:
    return admin_logout_response()


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
app.include_router(admin_router)

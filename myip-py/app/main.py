from fastapi import FastAPI, Request
from starlette.responses import Response

from app.api.health import router as health_router
from app.api.ip import router as ip_router

app = FastAPI(title="myip-py", version="0.1.0")


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

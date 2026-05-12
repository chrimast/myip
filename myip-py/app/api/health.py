from datetime import UTC, datetime

from fastapi import APIRouter

from app.core.config import get_settings

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def health_check() -> dict:
    settings = get_settings()
    return {
        "ok": True,
        "time": datetime.now(UTC).isoformat(),
        "keys": settings.key_status(),
        "config": settings.public_config(),
    }

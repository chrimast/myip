from fastapi import APIRouter, Depends

from app.core.config import Settings, get_settings
from app.services.admin_config import admin_fields, admin_providers, admin_settings

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/settings")
def settings(settings: Settings = Depends(get_settings)) -> dict:
    return admin_settings(settings)


@router.get("/providers")
def providers(settings: Settings = Depends(get_settings)) -> list[dict]:
    return admin_providers(settings)


@router.get("/fields")
def fields() -> list[dict]:
    return admin_fields()

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.exceptions import RequestValidationError

from app.core.config import Settings, get_settings
from app.services.admin_config import (
    admin_fields,
    admin_providers,
    admin_settings,
    read_provider_config,
    reset_provider_config,
    write_provider_config,
)
from app.services.ip_lookup import (
    IPInfo,
    IPLookupProvider,
    IPLookupUnavailable,
    enrich_ip_intelligence,
    get_ip_lookup_provider,
    _network_category,
)
from app.services.target_ip import DNSResolutionError, resolve_target

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


@router.get("/provider-config")
def provider_config() -> dict:
    return read_provider_config()


@router.put("/provider-config")
def save_provider_config(payload: dict) -> dict:
    return write_provider_config(payload)


@router.post("/provider-config/reset")
def reset_saved_provider_config() -> dict:
    return reset_provider_config()


def admin_ip_lookup_provider() -> IPLookupProvider:
    return get_ip_lookup_provider()


@router.get("/lookup")
def lookup(
    target: str = Query(..., min_length=1),
    provider: IPLookupProvider = Depends(admin_ip_lookup_provider),
) -> dict:
    try:
        resolution = resolve_target(target)
    except RequestValidationError:
        raise
    except DNSResolutionError as exc:
        raise HTTPException(status_code=502, detail="DNS resolvers are temporarily unavailable") from exc

    try:
        result = provider.lookup(resolution.selected_ip)
    except IPLookupUnavailable as exc:
        raise HTTPException(status_code=502, detail="IP lookup providers are temporarily unavailable") from exc

    enriched = enrich_ip_intelligence(result)
    return _admin_lookup_payload(target, resolution, enriched)


def _admin_lookup_payload(target: str, resolution, info: IPInfo) -> dict:
    return {
        "input": target,
        "resolved_ip": resolution.selected_ip,
        "resolved_ips": resolution.resolved_ips,
        "dns_provider": resolution.dns_provider,
        "result": info.model_dump(),
        "field_sources": info.field_sources,
        "debug": {
            "provider": info.provider,
            "network_category": _network_category(info),
            "ip_property_scores": info.ip_property_scores,
            "risk_breakdown": info.risk_breakdown,
            "humanbot_breakdown": info.humanbot_breakdown,
        },
    }

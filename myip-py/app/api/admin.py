from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.exceptions import RequestValidationError

from app.core.config import Settings, get_settings
from app.services.admin_config import (
    add_custom_field,
    add_custom_provider,
    admin_fields,
    admin_providers,
    admin_settings,
    custom_provider_by_id,
    delete_custom_field,
    delete_custom_provider,
    PROVIDER_DEFINITIONS,
    read_provider_config,
    record_custom_provider_preview,
    reset_provider_config,
    write_provider_config,
)
from app.services.custom_provider_preview import GenericJSONLookupProvider, preview_custom_provider
from app.services.configured_ip_lookup import (
    apply_field_overrides,
    default_provider_factory,
    enabled_provider_config,
    lookup_with_config,
)
from app.services.ip_lookup import (
    IPInfo,
    IPLookupUnavailable,
    enrich_ip_intelligence,
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


@router.post("/custom-providers")
def create_custom_provider(payload: dict) -> dict:
    return add_custom_provider(payload)


@router.post("/custom-providers/preview")
def custom_provider_preview(payload: dict) -> dict:
    provider_id = payload.get("provider_id")
    if not provider_id:
        return preview_custom_provider(payload)
    provider = custom_provider_by_id(provider_id)
    try:
        preview = preview_custom_provider({"ip": payload.get("ip"), "provider": provider})
    except HTTPException as exc:
        record_custom_provider_preview(
            provider_id,
            {
                "status": "error",
                "ip": payload.get("ip"),
                "normalized": {},
                "missing_fields": list(provider.get("field_paths", {}).keys()),
                "error": str(exc.detail),
            },
        )
        raise
    return record_custom_provider_preview(provider_id, {**preview, "status": "ok", "ip": payload.get("ip")})


@router.delete("/custom-providers/{provider_id}")
def remove_custom_provider(provider_id: str) -> dict:
    return delete_custom_provider(provider_id)


@router.post("/custom-fields")
def create_custom_field(payload: dict) -> dict:
    return add_custom_field(payload)


@router.delete("/custom-fields/{field}")
def remove_custom_field(field: str) -> dict:
    return delete_custom_field(field)


@router.post("/provider-config/reset")
def reset_saved_provider_config() -> dict:
    return reset_provider_config()


@router.get("/config-status")
def config_status() -> dict:
    config = read_provider_config()
    uses_admin_config = bool(config["exists"])
    public_custom = bool(config.get("public_custom_providers_enabled"))
    require_preview_ok = bool(config.get("require_custom_provider_preview_ok"))
    public_custom_warnings = _public_custom_provider_warnings(config, public_custom)
    warning = None
    if uses_admin_config:
        warning = (
            "保存的后台 Provider 配置正在影响公开 /api/ip，且公开接口允许自定义 Provider"
            if public_custom
            else "保存的后台 Provider 配置正在影响公开 /api/ip"
        )
        if public_custom_warnings:
            warning = f"{warning}；公开自定义 Provider 存在验证风险"
    return {
        "public_lookup_mode": "admin-config-chain" if uses_admin_config else "default-production-chain",
        "uses_admin_provider_config": uses_admin_config,
        "provider_config_exists": uses_admin_config,
        "public_custom_providers_enabled": public_custom,
        "require_custom_provider_preview_ok": require_preview_ok,
        "public_custom_provider_warnings": public_custom_warnings,
        "storage_path": config["storage_path"],
        "warning": warning,
    }


def _public_custom_provider_warnings(config: dict, public_custom: bool) -> list[str]:
    if not public_custom:
        return []
    custom_providers = {provider["id"]: provider for provider in config.get("custom_providers", [])}
    warnings = []
    for provider_config in config.get("providers", []):
        provider_id = provider_config.get("id")
        if not provider_config.get("enabled") or provider_id not in custom_providers:
            continue
        last_preview = custom_providers[provider_id].get("last_preview")
        if not last_preview:
            warnings.append(f"{provider_id} 最近未验证")
        elif last_preview.get("status") != "ok":
            warnings.append(f"{provider_id} 最近验证失败")
    return warnings


def admin_ip_lookup_provider():
    custom_providers = {provider["id"]: provider for provider in read_provider_config()["custom_providers"]}

    def provider_factory(provider_id: str, timeout_seconds: float | None):
        if provider_id in custom_providers:
            return GenericJSONLookupProvider(custom_providers[provider_id], timeout_seconds)
        return default_provider_factory(provider_id, timeout_seconds)

    return provider_factory


@router.get("/lookup")
def lookup(
    target: str = Query(..., min_length=1),
    provider_factory=Depends(admin_ip_lookup_provider),
) -> dict:
    try:
        resolution = resolve_target(target)
    except RequestValidationError:
        raise
    except DNSResolutionError as exc:
        raise HTTPException(status_code=502, detail="DNS resolvers are temporarily unavailable") from exc

    try:
        lookup_result = lookup_with_config(resolution.selected_ip, provider_factory)
        filtered_result, disabled_fields = apply_field_overrides(lookup_result.result)
        enriched = enrich_ip_intelligence(filtered_result)
        return _admin_lookup_payload(
            target,
            resolution,
            enriched,
            lookup_result.provider_config,
            lookup_result.attempts,
            disabled_fields,
        )
    except IPLookupUnavailable as exc:
        raise HTTPException(status_code=502, detail="IP lookup providers are temporarily unavailable") from exc


def _admin_lookup_payload(
    target: str,
    resolution,
    info: IPInfo,
    provider_config: list[dict],
    attempts: list[dict],
    disabled_fields: list[str],
) -> dict:
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
            "provider_config": provider_config,
            "provider_attempts": attempts,
            "disabled_fields": disabled_fields,
        },
    }

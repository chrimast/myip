from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.exceptions import RequestValidationError

from app.core.config import Settings, get_settings
from app.services.admin_config import (
    admin_fields,
    admin_providers,
    admin_settings,
    PROVIDER_DEFINITIONS,
    read_provider_config,
    reset_provider_config,
    write_provider_config,
)
from app.services.ip_lookup import (
    IPInfo,
    IPAPIIsLookupProvider,
    IPLookupProvider,
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


@router.post("/provider-config/reset")
def reset_saved_provider_config() -> dict:
    return reset_provider_config()


def admin_ip_lookup_provider():
    return _provider_for_admin_config


def _provider_for_admin_config(provider_id: str, timeout_seconds: float | None) -> IPLookupProvider:
    provider = IPAPIIsLookupProvider()
    provider.settings.myip_provider_timeout_seconds = timeout_seconds or provider.settings.myip_provider_timeout_seconds
    lookup_name = {
        "ipapi.is": "_lookup_ipapi_is",
        "ipwho.is": "_lookup_ipwho",
        "ip-api.com": "_lookup_ip_api_com",
        "ipapi.org": "_lookup_ipapi_org",
        "ipinfo.io": "_lookup_ipinfo",
        "ipdata.co": "_lookup_ipdata",
    }[provider_id]
    return _SingleMethodProvider(provider, lookup_name)


class _SingleMethodProvider:
    def __init__(self, provider: IPAPIIsLookupProvider, lookup_name: str) -> None:
        self.provider = provider
        self.lookup_name = lookup_name

    def lookup(self, ip: str) -> IPInfo:
        return getattr(self.provider, self.lookup_name)(ip)


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

    attempts: list[dict] = []
    enabled_providers = _enabled_provider_config()
    last_error: Exception | None = None
    for provider_config in enabled_providers:
        provider_id = provider_config["id"]
        timeout_seconds = provider_config.get("timeout_seconds")
        try:
            provider = provider_factory(provider_id, timeout_seconds)
            result = provider.lookup(resolution.selected_ip)
            attempts.append({"provider": provider_id, "status": "ok", "timeout_seconds": timeout_seconds})
            enriched = enrich_ip_intelligence(result)
            return _admin_lookup_payload(target, resolution, enriched, enabled_providers, attempts)
        except IPLookupUnavailable as exc:
            last_error = exc
            attempts.append(
                {
                    "provider": provider_id,
                    "status": "error",
                    "timeout_seconds": timeout_seconds,
                    "error": str(exc),
                }
            )

    raise HTTPException(status_code=502, detail="IP lookup providers are temporarily unavailable") from last_error


def _admin_lookup_payload(target: str, resolution, info: IPInfo, provider_config: list[dict], attempts: list[dict]) -> dict:
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
        },
    }


def _enabled_provider_config() -> list[dict]:
    definitions = {provider["id"]: provider for provider in PROVIDER_DEFINITIONS}
    configured = []
    for provider in read_provider_config()["providers"]:
        if not provider.get("enabled", True):
            continue
        provider_id = provider["id"]
        if provider_id not in definitions:
            continue
        configured.append(
            {
                "id": provider_id,
                "order": provider["order"],
                "timeout_seconds": provider.get("timeout_seconds"),
                "role": definitions[provider_id]["role"],
            }
        )
    return sorted(configured, key=lambda item: (item["order"], item["id"]))

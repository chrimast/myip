from __future__ import annotations

from typing import Callable

from app.services.admin_config import PROVIDER_DEFINITIONS, read_provider_config
from app.services.ip_lookup import IPAPIIsLookupProvider, IPInfo, IPLookupProvider, IPLookupUnavailable, _merge_provider_results

ProviderFactory = Callable[[str, float | None], IPLookupProvider]


LOOKUP_METHODS = {
    "ipapi.is": "_lookup_ipapi_is",
    "ipwho.is": "_lookup_ipwho",
    "ip-api.com": "_lookup_ip_api_com",
    "ipapi.org": "_lookup_ipapi_org",
    "ipinfo.io": "_lookup_ipinfo",
    "ipdata.co": "_lookup_ipdata",
}


def configured_ip_lookup_provider() -> IPLookupProvider:
    return ConfiguredIPLookupProvider()


def default_provider_factory(provider_id: str, timeout_seconds: float | None) -> IPLookupProvider:
    provider = IPAPIIsLookupProvider()
    if timeout_seconds is not None:
        provider.settings.myip_provider_timeout_seconds = timeout_seconds
    return SingleMethodProvider(provider, LOOKUP_METHODS[provider_id])


class SingleMethodProvider:
    def __init__(self, provider: IPAPIIsLookupProvider, lookup_name: str) -> None:
        self.provider = provider
        self.lookup_name = lookup_name

    def lookup(self, ip: str) -> IPInfo:
        return getattr(self.provider, self.lookup_name)(ip)


class ConfiguredIPLookupProvider:
    def __init__(self, provider_factory: ProviderFactory = default_provider_factory) -> None:
        self.provider_factory = provider_factory

    def lookup(self, ip: str) -> IPInfo:
        attempts = lookup_with_config(ip, self.provider_factory, continue_after_success=True)
        return attempts.result


class ConfiguredLookupResult:
    def __init__(self, result: IPInfo, attempts: list[dict], provider_config: list[dict]) -> None:
        self.result = result
        self.attempts = attempts
        self.provider_config = provider_config


def lookup_with_config(
    ip: str,
    provider_factory: ProviderFactory = default_provider_factory,
    *,
    continue_after_success: bool = False,
) -> ConfiguredLookupResult:
    attempts: list[dict] = []
    results: list[IPInfo] = []
    enabled_providers = enabled_provider_config()
    last_error: Exception | None = None
    for provider_config in enabled_providers:
        provider_id = provider_config["id"]
        timeout_seconds = provider_config.get("timeout_seconds")
        try:
            provider = provider_factory(provider_id, timeout_seconds)
            result = provider.lookup(ip)
            attempts.append({"provider": provider_id, "status": "ok", "timeout_seconds": timeout_seconds})
            results.append(result)
            merged = _merge_provider_results(results)
            if result.field_sources:
                return ConfiguredLookupResult(result, attempts, enabled_providers)
            if not continue_after_success:
                return ConfiguredLookupResult(merged, attempts, enabled_providers)
            if not _needs_more_configured_fallback(merged, results, provider_config):
                return ConfiguredLookupResult(merged, attempts, enabled_providers)
        except (IPLookupUnavailable, ValueError, AssertionError) as exc:
            last_error = exc
            attempts.append(
                {
                    "provider": provider_id,
                    "status": "error",
                    "timeout_seconds": timeout_seconds,
                    "error": str(exc),
                }
            )
    if results:
        return ConfiguredLookupResult(_merge_provider_results(results), attempts, enabled_providers)
    raise IPLookupUnavailable(str(last_error) if last_error else "no enabled IP lookup providers") from last_error


def _needs_more_configured_fallback(info: IPInfo, results: list[IPInfo], provider_config: dict) -> bool:
    if provider_config["id"] == "ipapi.is":
        if not _has_field_value(info.country) and not _has_field_value(info.country_code):
            return True
        if any(not _has_field_value(value) for value in (info.asn, info.isp, info.city)):
            return True
        if not _has_field_value(info.asn_domain):
            return True
        return False
    if provider_config.get("role") == "basic fallback":
        return not _has_field_value(info.asn_domain)
    return False


def _has_field_value(value) -> bool:
    if isinstance(value, bool):
        return value is True
    return value is not None and value != ""


def apply_field_overrides(info: IPInfo) -> tuple[IPInfo, list[str]]:
    disabled_fields = disabled_fields_from_config()
    if not disabled_fields:
        return info, []

    payload = info.model_dump()
    for field in disabled_fields:
        if field not in payload:
            continue
        value = payload[field]
        payload[field] = False if isinstance(value, bool) else None

    filtered = IPInfo(**payload)
    filtered.field_sources = {
        field: source for field, source in info.field_sources.items() if field not in disabled_fields
    }
    return filtered, disabled_fields


def disabled_fields_from_config() -> list[str]:
    field_overrides = read_provider_config().get("field_overrides", {})
    return sorted(
        field
        for field, override in field_overrides.items()
        if isinstance(override, dict) and override.get("enabled") is False
    )


def enabled_provider_config() -> list[dict]:
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

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from app.core.config import Settings

PROVIDER_CONFIG_PATH = Path("data/admin_provider_config.json")
CONFIG_VERSION = 1

PROVIDER_DEFINITIONS: list[dict[str, Any]] = [
    {
        "id": "ipapi.is",
        "name": "ipapi.is",
        "enabled": True,
        "role": "primary",
        "fallback_phase": "primary",
        "endpoint": "https://api.ipapi.is",
        "requires_key": False,
        "key_name": "ipapi_is_key",
        "provides": [
            "ip",
            "country",
            "country_code",
            "region",
            "city",
            "asn",
            "asn_owner",
            "org",
            "isp",
            "latitude",
            "longitude",
            "network_type",
            "registry",
            "reg_region",
            "asn_domain",
            "org_domain",
            "is_proxy",
            "is_vpn",
            "is_tor",
            "is_mobile",
            "is_hosting",
            "is_crawler",
            "is_abuser",
        ],
        "field_paths": {
            "network_type": ["company.type", "asn.type"],
            "is_hosting": ["is_datacenter", "is_hosting", "hosting", "security.is_datacenter", "privacy.is_datacenter"],
            "is_proxy": ["is_proxy", "proxy", "security.proxy", "privacy.proxy"],
            "is_vpn": ["is_vpn", "vpn", "security.vpn", "privacy.vpn"],
            "is_tor": ["is_tor", "tor", "security.tor", "privacy.tor"],
            "is_mobile": ["is_mobile", "mobile"],
            "is_crawler": ["is_crawler", "crawler"],
            "is_abuser": ["is_abuser", "abuser"],
        },
    },
    {
        "id": "ipwho.is",
        "name": "ipwho.is",
        "enabled": True,
        "role": "basic fallback",
        "fallback_phase": "basic",
        "endpoint": "https://ipwho.is/{ip}",
        "requires_key": False,
        "key_name": None,
        "provides": [
            "ip",
            "country",
            "country_code",
            "region",
            "city",
            "asn",
            "asn_owner",
            "org",
            "isp",
            "latitude",
            "longitude",
            "network_type",
            "asn_domain",
            "org_domain",
            "is_proxy",
            "is_vpn",
            "is_tor",
            "is_hosting",
            "is_crawler",
            "is_abuser",
        ],
        "field_paths": {
            "network_type": ["connection.type", "connection.connection_type"],
            "is_proxy": ["security.proxy", "security.is_proxy"],
            "is_vpn": ["security.vpn", "security.is_vpn"],
            "is_tor": ["security.tor", "security.is_tor"],
            "is_hosting": ["security.hosting", "security.is_hosting"],
            "is_crawler": ["security.crawler", "security.is_crawler"],
            "is_abuser": ["security.abuser", "security.is_abuser", "security.threat", "security.is_threat"],
        },
    },
    {
        "id": "ip-api.com",
        "name": "ip-api.com",
        "enabled": True,
        "role": "basic fallback",
        "fallback_phase": "basic",
        "endpoint": "http://ip-api.com/json/{ip}",
        "requires_key": False,
        "key_name": None,
        "provides": [
            "ip",
            "country",
            "country_code",
            "region",
            "city",
            "asn",
            "asn_owner",
            "org",
            "isp",
            "latitude",
            "longitude",
            "is_proxy",
            "is_mobile",
            "is_hosting",
        ],
        "field_paths": {
            "is_proxy": ["proxy"],
            "is_mobile": ["mobile"],
            "is_hosting": ["hosting"],
        },
    },
    {
        "id": "ipapi.org",
        "name": "ipapi.org",
        "enabled": True,
        "role": "basic fallback",
        "fallback_phase": "basic",
        "endpoint": "https://ipapi.org/api/ip/{ip}",
        "requires_key": False,
        "key_name": "ipapi_org_key",
        "provides": [
            "ip",
            "country",
            "country_code",
            "region",
            "city",
            "asn",
            "asn_owner",
            "org",
            "isp",
            "latitude",
            "longitude",
        ],
        "field_paths": {},
    },
    {
        "id": "ipinfo.io",
        "name": "ipinfo.io",
        "enabled": True,
        "role": "domain fallback",
        "fallback_phase": "asn_domain",
        "endpoint": "https://ipinfo.io/{ip}/json",
        "requires_key": False,
        "key_name": "ipinfo_token",
        "provides": [
            "ip",
            "country",
            "region",
            "city",
            "asn",
            "org",
            "isp",
            "latitude",
            "longitude",
            "network_type",
            "asn_domain",
        ],
        "field_paths": {
            "network_type": ["asn.type", "network_type"],
        },
    },
    {
        "id": "ipdata.co",
        "name": "ipdata.co",
        "enabled": True,
        "role": "domain/security fallback",
        "fallback_phase": "asn_domain",
        "endpoint": "https://api.ipdata.co/{ip}",
        "requires_key": False,
        "key_name": "ipdata_key",
        "provides": [
            "ip",
            "country",
            "country_code",
            "region",
            "city",
            "asn",
            "asn_owner",
            "org",
            "isp",
            "latitude",
            "longitude",
            "network_type",
            "asn_domain",
            "is_proxy",
            "is_vpn",
            "is_tor",
            "is_hosting",
            "is_abuser",
        ],
        "field_paths": {
            "network_type": ["asn.type", "network_type", "usage_type"],
            "is_proxy": ["threat.is_proxy", "threat.is_anonymous", "threat.is_icloud"],
            "is_vpn": ["threat.is_vpn"],
            "is_tor": ["threat.is_tor"],
            "is_hosting": ["threat.is_datacenter", "threat.is_cloud_provider"],
            "is_abuser": [
                "threat.is_known_attacker",
                "threat.is_known_abuser",
                "threat.is_abuser",
                "threat.is_threat",
                "threat.is_spam",
            ],
        },
    },
]

FIELD_DEFINITIONS: list[dict[str, Any]] = [
    {
        "field": "network_type",
        "label": "网络类型",
        "source_type": "provider_structured",
        "scoring": True,
        "used_for": ["ip_property", "risk_confidence", "humanbot_confidence"],
        "providers": {
            "ipapi.is": ["company.type", "asn.type"],
            "ipwho.is": ["connection.type", "connection.connection_type"],
            "ipinfo.io": ["asn.type", "network_type"],
            "ipdata.co": ["asn.type", "network_type", "usage_type"],
        },
    },
    {
        "field": "is_hosting",
        "label": "托管/机房信号",
        "source_type": "provider_structured",
        "scoring": True,
        "used_for": ["ip_property", "risk_score", "humanbot"],
        "providers": {
            "ipapi.is": ["is_datacenter", "is_hosting", "hosting"],
            "ipwho.is": ["security.hosting", "security.is_hosting"],
            "ip-api.com": ["hosting"],
            "ipdata.co": ["threat.is_datacenter", "threat.is_cloud_provider"],
        },
    },
    {
        "field": "is_proxy",
        "label": "代理信号",
        "source_type": "provider_structured",
        "scoring": True,
        "used_for": ["risk_score", "humanbot"],
        "providers": {
            "ipapi.is": ["is_proxy", "proxy", "security.proxy", "privacy.proxy"],
            "ipwho.is": ["security.proxy", "security.is_proxy"],
            "ip-api.com": ["proxy"],
            "ipdata.co": ["threat.is_proxy", "threat.is_anonymous", "threat.is_icloud"],
        },
    },
    {
        "field": "is_vpn",
        "label": "VPN 信号",
        "source_type": "provider_structured",
        "scoring": True,
        "used_for": ["risk_score", "humanbot"],
        "providers": {
            "ipapi.is": ["is_vpn", "vpn", "security.vpn", "privacy.vpn"],
            "ipwho.is": ["security.vpn", "security.is_vpn"],
            "ipdata.co": ["threat.is_vpn"],
        },
    },
    {
        "field": "is_tor",
        "label": "TOR 信号",
        "source_type": "provider_structured",
        "scoring": True,
        "used_for": ["risk_score", "humanbot"],
        "providers": {
            "ipapi.is": ["is_tor", "tor", "security.tor", "privacy.tor"],
            "ipwho.is": ["security.tor", "security.is_tor"],
            "ipdata.co": ["threat.is_tor"],
        },
    },
    {
        "field": "is_mobile",
        "label": "移动网络信号",
        "source_type": "provider_structured",
        "scoring": True,
        "used_for": ["ip_property_home_leaning", "risk_discount", "confidence"],
        "providers": {
            "ipapi.is": ["is_mobile", "mobile"],
            "ip-api.com": ["mobile"],
        },
    },
    {
        "field": "is_crawler",
        "label": "爬虫信号",
        "source_type": "provider_structured",
        "scoring": True,
        "used_for": ["risk_score", "humanbot"],
        "providers": {
            "ipapi.is": ["is_crawler", "crawler"],
            "ipwho.is": ["security.crawler", "security.is_crawler"],
        },
    },
    {
        "field": "is_abuser",
        "label": "滥用信号",
        "source_type": "provider_structured",
        "scoring": True,
        "used_for": ["risk_score", "humanbot"],
        "providers": {
            "ipapi.is": ["is_abuser", "abuser"],
            "ipwho.is": ["security.abuser", "security.is_abuser", "security.threat", "security.is_threat"],
            "ipdata.co": [
                "threat.is_known_attacker",
                "threat.is_known_abuser",
                "threat.is_abuser",
                "threat.is_threat",
                "threat.is_spam",
            ],
        },
    },
    {
        "field": "ip_source",
        "label": "原生/广播 IP",
        "source_type": "derived",
        "scoring": True,
        "used_for": ["risk_score"],
        "providers": {
            "derived": ["reg_region", "country_code", "country"],
        },
    },
    {
        "field": "isp",
        "label": "ISP/运营商",
        "source_type": "identity_text",
        "scoring": False,
        "used_for": ["display", "compatibility"],
        "providers": {
            "ipapi.is": ["isp", "company.name", "asn.name", "asn.org"],
            "ipwho.is": ["connection.isp", "connection.org"],
            "ip-api.com": ["isp", "org"],
            "ipapi.org": ["isp", "org", "asn.name"],
            "ipinfo.io": ["org", "hostname"],
            "ipdata.co": ["asn.name", "organisation", "isp"],
        },
    },
    {
        "field": "org",
        "label": "企业/组织",
        "source_type": "identity_text",
        "scoring": False,
        "used_for": ["display", "compatibility"],
        "providers": {},
    },
    {
        "field": "asn_owner",
        "label": "ASN 所有者",
        "source_type": "identity_text",
        "scoring": False,
        "used_for": ["display", "compatibility"],
        "providers": {},
    },
    {
        "field": "asn_domain",
        "label": "ASN 域名",
        "source_type": "identity_text",
        "scoring": False,
        "used_for": ["display", "link"],
        "providers": {},
    },
    {
        "field": "org_domain",
        "label": "企业域名",
        "source_type": "identity_text",
        "scoring": False,
        "used_for": ["display", "link"],
        "providers": {},
    },
]


def admin_settings(settings: Settings) -> dict[str, Any]:
    return {"keys": settings.key_status(), "config": settings.public_config()}


def admin_providers(settings: Settings) -> list[dict[str, Any]]:
    key_status = settings.key_status()
    saved_config = read_provider_config()
    config_by_id = {provider["id"]: provider for provider in saved_config["providers"]}
    timeout = settings.myip_provider_timeout_seconds
    providers: list[dict[str, Any]] = []
    for index, definition in enumerate([*PROVIDER_DEFINITIONS, *saved_config["custom_providers"]], start=1):
        provider = dict(definition)
        key_name = provider["key_name"]
        override = config_by_id.get(provider["id"], {})
        provider["order"] = override.get("order", index)
        provider["enabled"] = override.get("enabled", provider["enabled"])
        provider["timeout_seconds"] = override.get("timeout_seconds") or timeout
        provider["timeout_override_seconds"] = override.get("timeout_seconds")
        provider["config_source"] = "json" if saved_config["exists"] else "default"
        provider["key_configured"] = bool(key_name and key_status.get(key_name, {}).get("configured"))
        providers.append(provider)
    return sorted(providers, key=lambda item: (item["order"], item["id"]))


def admin_fields() -> list[dict[str, Any]]:
    return [*FIELD_DEFINITIONS, *read_provider_config()["custom_fields"]]


def default_provider_config() -> dict[str, Any]:
    return {
        "version": CONFIG_VERSION,
        "providers": [
            {
                "id": provider["id"],
                "enabled": bool(provider["enabled"]),
                "order": index,
                "timeout_seconds": None,
            }
            for index, provider in enumerate(PROVIDER_DEFINITIONS, start=1)
        ],
        "field_overrides": {},
        "custom_providers": [],
        "custom_fields": [],
        "public_custom_providers_enabled": False,
    }


def read_provider_config() -> dict[str, Any]:
    config = default_provider_config()
    exists = PROVIDER_CONFIG_PATH.exists()
    if exists:
        raw = json.loads(PROVIDER_CONFIG_PATH.read_text(encoding="utf-8"))
        config = _normalize_provider_config(raw)
    config["storage_path"] = str(PROVIDER_CONFIG_PATH)
    config["exists"] = exists
    return config


def write_provider_config(payload: dict[str, Any]) -> dict[str, Any]:
    config = _normalize_provider_config(payload)
    PROVIDER_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    PROVIDER_CONFIG_PATH.write_text(
        json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return read_provider_config()


def reset_provider_config() -> dict[str, Any]:
    if PROVIDER_CONFIG_PATH.exists():
        PROVIDER_CONFIG_PATH.unlink()
    return read_provider_config()


def _normalize_provider_config(payload: dict[str, Any]) -> dict[str, Any]:
    custom_providers = _normalize_custom_providers(payload.get("custom_providers", []))
    custom_fields = _normalize_custom_fields(payload.get("custom_fields", []))
    custom_provider_defaults = {
        provider["id"]: {
            "id": provider["id"],
            "enabled": bool(provider.get("enabled", False)),
            "order": provider.get("order", len(PROVIDER_DEFINITIONS) + 100),
            "timeout_seconds": provider.get("timeout_seconds"),
        }
        for provider in custom_providers
    }
    known_provider_ids = {provider["id"] for provider in PROVIDER_DEFINITIONS} | set(custom_provider_defaults)
    known_fields = {field["field"] for field in FIELD_DEFINITIONS} | {field["field"] for field in custom_fields}
    defaults_by_id = {
        **{provider["id"]: provider for provider in default_provider_config()["providers"]},
        **custom_provider_defaults,
    }

    incoming_providers = payload.get("providers", [])
    if not isinstance(incoming_providers, list):
        raise HTTPException(status_code=422, detail="providers must be a list")

    merged_providers = {provider_id: dict(defaults_by_id[provider_id]) for provider_id in defaults_by_id}
    for provider in incoming_providers:
        if not isinstance(provider, dict):
            raise HTTPException(status_code=422, detail="provider override must be an object")
        provider_id = provider.get("id")
        if provider_id not in known_provider_ids:
            raise HTTPException(status_code=422, detail=f"unknown provider: {provider_id}")
        merged_providers[provider_id].update(
            {
                "id": provider_id,
                "enabled": bool(provider.get("enabled", merged_providers[provider_id]["enabled"])),
                "order": _positive_int(provider.get("order", merged_providers[provider_id]["order"]), "order"),
                "timeout_seconds": _optional_positive_float(provider.get("timeout_seconds"), "timeout_seconds"),
            }
        )

    field_overrides = payload.get("field_overrides", {}) or {}
    if not isinstance(field_overrides, dict):
        raise HTTPException(status_code=422, detail="field_overrides must be an object")
    normalized_fields: dict[str, dict[str, bool]] = {}
    for field, override in field_overrides.items():
        if field not in known_fields:
            raise HTTPException(status_code=422, detail=f"unknown field: {field}")
        if not isinstance(override, dict):
            raise HTTPException(status_code=422, detail="field override must be an object")
        if "enabled" in override:
            normalized_fields[field] = {"enabled": bool(override["enabled"])}

    return {
        "version": CONFIG_VERSION,
        "providers": sorted(merged_providers.values(), key=lambda item: (item["order"], item["id"])),
        "field_overrides": normalized_fields,
        "custom_providers": custom_providers,
        "custom_fields": custom_fields,
        "public_custom_providers_enabled": bool(payload.get("public_custom_providers_enabled", False)),
    }


def add_custom_provider(payload: dict[str, Any]) -> dict[str, Any]:
    config = read_provider_config()
    providers = [provider for provider in config["custom_providers"] if provider["id"] != payload.get("id")]
    providers.append(_normalize_custom_provider(payload))
    return write_provider_config({**_persistable_config(config), "custom_providers": providers})


def delete_custom_provider(provider_id: str) -> dict[str, Any]:
    config = read_provider_config()
    providers = [provider for provider in config["custom_providers"] if provider["id"] != provider_id]
    configured_providers = [provider for provider in config["providers"] if provider["id"] != provider_id]
    return write_provider_config(
        {**_persistable_config(config), "providers": configured_providers, "custom_providers": providers}
    )


def add_custom_field(payload: dict[str, Any]) -> dict[str, Any]:
    config = read_provider_config()
    fields = [field for field in config["custom_fields"] if field["field"] != payload.get("field")]
    fields.append(_normalize_custom_field(payload))
    return write_provider_config({**_persistable_config(config), "custom_fields": fields})


def delete_custom_field(field: str) -> dict[str, Any]:
    config = read_provider_config()
    fields = [item for item in config["custom_fields"] if item["field"] != field]
    config["field_overrides"].pop(field, None)
    return write_provider_config({**_persistable_config(config), "custom_fields": fields})


def _persistable_config(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "providers": config["providers"],
        "field_overrides": config["field_overrides"],
        "custom_providers": config["custom_providers"],
        "custom_fields": config["custom_fields"],
        "public_custom_providers_enabled": config.get("public_custom_providers_enabled", False),
    }


def _normalize_custom_providers(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise HTTPException(status_code=422, detail="custom_providers must be a list")
    providers = [_normalize_custom_provider(provider) for provider in value]
    ids = [provider["id"] for provider in providers]
    if len(ids) != len(set(ids)):
        raise HTTPException(status_code=422, detail="duplicate custom provider id")
    return sorted(providers, key=lambda provider: provider["id"])


def _normalize_custom_provider(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="custom provider must be an object")
    provider_id = _slug(payload.get("id"), "provider id")
    if provider_id in {provider["id"] for provider in PROVIDER_DEFINITIONS}:
        raise HTTPException(status_code=422, detail=f"custom provider conflicts with built-in provider: {provider_id}")
    provides = _string_list(payload.get("provides", []), "provides")
    return {
        "id": provider_id,
        "name": _non_empty_text(payload.get("name", provider_id), "name"),
        "enabled": False,
        "order": _positive_int(payload.get("order", len(PROVIDER_DEFINITIONS) + 100), "order"),
        "timeout_seconds": _optional_positive_float(payload.get("timeout_seconds"), "timeout_seconds"),
        "role": "custom metadata",
        "fallback_phase": "custom",
        "endpoint": _non_empty_text(payload.get("endpoint"), "endpoint"),
        "requires_key": bool(payload.get("requires_key", False)),
        "key_name": payload.get("key_name"),
        "provides": provides,
        "field_paths": _field_path_map(payload.get("field_paths", {}), provides),
        "transforms": _transform_map(payload.get("transforms", {}), provides),
        "custom": True,
    }


def _normalize_custom_fields(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise HTTPException(status_code=422, detail="custom_fields must be a list")
    fields = [_normalize_custom_field(field) for field in value]
    names = [field["field"] for field in fields]
    if len(names) != len(set(names)):
        raise HTTPException(status_code=422, detail="duplicate custom field")
    return sorted(fields, key=lambda field: field["field"])


def _normalize_custom_field(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="custom field must be an object")
    field = _slug(payload.get("field"), "field")
    if field in {definition["field"] for definition in FIELD_DEFINITIONS}:
        raise HTTPException(status_code=422, detail=f"custom field conflicts with built-in field: {field}")
    field_type = payload.get("type", "string")
    if field_type not in {"string", "bool", "int", "float", "list", "object"}:
        raise HTTPException(status_code=422, detail="custom field type is invalid")
    return {
        "field": field,
        "label": _non_empty_text(payload.get("label", field), "label"),
        "type": field_type,
        "source_type": payload.get("source_type", "custom"),
        "scoring": False,
        "used_for": _string_list(payload.get("used_for", ["display", "debug"]), "used_for"),
        "providers": _providers_map(payload.get("providers", {})),
        "custom": True,
    }


def _slug(value: Any, field: str) -> str:
    text = _non_empty_text(value, field)
    if not all(char.islower() or char.isdigit() or char in {"_", "-", "."} for char in text):
        raise HTTPException(status_code=422, detail=f"{field} must use lowercase letters, numbers, dot, dash or underscore")
    return text


def _non_empty_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(status_code=422, detail=f"{field} must be a non-empty string")
    return value.strip()


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise HTTPException(status_code=422, detail=f"{field} must be a list of strings")
    return value


def _field_path_map(value: Any, provides: list[str]) -> dict[str, list[str]]:
    mapping = _providers_map(value)
    unknown = set(mapping) - set(provides)
    if unknown:
        raise HTTPException(status_code=422, detail=f"field_paths contains fields not listed in provides: {sorted(unknown)}")
    return mapping


def _transform_map(value: Any, provides: list[str]) -> dict[str, str]:
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail="transforms must be an object")
    mapping = {str(field): str(transform) for field, transform in value.items()}
    unknown = set(mapping) - set(provides)
    if unknown:
        raise HTTPException(status_code=422, detail=f"transforms contains fields not listed in provides: {sorted(unknown)}")
    return mapping


def _providers_map(value: Any) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail="mapping must be an object")
    return {str(key): _string_list(paths, "paths") for key, paths in value.items()}


def normalize_custom_provider_preview(payload: Any) -> dict[str, Any]:
    return _normalize_custom_provider(payload)


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise HTTPException(status_code=422, detail=f"{field} must be a positive integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"{field} must be a positive integer") from exc
    if parsed < 1:
        raise HTTPException(status_code=422, detail=f"{field} must be a positive integer")
    return parsed


def _optional_positive_float(value: Any, field: str) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise HTTPException(status_code=422, detail=f"{field} must be positive")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"{field} must be positive") from exc
    if parsed <= 0:
        raise HTTPException(status_code=422, detail=f"{field} must be positive")
    return parsed

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from app.core.config import Settings
from app.services.ip_lookup import FIELD_PRIORITY_GROUPS, PROVIDER_FIELD_PRIORITIES

PROVIDER_CONFIG_PATH = Path("data/admin_provider_config.json")
CONFIG_VERSION = 1
AUTH_HASH_ALGORITHM = "pbkdf2_sha256"
BUILTIN_API_KEYS = {
    "ipapi_is_key": "ipapi_is_key",
    "ipapi_org_key": "ipapi_org_key",
    "ipinfo_token": "ipinfo_token",
    "ipdata_key": "ipdata_key",
}
SECRET_PREFIX = "encoded:"

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
        },
    },
    {
        "field": "org",
        "label": "企业/组织",
        "source_type": "identity_text",
        "scoring": False,
        "used_for": ["display", "compatibility"],
        "providers": {
            "ipapi.is": ["company.name"],
            "ipwho.is": ["connection.org"],
            "ip-api.com": ["org"],
            "ipapi.org": ["org", "asn.name"],
        },
    },
    {
        "field": "asn_owner",
        "label": "ASN 所有者",
        "source_type": "identity_text",
        "scoring": False,
        "used_for": ["display", "compatibility"],
        "providers": {
            "ipapi.is": ["asn.org"],
            "ipwho.is": ["connection.isp"],
            "ip-api.com": ["as"],
            "ipapi.org": ["asname", "asn.name"],
        },
    },
    {
        "field": "asn_domain",
        "label": "ASN 域名",
        "source_type": "identity_text",
        "scoring": False,
        "used_for": ["display", "link"],
        "providers": {
            "ipapi.is": ["asn.domain"],
            "ipinfo.io": ["asn.domain", "asn_domain", "as_domain"],
            "ipdata.co": ["asn.domain"],
        },
    },
    {
        "field": "org_domain",
        "label": "企业域名",
        "source_type": "identity_text",
        "scoring": False,
        "used_for": ["display", "link"],
        "providers": {
            "ipapi.is": ["company.domain"],
            "ipwho.is": ["connection.domain"],
        },
    },
]


def admin_settings(settings: Settings) -> dict[str, Any]:
    return {"keys": builtin_api_key_status(settings), "config": settings.public_config()}


def builtin_api_key_values(settings: Settings | None = None) -> dict[str, str]:
    settings = settings or Settings()
    admin_keys = read_provider_config(include_secrets=True).get("api_keys", {})
    return {
        key: str(_decode_secret(admin_keys.get(key)) or getattr(settings, attr, "") or "")
        for key, attr in BUILTIN_API_KEYS.items()
    }


def builtin_api_key_status(settings: Settings | None = None) -> dict[str, dict[str, bool | str]]:
    settings = settings or Settings()
    admin_keys = read_provider_config(include_secrets=True).get("api_keys", {})
    status = {}
    for key, attr in BUILTIN_API_KEYS.items():
        if admin_keys.get(key):
            status[key] = {"configured": True, "source": "admin"}
        else:
            value = getattr(settings, attr, "")
            status[key] = {"configured": bool(value), "source": "env" if value else "missing"}
    return status


def save_builtin_api_keys(payload: dict[str, Any], settings: Settings | None = None) -> dict[str, dict[str, bool | str]]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="api keys payload must be an object")
    config = read_provider_config(include_secrets=True)
    api_keys = dict(config.get("api_keys", {}))
    for key, value in payload.items():
        if key not in BUILTIN_API_KEYS:
            raise HTTPException(status_code=422, detail=f"unknown api key: {key}")
        if value is None or str(value).strip() == "":
            api_keys.pop(key, None)
        else:
            api_keys[key] = _encode_secret(str(value).strip())
    write_provider_config({**_persistable_config(config), "api_keys": api_keys})
    return builtin_api_key_status(settings)


def clear_builtin_api_key(key_name: str) -> None:
    if key_name not in BUILTIN_API_KEYS:
        raise HTTPException(status_code=422, detail=f"unknown api key: {key_name}")
    config = read_provider_config(include_secrets=True)
    api_keys = dict(config.get("api_keys", {}))
    api_keys.pop(key_name, None)
    write_provider_config({**_persistable_config(config), "api_keys": api_keys})


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
    saved_config = read_provider_config()
    mapping_overrides = saved_config.get("field_mappings", {})
    return [_field_view(field, mapping_overrides.get(field["field"])) for field in FIELD_DEFINITIONS]


def _field_view(field: dict[str, Any], mapping_override: dict[str, Any] | None = None) -> dict[str, Any]:
    enriched = dict(field)
    providers = dict((mapping_override or {}).get("providers") or enriched.get("providers") or {})
    priority = _provider_priority(enriched["field"], providers, (mapping_override or {}).get("provider_priority"))
    enriched["providers"] = providers
    enriched["mapping_source"] = "admin" if mapping_override else "default"
    enriched["display_name"] = enriched["field"]
    enriched["provider_priority"] = priority
    enriched["provider_mappings"] = [
        {"provider": provider, "paths": providers.get(provider, []), "priority": index}
        for index, provider in enumerate(priority, start=1)
    ]
    enriched["scoring_details"] = _scoring_details(enriched)
    return enriched


def _provider_priority(field_name: str, providers: dict[str, list[str]], configured_priority: Any = None) -> list[str]:
    configured_order = list(providers)
    if isinstance(configured_priority, list):
        preferred = [provider for provider in configured_priority if provider in providers]
        return [*preferred, *[provider for provider in configured_order if provider not in preferred]]
    group = FIELD_PRIORITY_GROUPS.get(field_name)
    if not group:
        return configured_order
    preferred = [provider for provider in PROVIDER_FIELD_PRIORITIES[group] if provider in providers]
    return [*preferred, *[provider for provider in configured_order if provider not in preferred]]


def _scoring_details(field: dict[str, Any]) -> dict[str, Any]:
    details = {
        "participates": bool(field.get("scoring")),
        "signals": list(field.get("used_for") or []),
        "rule": "仅用于展示/兼容，不直接参与评分",
    }
    field_name = field.get("field")
    if field_name == "network_type":
        details["rule"] = "识别 hosting/residential/business 网络类型，影响 IP 属性、风险置信度和人机置信度"
    elif field_name == "is_hosting":
        details["rule"] = "托管/机房信号会提高机房 IP、风险和机器人倾向"
    elif field_name in {"is_proxy", "is_vpn", "is_tor", "is_crawler", "is_abuser"}:
        details["rule"] = "风险布尔信号会提高风险分和机器人倾向"
    elif field_name == "is_mobile":
        details["rule"] = "移动网络信号通常降低风险并偏向家庭 IP，强风险存在时折扣变小"
    elif field_name == "ip_source":
        details["rule"] = "比较注册归属地 reg_region 与实际出口 country_code/country"
    return details


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
        "field_mappings": {},
        "custom_providers": [],
        "custom_fields": [],
        "runtime_settings": default_runtime_settings(),
        "public_custom_providers_enabled": False,
        "require_custom_provider_preview_ok": False,
    }


def read_provider_config(*, include_secrets: bool = False) -> dict[str, Any]:
    config = _read_provider_config()
    return config if include_secrets else _redact_provider_config(config)


def _read_provider_config() -> dict[str, Any]:
    config = default_provider_config()
    exists = PROVIDER_CONFIG_PATH.exists()
    if exists:
        raw = json.loads(PROVIDER_CONFIG_PATH.read_text(encoding="utf-8"))
        config = _normalize_provider_config(raw)
    config["storage_path"] = str(PROVIDER_CONFIG_PATH)
    config["exists"] = exists
    return config


def _redact_provider_config(config: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(config)
    redacted["custom_providers"] = [_redact_custom_provider(provider) for provider in config.get("custom_providers", [])]
    redacted["api_keys"] = {
        key: {"configured": bool(value), "source": "admin"}
        for key, value in config.get("api_keys", {}).items()
        if key in BUILTIN_API_KEYS
    }
    return redacted


def _redact_custom_provider(provider: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(provider)
    auth = redacted.get("auth")
    if isinstance(auth, dict):
        redacted["auth"] = {
            "type": auth.get("type", "none"),
            "name": auth.get("name"),
            "configured": bool(auth.get("value")),
        }
    return redacted


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
    custom_fields: list[dict[str, Any]] = []
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
    known_fields = {field["field"] for field in FIELD_DEFINITIONS}
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
            continue
        if not isinstance(override, dict):
            raise HTTPException(status_code=422, detail="field override must be an object")
        if "enabled" in override:
            normalized_fields[field] = {"enabled": bool(override["enabled"])}

    field_mappings = _normalize_field_mappings(
        _known_field_mapping_payload(payload.get("field_mappings", {}), known_fields), known_fields, known_provider_ids
    )

    if payload.get("require_custom_provider_preview_ok") and not payload.get("public_custom_providers_enabled"):
        raise HTTPException(
            status_code=422,
            detail="require_custom_provider_preview_ok requires public custom providers to be enabled",
        )

    normalized = {
        "version": CONFIG_VERSION,
        "providers": sorted(merged_providers.values(), key=lambda item: (item["order"], item["id"])),
        "field_overrides": normalized_fields,
        "field_mappings": field_mappings,
        "custom_providers": custom_providers,
        "custom_fields": custom_fields,
        "runtime_settings": _normalize_runtime_settings(payload.get("runtime_settings", default_runtime_settings())),
        "public_custom_providers_enabled": bool(payload.get("public_custom_providers_enabled", False)),
        "require_custom_provider_preview_ok": bool(payload.get("require_custom_provider_preview_ok", False)),
    }
    api_keys = _normalize_builtin_api_keys(payload.get("api_keys", {}))
    if api_keys:
        normalized["api_keys"] = api_keys
    if "admin_auth" in payload:
        normalized["admin_auth"] = _normalize_admin_auth(payload["admin_auth"])
    return normalized


def add_custom_provider(payload: dict[str, Any]) -> dict[str, Any]:
    config = read_provider_config(include_secrets=True)
    providers = [provider for provider in config["custom_providers"] if provider["id"] != payload.get("id")]
    providers.append(_normalize_custom_provider(payload))
    return write_provider_config({**_persistable_config(config), "custom_providers": providers})


def delete_custom_provider(provider_id: str) -> dict[str, Any]:
    config = read_provider_config(include_secrets=True)
    providers = [provider for provider in config["custom_providers"] if provider["id"] != provider_id]
    configured_providers = [provider for provider in config["providers"] if provider["id"] != provider_id]
    return write_provider_config(
        {**_persistable_config(config), "providers": configured_providers, "custom_providers": providers}
    )


def save_field_mappings(payload: dict[str, Any]) -> dict[str, Any]:
    config = read_provider_config(include_secrets=True)
    known_fields = {field["field"] for field in FIELD_DEFINITIONS}
    known_providers = {provider["id"] for provider in PROVIDER_DEFINITIONS} | {provider["id"] for provider in config["custom_providers"]}
    mappings = _normalize_field_mappings(payload, known_fields, known_providers)
    write_provider_config({**_persistable_config(config), "field_mappings": mappings})
    return mappings


def record_custom_provider_preview(provider_id: str, preview: dict[str, Any]) -> dict[str, Any]:
    config = read_provider_config(include_secrets=True)
    providers = []
    found = False
    for provider in config["custom_providers"]:
        if provider["id"] != provider_id:
            providers.append(provider)
            continue
        found = True
        providers.append({**provider, "last_preview": _preview_metadata(preview)})
    if not found:
        raise HTTPException(status_code=422, detail=f"unknown custom provider: {provider_id}")
    write_provider_config({**_persistable_config(config), "custom_providers": providers})
    return preview


def save_preview_field_mappings(provider_id: str, preview: dict[str, Any]) -> dict[str, dict[str, Any]]:
    config = read_provider_config(include_secrets=True)
    provider = custom_provider_by_id(provider_id)
    known_fields = {field["field"] for field in FIELD_DEFINITIONS}
    normalized = preview.get("normalized") or {}
    sources = preview.get("field_sources") or {}
    if not isinstance(normalized, dict) or not isinstance(sources, dict):
        raise HTTPException(status_code=422, detail="preview normalized fields are invalid")

    current = dict(config.get("field_mappings", {}))
    applied: dict[str, dict[str, Any]] = {}
    for field in sorted(normalized):
        if field not in known_fields or field not in sources:
            continue
        source_path = sources[field]
        provider_paths = provider.get("field_paths", {}).get(field) or [source_path]
        mapping = current.get(field) or _default_field_mapping(field)
        providers = {key: list(value) for key, value in (mapping.get("providers") or {}).items()}
        priority = list(mapping.get("provider_priority") or providers)
        paths = [source_path, *[path for path in provider_paths if path != source_path]]
        providers[provider_id] = paths
        priority = [provider_id, *[item for item in priority if item != provider_id]]
        current[field] = {"providers": providers, "provider_priority": priority}
        applied[field] = {"provider": provider_id, "paths": paths}
    write_provider_config({**_persistable_config(config), "field_mappings": current})
    return applied


def _default_field_mapping(field_name: str) -> dict[str, Any]:
    for field in FIELD_DEFINITIONS:
        if field["field"] == field_name:
            providers = dict(field.get("providers") or {})
            return {"providers": providers, "provider_priority": _provider_priority(field_name, providers)}
    return {"providers": {}, "provider_priority": []}


def custom_provider_by_id(provider_id: str, *, include_secrets: bool = False) -> dict[str, Any]:
    config = read_provider_config(include_secrets=include_secrets)
    for provider in config["custom_providers"]:
        if provider["id"] == provider_id:
            return provider
    raise HTTPException(status_code=422, detail=f"unknown custom provider: {provider_id}")


def _persistable_config(config: dict[str, Any]) -> dict[str, Any]:
    persisted = {
        "version": config["version"],
        "providers": config["providers"],
        "field_overrides": config["field_overrides"],
        "field_mappings": config.get("field_mappings", {}),
        "custom_providers": config["custom_providers"],
        "custom_fields": config["custom_fields"],
        "runtime_settings": config.get("runtime_settings", default_runtime_settings()),
        "public_custom_providers_enabled": config.get("public_custom_providers_enabled", False),
        "require_custom_provider_preview_ok": config.get("require_custom_provider_preview_ok", False),
    }
    if config.get("api_keys"):
        persisted["api_keys"] = config["api_keys"]
    if "admin_auth" in config:
        persisted["admin_auth"] = config["admin_auth"]
    return persisted


def default_admin_auth_config() -> dict[str, Any]:
    return {
        "username": "admin",
        "password_hash": hash_admin_password("admin"),
    }


def hash_admin_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000).hex()
    return f"{AUTH_HASH_ALGORITHM}${salt}${digest}"


def verify_admin_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, salt, expected = password_hash.split("$", 2)
    except ValueError:
        return False
    if algorithm != AUTH_HASH_ALGORITHM:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000).hex()
    return secrets.compare_digest(digest, expected)


def read_admin_auth_config() -> dict[str, Any]:
    return read_provider_config(include_secrets=True).get("admin_auth", default_admin_auth_config())


def public_admin_auth_config() -> dict[str, Any]:
    auth = read_admin_auth_config()
    return {"username": auth.get("username", "admin"), "password_configured": bool(auth.get("password_hash"))}


def save_admin_auth_config(payload: dict[str, Any]) -> dict[str, Any]:
    config = read_provider_config(include_secrets=True)
    current = config.get("admin_auth") or default_admin_auth_config()
    auth = _normalize_admin_auth(
        {
            "username": payload.get("username", current.get("username", "admin")),
            "password_hash": hash_admin_password(payload["password"]) if payload.get("password") else current.get("password_hash"),
        }
    )
    write_provider_config({**_persistable_config(config), "admin_auth": auth})
    return {"username": auth["username"], "password_configured": bool(auth.get("password_hash"))}


def _normalize_admin_auth(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="admin_auth must be an object")
    username = str(payload.get("username") or "admin").strip()
    if not username:
        raise HTTPException(status_code=422, detail="admin username is required")
    password_hash = str(payload.get("password_hash") or "").strip()
    if not password_hash:
        password_hash = default_admin_auth_config()["password_hash"]
    return {"username": username, "password_hash": password_hash}


def save_runtime_settings(payload: dict[str, Any]) -> dict[str, Any]:
    config = read_provider_config(include_secrets=True)
    runtime_settings = _normalize_runtime_settings(payload)
    write_provider_config({**_persistable_config(config), "runtime_settings": runtime_settings})
    return runtime_settings


def runtime_status() -> dict[str, Any]:
    effective = read_provider_config()["runtime_settings"]
    cache = effective.get("cache", {})
    rate_limit = effective.get("rate_limit", {})
    dns = effective.get("dns", {})
    bgp = effective.get("bgp", {})
    return {
        "effective": effective,
        "modules": {
            "ip_lookup": {
                "cache": "enabled" if cache.get("ip_enabled", True) else "disabled",
                "cache_ttl_seconds": cache.get("ip_ttl_seconds"),
                "rate_limit": "enabled" if rate_limit.get("ip_enabled", True) else "disabled",
                "rate_limit_per_minute": rate_limit.get("ip_per_minute"),
            },
            "bgp": {
                "enabled": bool(bgp.get("enabled", True)),
                "cache": "enabled" if cache.get("bgp_enabled", True) else "disabled",
                "default_upstream_limit": bgp.get("default_upstream_limit"),
                "max_upstream_limit": bgp.get("max_upstream_limit"),
            },
            "dns": {
                "doh": "enabled" if dns.get("doh_enabled", True) else "disabled",
                "provider_order": list(dns.get("doh_providers", [])),
                "timeout_seconds": dns.get("timeout_seconds"),
                "ip_version_preference": dns.get("ip_version_preference"),
            },
        },
        "actions": {"can_clear_cache": True},
    }


def import_preview(config: dict[str, Any]) -> dict[str, Any]:
    current = read_provider_config()
    incoming = _normalize_provider_config(config)
    return {"valid": True, "will_write": False, "diff": _config_diff(current, incoming), "config": _redact_provider_config(incoming)}


def _config_diff(current: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    return {
        "providers": _list_id_diff(current.get("providers", []), incoming.get("providers", []), "id"),
        "custom_providers": _list_id_diff(current.get("custom_providers", []), incoming.get("custom_providers", []), "id"),
        "custom_fields": _list_id_diff(current.get("custom_fields", []), incoming.get("custom_fields", []), "field"),
        "runtime_settings_changed": current.get("runtime_settings") != incoming.get("runtime_settings"),
        "field_mappings_changed": current.get("field_mappings", {}) != incoming.get("field_mappings", {}),
    }


def _list_id_diff(current_items: list[dict[str, Any]], incoming_items: list[dict[str, Any]], key: str) -> dict[str, list[str]]:
    current = {item[key]: item for item in current_items if key in item}
    incoming = {item[key]: item for item in incoming_items if key in item}
    return {
        "added": sorted(set(incoming) - set(current)),
        "removed": sorted(set(current) - set(incoming)),
        "changed": sorted(item_key for item_key in set(current) & set(incoming) if current[item_key] != incoming[item_key]),
    }


def default_runtime_settings() -> dict[str, Any]:
    settings = Settings()
    return {
        "cache": {
            "ip_enabled": True,
            "ip_ttl_seconds": settings.myip_cache_ttl_seconds,
            "ip_cache_granularity": "ipv4_24",
            "bgp_enabled": True,
            "bgp_ttl_seconds": 300,
        },
        "rate_limit": {
            "ip_enabled": True,
            "ip_per_minute": settings.myip_rate_limit_per_minute,
            "bgp_enabled": False,
            "bgp_per_minute": settings.myip_rate_limit_per_minute,
        },
        "dns": {
            "system_dns_enabled": False,
            "doh_enabled": True,
            "doh_providers": settings.doh_provider_names(),
            "timeout_seconds": settings.myip_doh_timeout_seconds,
            "ip_version_preference": "ipv4_first",
        },
        "bgp": {
            "enabled": True,
            "default_upstream_limit": 20,
            "max_upstream_limit": 50,
            "show_tier1": True,
            "show_edge_state": True,
            "cache_ttl_seconds": 300,
        },
    }


def _normalize_runtime_settings(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="runtime_settings must be an object")
    defaults = default_runtime_settings()
    cache = {**defaults["cache"], **(payload.get("cache") or {})}
    rate_limit = {**defaults["rate_limit"], **(payload.get("rate_limit") or {})}
    dns = {**defaults["dns"], **(payload.get("dns") or {})}
    bgp = {**defaults["bgp"], **(payload.get("bgp") or {})}
    providers = _string_list(dns.get("doh_providers", []), "doh_providers")
    unknown_providers = set(providers) - {"cloudflare", "google", "quad9"}
    if unknown_providers:
        raise HTTPException(status_code=422, detail=f"unknown DoH provider: {sorted(unknown_providers)}")
    preference = dns.get("ip_version_preference", "ipv4_first")
    granularity = cache.get("ip_cache_granularity", "ipv4_24")
    if granularity not in {"single_ip", "ipv4_24"}:
        raise HTTPException(status_code=422, detail="ip_cache_granularity is invalid")
    if preference not in {"ipv4_first", "ipv6_first"}:
        raise HTTPException(status_code=422, detail="ip_version_preference is invalid")
    max_upstreams = _positive_int(bgp.get("max_upstream_limit"), "max_upstream_limit")
    default_upstreams = _positive_int(bgp.get("default_upstream_limit"), "default_upstream_limit")
    if default_upstreams > max_upstreams:
        raise HTTPException(status_code=422, detail="default_upstream_limit must be <= max_upstream_limit")
    return {
        "cache": {
            "ip_enabled": bool(cache.get("ip_enabled")),
            "ip_ttl_seconds": _positive_int(cache.get("ip_ttl_seconds"), "ip_ttl_seconds"),
            "ip_cache_granularity": granularity,
            "bgp_enabled": bool(cache.get("bgp_enabled")),
            "bgp_ttl_seconds": _positive_int(cache.get("bgp_ttl_seconds"), "bgp_ttl_seconds"),
        },
        "rate_limit": {
            "ip_enabled": bool(rate_limit.get("ip_enabled")),
            "ip_per_minute": _positive_int(rate_limit.get("ip_per_minute"), "ip_per_minute"),
            "bgp_enabled": bool(rate_limit.get("bgp_enabled")),
            "bgp_per_minute": _positive_int(rate_limit.get("bgp_per_minute"), "bgp_per_minute"),
        },
        "dns": {
            "system_dns_enabled": bool(dns.get("system_dns_enabled")),
            "doh_enabled": bool(dns.get("doh_enabled")),
            "doh_providers": providers,
            "timeout_seconds": _optional_positive_float(dns.get("timeout_seconds"), "timeout_seconds") or defaults["dns"]["timeout_seconds"],
            "ip_version_preference": preference,
        },
        "bgp": {
            "enabled": bool(bgp.get("enabled")),
            "default_upstream_limit": default_upstreams,
            "max_upstream_limit": max_upstreams,
            "show_tier1": bool(bgp.get("show_tier1")),
            "show_edge_state": bool(bgp.get("show_edge_state")),
            "cache_ttl_seconds": _positive_int(bgp.get("cache_ttl_seconds"), "cache_ttl_seconds"),
        },
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
        "requires_key": bool(payload.get("requires_key", False)) or _normalize_auth(payload).get("type") != "none",
        "key_name": payload.get("key_name") or _normalize_auth(payload).get("name"),
        "auth": _normalize_auth(payload),
        "provides": provides,
        "field_paths": _field_path_map(payload.get("field_paths", {}), provides),
        "transforms": _transform_map(payload.get("transforms", {}), provides),
        "last_preview": _last_preview(payload.get("last_preview")),
        "custom": True,
    }


def _normalize_auth(payload: dict[str, Any]) -> dict[str, Any]:
    raw = payload.get("auth") or {}
    if not isinstance(raw, dict):
        raise HTTPException(status_code=422, detail="auth must be an object")
    auth_type = raw.get("type") or ("api_key" if payload.get("requires_key") else "none")
    if auth_type not in {"none", "api_key", "bearer_token"}:
        raise HTTPException(status_code=422, detail="auth type is invalid")
    name = raw.get("name") or payload.get("key_name")
    value = raw.get("value")
    if auth_type == "none":
        return {"type": "none", "name": None, "value": None}
    if not isinstance(name, str) or not name.strip():
        raise HTTPException(status_code=422, detail="auth name is required")
    configured_without_value = bool(raw.get("configured")) or "value" in raw
    if not isinstance(value, str) or not value.strip():
        if configured_without_value:
            return {"type": auth_type, "name": name.strip(), "value": None}
        raise HTTPException(status_code=422, detail="auth value is required")
    return {"type": auth_type, "name": name.strip(), "value": value.strip()}

def _encode_secret(value: str) -> str:
    if value.startswith(SECRET_PREFIX):
        return value
    return SECRET_PREFIX + base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")


def _decode_secret(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    if not value.startswith(SECRET_PREFIX):
        return value
    try:
        return base64.urlsafe_b64decode(value[len(SECRET_PREFIX):].encode("ascii")).decode("utf-8")
    except Exception:
        return ""


def _normalize_builtin_api_keys(value: Any) -> dict[str, str]:
    if value in (None, {}):
        return {}
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail="api_keys must be an object")
    normalized = {}
    for key, secret in value.items():
        if key not in BUILTIN_API_KEYS:
            raise HTTPException(status_code=422, detail=f"unknown api key: {key}")
        if isinstance(secret, str) and secret.strip():
            normalized[key] = _encode_secret(secret.strip())
    return normalized


def _known_field_mapping_payload(value: Any, known_fields: set[str]) -> Any:
    if not isinstance(value, dict):
        return value
    return {field: mapping for field, mapping in value.items() if field in known_fields}


def _normalize_field_mappings(value: Any, known_fields: set[str], known_providers: set[str]) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail="field_mappings must be an object")
    normalized: dict[str, dict[str, Any]] = {}
    for field, mapping in value.items():
        if field not in known_fields:
            raise HTTPException(status_code=422, detail=f"unknown field: {field}")
        if not isinstance(mapping, dict):
            raise HTTPException(status_code=422, detail="field mapping must be an object")
        providers = _providers_map(mapping.get("providers", {}))
        unknown_providers = set(providers) - known_providers
        if unknown_providers:
            raise HTTPException(status_code=422, detail=f"unknown provider in field mapping: {sorted(unknown_providers)}")
        provider_priority = mapping.get("provider_priority", list(providers))
        priority = _string_list(provider_priority, "provider_priority")
        unknown_priority = set(priority) - set(providers)
        if unknown_priority:
            raise HTTPException(status_code=422, detail=f"provider_priority contains providers without paths: {sorted(unknown_priority)}")
        if providers:
            normalized[str(field)] = {
                "providers": providers,
                "provider_priority": [*priority, *[provider for provider in providers if provider not in priority]],
            }
    return normalized


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


def _preview_metadata(preview: dict[str, Any]) -> dict[str, Any]:
    return _last_preview(
        {
            "status": preview.get("status", "ok"),
            "ip": preview.get("ip"),
            "checked_at": _utc_now_iso(),
            "normalized_fields": sorted(preview.get("normalized", {}).keys()),
            "missing_fields": preview.get("missing_fields", []),
            "error": preview.get("error"),
        }
    )


def _last_preview(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail="last_preview must be an object")
    status = value.get("status")
    if status not in {"ok", "error"}:
        raise HTTPException(status_code=422, detail="last_preview status is invalid")
    metadata = {
        "status": status,
        "ip": _non_empty_text(value.get("ip"), "last_preview.ip"),
        "checked_at": _non_empty_text(value.get("checked_at"), "last_preview.checked_at"),
        "normalized_fields": _string_list(value.get("normalized_fields", []), "normalized_fields"),
        "missing_fields": _string_list(value.get("missing_fields", []), "missing_fields"),
    }
    if value.get("error"):
        metadata["error"] = _non_empty_text(value.get("error"), "last_preview.error")
    return metadata


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


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

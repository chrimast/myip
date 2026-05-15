from typing import Any, Protocol
from urllib.parse import quote

import httpx
from pydantic import BaseModel, Field

from app.core.config import get_settings


class IPInfo(BaseModel):
    ip: str
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    asn: str | None = None
    asn_owner: str | None = None
    org: str | None = None
    isp: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    provider: str
    network_type: str | None = None
    ip_source: str | None = None
    ip_source_reason: str | None = None
    ip_property: str | None = None
    ip_property_reason: str | None = None
    ip_property_scores: dict[str, int] | None = None
    risk_score: int | None = None
    risk_reason: str | None = None
    risk_breakdown: dict[str, int] | None = None
    risk_confidence: float | None = None
    human_percent: float | None = None
    bot_percent: float | None = None
    humanbot_reason: str | None = None
    humanbot_breakdown: dict[str, float] | None = None
    humanbot_confidence: float | None = None
    registry: str | None = None
    reg_region: str | None = None
    asn_domain: str | None = None
    org_domain: str | None = None
    is_proxy: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    is_mobile: bool = False
    is_hosting: bool = False
    is_crawler: bool = False
    is_abuser: bool = False
    field_sources: dict[str, str] = Field(default_factory=dict, exclude=True)


class IPLookupResponse(IPInfo):
    input: str | None = None
    resolved_ip: str | None = None
    resolved_ips: list[str] | None = None
    dns_provider: str | None = None
    geo_provider: str | None = None
    query: str | None = None
    countryCode: str | None = None
    regionName: str | None = None
    lat: float | None = None
    lon: float | None = None
    org: str | None = None
    as_field: str | None = Field(default=None, serialization_alias="as")
    asn_owner: str = ""
    asn_domain: str = ""
    org_domain: str = ""
    registry: str = ""
    reg_region: str = ""
    proxy: bool = False
    hosting: bool = False
    mobile: bool = False
    status: str = "success"


class IPLookupProvider(Protocol):
    def lookup(self, ip: str) -> IPInfo: ...


IP_LOOKUP_TIMEOUT_SECONDS = 8.0
IP_API_FIELDS = "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as,mobile,proxy,hosting"


class IPLookupUnavailable(RuntimeError):
    pass


class StaticIPLookupProvider:
    def __init__(self, result: IPInfo) -> None:
        self.result = result

    def lookup(self, ip: str) -> IPInfo:
        return self.result


class IPAPIIsLookupProvider:
    provider_name = "ipapi.is"
    endpoint = "https://api.ipapi.is"

    def __init__(self) -> None:
        self.settings = get_settings()

    def lookup(self, ip: str) -> IPInfo:
        results: list[IPInfo] = []
        last_error: Exception | None = None

        def run(lookup) -> bool:
            nonlocal last_error
            try:
                results.append(lookup(ip))
                return True
            except (httpx.HTTPError, ValueError, AssertionError) as exc:
                last_error = exc
                return False

        run(self._lookup_ipapi_is)
        merged = _merge_provider_results(results) if results else None
        if merged is None or _needs_basic_fallback(merged):
            for lookup in (self._lookup_ipwho, self._lookup_ip_api_com, self._lookup_ipapi_org):
                run(lookup)
                merged = _merge_provider_results(results) if results else None
                if _has_provider(results, "ipapi.org"):
                    break
                if merged is not None and not _needs_basic_fallback(merged):
                    break

        merged = _merge_provider_results(results) if results else None
        if merged is None or _needs_asn_domain_fallback(merged):
            for lookup in (self._lookup_ipinfo, self._lookup_ipdata):
                run(lookup)
                merged = _merge_provider_results(results) if results else None
                if merged is not None and not _needs_asn_domain_fallback(merged) and _has_provider(results, "ipdata.co"):
                    break

        merged = _merge_provider_results(results) if results else None
        if merged is not None and _needs_org_domain_fallback(merged) and not _has_provider(results, "ipwho.is"):
            run(self._lookup_ipwho)

        if results:
            result = _merge_provider_results(results)
            if not result.field_sources:
                result.field_sources = _field_sources_for(result, result.provider)
            return result

        raise IPLookupUnavailable(str(last_error)) from last_error

    def _get_json(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        response = httpx.get(url, params=params, timeout=self.settings.myip_provider_timeout_seconds)
        response.raise_for_status()
        return response.json()

    def _params_with_optional_key(
        self,
        params: dict[str, str] | None,
        key_name: str,
        key_value: str,
    ) -> dict[str, str] | None:
        if not key_value:
            return params
        merged = dict(params or {})
        merged[key_name] = key_value
        return merged

    def _lookup_ipapi_is(self, ip: str) -> IPInfo:
        data = self._get_json(
            self.endpoint,
            params=self._params_with_optional_key({"q": ip}, "key", self.settings.ipapi_is_key),
        )
        if error := _string(data, "error"):
            raise ValueError(error)
        provider_ip = _matching_ip(data, "ip", ip, "ipapi.is")

        location = _mapping(data, "location")
        location_country = _mapping(location, "country")
        asn = _mapping(data, "asn")
        company = _mapping(data, "company")

        return IPInfo(
            ip=provider_ip,
            country=_first_string(
                _string(location_country, "name"),
                _string(location, "country"),
                _string(data, "country"),
            ),
            country_code=_first_string(
                _string(location_country, "code"),
                _string(location, "country_code"),
                _string(data, "country_code"),
            ),
            region=_first_string(_string(location, "state"), _string(location, "region")),
            city=_first_string(_string(location, "city"), _string(data, "city")),
            asn=_format_asn(asn.get("asn")),
            asn_owner=_string(asn, "org") or None,
            org=_string(company, "name") or None,
            isp=_first_string(
                _string(data, "isp"),
                _string(company, "name"),
                _string(asn, "name"),
                _string(asn, "org"),
            ),
            latitude=_first_float(location.get("latitude"), location.get("lat"), data.get("lat")),
            longitude=_first_float(
                location.get("longitude"),
                location.get("lon"),
                data.get("lon"),
            ),
            provider=self.provider_name,
            network_type=_first_string(_string(company, "type"), _string(asn, "type")),
            registry=_first_string(_string(asn, "rir"), _string(asn, "registry")),
            reg_region=_first_string(_string(asn, "country"), _string(location, "country_code"), _string(location_country, "code")),
            asn_domain=_string(asn, "domain") or None,
            org_domain=_string(company, "domain") or None,
            is_proxy=_bool_any(data, "is_proxy", "proxy") or _bool_any(_mapping(data, "security"), "is_proxy", "proxy") or _bool_any(_mapping(data, "privacy"), "is_proxy", "proxy"),
            is_vpn=_bool_any(data, "is_vpn", "vpn") or _bool_any(_mapping(data, "security"), "is_vpn", "vpn") or _bool_any(_mapping(data, "privacy"), "is_vpn", "vpn"),
            is_tor=_bool_any(data, "is_tor", "tor") or _bool_any(_mapping(data, "security"), "is_tor", "tor") or _bool_any(_mapping(data, "privacy"), "is_tor", "tor"),
            is_mobile=_bool_any(data, "is_mobile", "mobile"),
            is_hosting=_bool_any(data, "is_datacenter", "is_hosting", "hosting") or _bool_any(_mapping(data, "security"), "is_datacenter", "is_hosting", "hosting") or _bool_any(_mapping(data, "privacy"), "is_datacenter", "is_hosting", "hosting"),
            is_crawler=_bool_any(data, "is_crawler", "crawler"),
            is_abuser=_bool_any(data, "is_abuser", "abuser"),
        )

    def _lookup_ipwho(self, ip: str) -> IPInfo:
        data = self._get_json(f"https://ipwho.is/{quote(ip, safe='')}")
        if data.get("success") is False:
            raise ValueError(_string(data, "message") or "ipwho.is lookup failed")
        provider_ip = _matching_ip(data, "ip", ip, "ipwho.is")

        connection = _mapping(data, "connection")
        security = _mapping(data, "security")
        return IPInfo(
            ip=provider_ip,
            country=_string(data, "country") or None,
            country_code=_string(data, "country_code") or None,
            region=_first_string(_string(data, "region"), _string(data, "state")),
            city=_string(data, "city") or None,
            asn=_format_asn(connection.get("asn")),
            asn_owner=_string(connection, "isp") or None,
            org=_string(connection, "org") or None,
            isp=_first_string(_string(connection, "isp"), _string(connection, "org")),
            asn_domain=_string(connection, "domain") or None,
            org_domain=_string(connection, "domain") or None,
            latitude=_first_float(data.get("latitude"), data.get("lat")),
            longitude=_first_float(data.get("longitude"), data.get("lon")),
            provider="ipwho.is",
            is_proxy=_bool_any(security, "proxy", "is_proxy"),
            is_vpn=_bool_any(security, "vpn", "is_vpn"),
            is_tor=_bool_any(security, "tor", "is_tor"),
            is_hosting=_bool_any(security, "hosting", "is_hosting"),
            is_crawler=_bool_any(security, "crawler", "is_crawler"),
            is_abuser=_bool_any(security, "abuser", "is_abuser", "threat", "is_threat"),
        )

    def _lookup_ip_api_com(self, ip: str) -> IPInfo:
        data = self._get_json(
            f"http://ip-api.com/json/{quote(ip, safe='')}",
            params={"fields": IP_API_FIELDS},
        )
        if data.get("status") != "success":
            raise ValueError(_string(data, "message") or "ip-api.com lookup failed")
        provider_ip = _matching_ip(data, "query", ip, "ip-api.com")

        asn, _owner = _parse_as_field(_string(data, "as"))
        return IPInfo(
            ip=provider_ip,
            country=_string(data, "country") or None,
            country_code=_string(data, "countryCode") or None,
            region=_string(data, "regionName") or None,
            city=_string(data, "city") or None,
            asn=asn,
            asn_owner=_owner,
            org=_first_string(_string(data, "org"), _string(data, "isp")),
            isp=_first_string(_string(data, "isp"), _string(data, "org")),
            latitude=_first_float(data.get("lat")),
            longitude=_first_float(data.get("lon")),
            provider="ip-api.com",
            is_proxy=bool(data.get("proxy")),
            is_mobile=bool(data.get("mobile")),
            is_hosting=bool(data.get("hosting")),
        )

    def _lookup_ipapi_org(self, ip: str) -> IPInfo:
        data = self._get_json(
            f"https://ipapi.org/api/ip/{quote(ip, safe='')}",
            params=self._params_with_optional_key(None, "key", self.settings.ipapi_org_key),
        )
        provider_ip = _matching_ip(data, "ip", ip, "ipapi.org")
        asn = _mapping(data, "asn")
        location = _mapping(data, "location")
        return IPInfo(
            ip=provider_ip,
            country=_first_string(_string(data, "country_name"), _string(data, "country")),
            country_code=_first_string(_string(data, "country_code"), _string(data, "countryCode")),
            region=_first_string(_string(data, "region"), _string(location, "region")),
            city=_first_string(_string(data, "city"), _string(location, "city")),
            asn=_format_asn(_first_string(_string(data, "asn"), _string(asn, "asn"))),
            asn_owner=_first_string(_string(data, "asname"), _string(data, "isp"), _string(asn, "name")),
            org=_first_string(_string(data, "org"), _string(data, "isp"), _string(asn, "name")),
            isp=_first_string(_string(data, "isp"), _string(data, "org"), _string(asn, "name")),
            latitude=_first_float(data.get("latitude"), data.get("lat"), location.get("latitude")),
            longitude=_first_float(data.get("longitude"), data.get("lon"), location.get("longitude")),
            provider="ipapi.org",
        )

    def _lookup_ipinfo(self, ip: str) -> IPInfo:
        data = self._get_json(
            f"https://ipinfo.io/{quote(ip, safe='')}/json",
            params=self._params_with_optional_key(None, "token", self.settings.ipinfo_token),
        )
        if error := _string(data, "error"):
            raise ValueError(error)
        provider_ip = _matching_ip(data, "ip", ip, "ipinfo.io")
        asn = _mapping(data, "asn")
        latitude, longitude = _parse_loc(_string(data, "loc"))
        return IPInfo(
            ip=provider_ip,
            country=_string(data, "country") or None,
            region=_string(data, "region") or None,
            city=_string(data, "city") or None,
            asn=_format_asn(_string(data, "asn")),
            org=_first_string(_string(data, "org"), _string(data, "hostname")),
            isp=_first_string(_string(data, "org"), _string(data, "hostname")),
            latitude=latitude,
            longitude=longitude,
            asn_domain=_first_string(_string(asn, "domain"), _string(data, "asn_domain")),
            provider="ipinfo.io",
        )

    def _lookup_ipdata(self, ip: str) -> IPInfo:
        data = self._get_json(
            f"https://api.ipdata.co/{quote(ip, safe='')}",
            params=self._params_with_optional_key(None, "api-key", self.settings.ipdata_key),
        )
        if _string(data, "message") and not _string(data, "ip"):
            raise ValueError(_string(data, "message"))
        provider_ip = _matching_ip(data, "ip", ip, "ipdata.co")
        asn = _mapping(data, "asn")
        threat = _mapping(data, "threat")
        return IPInfo(
            ip=provider_ip,
            country=_first_string(_string(data, "country_name"), _string(data, "country")),
            country_code=_string(data, "country_code") or None,
            region=_string(data, "region") or None,
            city=_string(data, "city") or None,
            asn=_format_asn(_first_string(_string(asn, "asn"), _string(data, "asn"))),
            asn_owner=_string(asn, "name") or None,
            org=_first_string(_string(data, "organisation"), _string(data, "isp"), _string(asn, "name")),
            isp=_first_string(_string(asn, "name"), _string(data, "organisation"), _string(data, "isp")),
            latitude=_first_float(data.get("latitude"), data.get("lat")),
            longitude=_first_float(data.get("longitude"), data.get("lon")),
            asn_domain=_string(asn, "domain") or None,
            provider="ipdata.co",
            is_proxy=_bool_any(threat, "is_proxy", "is_anonymous", "is_icloud") or _bool_any(data, "is_proxy", "is_anonymous", "is_icloud"),
            is_vpn=_bool_any(threat, "is_vpn") or _bool_any(data, "is_vpn"),
            is_tor=_bool_any(threat, "is_tor") or _bool_any(data, "is_tor"),
            is_hosting=_bool_any(threat, "is_datacenter", "is_cloud_provider") or _bool_any(data, "is_datacenter", "is_cloud_provider"),
            is_abuser=_bool_any(threat, "is_known_attacker", "is_known_abuser", "is_abuser", "is_threat", "is_spam") or _bool_any(data, "is_known_attacker", "is_known_abuser", "is_abuser", "is_threat", "is_spam"),
        )


def _mapping(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def _bool_any(data: dict[str, Any], *keys: str) -> bool:
    return any(data.get(key) is True for key in keys)


def _string(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    return value.strip() if isinstance(value, str) else ""


def _required_string(data: dict[str, Any], key: str, message: str) -> str:
    value = _string(data, key)
    if not value:
        raise ValueError(message)
    return value


def _matching_ip(data: dict[str, Any], key: str, expected_ip: str, provider: str) -> str:
    value = _required_string(data, key, f"{provider} response missing {key}")
    if value != expected_ip:
        raise ValueError(f"{provider} response IP does not match requested IP")
    return value


def _first_string(*values: str) -> str | None:
    return next((value for value in values if value), None)


def _first_float(*values: Any) -> float | None:
    for value in values:
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                continue
    return None


def _format_asn(value: Any) -> str | None:
    if isinstance(value, int):
        return f"AS{value}"
    if isinstance(value, str) and value.strip():
        stripped = value.strip()
        return stripped if stripped.upper().startswith("AS") else f"AS{stripped}"
    return None


def _parse_as_field(value: str) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    parts = value.split(maxsplit=1)
    asn = _format_asn(parts[0])
    owner = parts[1].strip() if len(parts) > 1 else None
    return asn, owner or None


def _parse_loc(value: str) -> tuple[float | None, float | None]:
    if not value or "," not in value:
        return None, None
    latitude, longitude = value.split(",", maxsplit=1)
    return _first_float(latitude), _first_float(longitude)


def _needs_basic_fallback(info: IPInfo) -> bool:
    if not (_has_field_value(info.country) or _has_field_value(info.country_code)):
        return True
    return any(not _has_field_value(value) for value in (info.asn, info.isp, info.city))


def _has_provider(results: list[IPInfo], provider: str) -> bool:
    return any(result.provider == provider for result in results)


def _needs_asn_domain_fallback(info: IPInfo) -> bool:
    return not _has_field_value(info.asn_domain) and not _needs_basic_fallback(info)


def _needs_org_domain_fallback(info: IPInfo) -> bool:
    return False


def _is_complete_provider_result(info: IPInfo) -> bool:
    required = (info.country, info.country_code, info.asn, info.isp)
    return all(value is not None and value != "" for value in required)


def _merge_provider_results(results: list[IPInfo]) -> IPInfo:
    if len(results) == 1:
        return results[0]
    merged = results[0].model_copy(deep=True)
    sources = _field_sources_for(merged, merged.provider)
    provider_names = [merged.provider]
    fields = (
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
    )

    for result in results[1:]:
        provider_names.append(result.provider)
        for field in fields:
            value = getattr(result, field)
            current = getattr(merged, field)
            if _should_take_field(current, value):
                setattr(merged, field, value)
                sources[field] = result.provider

    merged.provider = "+".join(dict.fromkeys(provider_names))
    merged.field_sources = sources
    return merged


def _field_sources_for(info: IPInfo, provider: str) -> dict[str, str]:
    fields = (
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
    )
    return {field: provider for field in fields if _has_field_value(getattr(info, field))}


def _should_take_field(current: Any, value: Any) -> bool:
    if not _has_field_value(value):
        return False
    if isinstance(value, bool):
        return value is True and current is not True
    return not _has_field_value(current)


def _has_field_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value is True
    return value is not None and value != ""


def get_ip_lookup_provider() -> IPLookupProvider:
    return IPAPIIsLookupProvider()


def enrich_ip_intelligence(info: IPInfo) -> IPInfo:
    data = info.model_copy(deep=True)
    property_scores = _property_scores(data)
    data.ip_property_scores = property_scores
    data.ip_property = _best_property(property_scores)
    data.ip_property_reason = _ip_property_reason(data, property_scores)
    data.ip_source = _ip_source(data)
    data.ip_source_reason = _ip_source_reason(data)
    data.risk_breakdown = _risk_breakdown(data)
    data.risk_score = _clamp(sum(data.risk_breakdown.values()), 0, 100)
    data.risk_reason = _risk_reason(data)
    data.risk_confidence = _risk_confidence(data)
    bot_score = _clamp(_bot_score(data), 0, 100)
    data.bot_percent = float(bot_score)
    data.human_percent = float(100 - bot_score)
    data.humanbot_reason = _humanbot_reason(data)
    data.humanbot_breakdown = {"human": data.human_percent, "bot": data.bot_percent}
    data.humanbot_confidence = _humanbot_confidence(data)
    return data


def _property_scores(info: IPInfo) -> dict[str, int]:
    scores = {"机房IP": 0, "家庭IP": 0, "商业IP": 0}
    category = _network_category(info)

    if category == "hosting":
        scores["机房IP"] += 90
    elif category == "residential":
        scores["家庭IP"] += 80
    elif category == "business":
        scores["商业IP"] += 30

    if info.is_mobile and scores["机房IP"] == 0:
        scores["家庭IP"] += 60
    if all(value == 0 for value in scores.values()):
        scores["家庭IP"] = 3
    return scores


def _network_category(info: IPInfo) -> str:
    network_type = (info.network_type or "").lower()
    if info.is_hosting:
        return "hosting"
    if _contains_any(network_type, ("hosting", "datacenter", "data center", "cloud", "vps", "server", "colo")):
        return "hosting"
    if _contains_any(network_type, ("residential", "consumer", "home", "broadband", "fiber", "cable", "dsl", "isp")):
        return "residential"
    if _contains_any(network_type, ("business", "enterprise", "corporate", "commercial")):
        return "business"
    return "unknown"


def _best_property(scores: dict[str, int]) -> str:
    best = "家庭IP"
    if scores["商业IP"] > scores[best]:
        best = "商业IP"
    if scores["机房IP"] >= scores[best] and scores["机房IP"] > 0:
        best = "机房IP"
    return best


def _ip_source(info: IPInfo) -> str:
    reg_region = _normalize_region_code(info.reg_region)
    exit_region = _normalize_region_code(info.country_code or info.country)
    if not reg_region or not exit_region:
        return "原生IP"
    if reg_region == exit_region:
        return "原生IP"
    return "广播IP"


def _ip_source_reason(info: IPInfo) -> str:
    reg_region = _normalize_region_code(info.reg_region)
    exit_region = _normalize_region_code(info.country_code or info.country)
    if not reg_region:
        return "缺少注册归属地，默认按实际出口地理位置视为一致"
    if not exit_region:
        return "缺少实际出口地理位置，默认按注册归属地视为一致"
    relation = "一致" if reg_region == exit_region else "不一致"
    registry = info.registry or "未知注册机构"
    return f"注册归属地/注册机构与实际出口地理位置{relation}: {registry}/{reg_region} vs {exit_region}"


def _normalize_region_code(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().upper()
    if not normalized:
        return None
    aliases = {
        "UNITED STATES": "US",
        "UNITED STATES OF AMERICA": "US",
        "USA": "US",
        "JAPAN": "JP",
        "CHINA": "CN",
        "HONG KONG": "HK",
        "HONG KONG SAR": "HK",
        "TAIWAN": "TW",
        "SINGAPORE": "SG",
        "GERMANY": "DE",
        "UNITED KINGDOM": "GB",
        "UK": "GB",
    }
    return aliases.get(normalized, normalized)


def _ip_property_reason(info: IPInfo, scores: dict[str, int]) -> str:
    return ", ".join(f"{key}:{value}" for key, value in scores.items())


def _risk_reason(info: IPInfo) -> str:
    return "基于代理/VPN/TOR/托管网络/爬虫/滥用信号与注册地差异综合评估"


def _humanbot_reason(info: IPInfo) -> str:
    return "基于 IP 属性和风险信号估算人机流量比例"


def _risk_breakdown(info: IPInfo) -> dict[str, int]:
    breakdown = {"base": 10}
    if info.is_abuser:
        breakdown["abuser"] = 35
    if info.is_crawler:
        breakdown["crawler"] = 25
    if info.is_tor:
        breakdown["tor"] = 40
    if info.is_vpn:
        breakdown["vpn"] = 24
    if info.is_proxy:
        breakdown["proxy"] = 28
    if info.is_hosting:
        breakdown["hosting"] = 20
    if info.ip_source == "广播IP":
        breakdown["broadcast"] = 10
    if info.ip_property == "机房IP":
        breakdown["datacenter"] = 12
    if info.is_mobile and not any(key in breakdown for key in ("tor", "proxy", "vpn", "hosting", "abuser", "crawler")):
        breakdown["mobile_residential_discount"] = -8
    return breakdown


def _bot_score(info: IPInfo) -> int:
    score = 10
    has_strong_risk = any((info.is_tor, info.is_proxy, info.is_vpn, info.is_hosting, info.is_abuser, info.is_crawler))
    if info.is_abuser:
        score += 35
    if info.is_crawler:
        score += 30
    if info.is_tor:
        score += 40
    if info.is_proxy:
        score += 28
    if info.is_vpn:
        score += 20
    if info.is_hosting:
        score += 18
    if info.is_mobile:
        score -= 6 if has_strong_risk else 12
    if info.ip_source == "广播IP":
        score += 10
    if info.ip_property == "机房IP":
        score += 8
    elif info.ip_property == "商业IP":
        score += 5
    elif info.ip_property == "家庭IP":
        score -= 8
    return score


def _contains_any(value: str, needles: tuple[str, ...]) -> bool:
    return any(needle in value for needle in needles)


def _risk_confidence(info: IPInfo) -> float:
    confidence = 0.45
    if any((info.is_proxy, info.is_vpn, info.is_tor, info.is_hosting, info.is_crawler, info.is_abuser)):
        confidence += 0.25
    elif info.is_mobile:
        confidence += 0.1
    if info.network_type:
        confidence += 0.15
    if info.reg_region and (info.country_code or info.country):
        confidence += 0.05
    return round(min(confidence, 0.9), 2)


def _humanbot_confidence(info: IPInfo) -> float:
    confidence = 0.4
    if any((info.is_proxy, info.is_vpn, info.is_tor, info.is_hosting, info.is_crawler, info.is_abuser)):
        confidence += 0.2
    elif info.is_mobile:
        confidence += 0.1
    if info.network_type:
        confidence += 0.15
    if info.ip_property_scores and max(info.ip_property_scores.values()) >= 60:
        confidence += 0.05
    return round(min(confidence, 0.85), 2)


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))

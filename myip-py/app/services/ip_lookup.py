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
    isp: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    provider: str
    network_type: str | None = None
    ip_property: str | None = None
    risk_score: int | None = None
    risk_breakdown: dict[str, int] | None = None
    human_percent: float | None = None
    bot_percent: float | None = None
    is_proxy: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    is_mobile: bool = False
    is_hosting: bool = False
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
        for lookup in (
            self._lookup_ipapi_is,
            self._lookup_ipwho,
            self._lookup_ip_api_com,
            self._lookup_ipapi_org,
            self._lookup_ipinfo,
            self._lookup_ipdata,
        ):
            try:
                results.append(lookup(ip))
                if _is_complete_provider_result(_merge_provider_results(results)):
                    break
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc

        if results:
            return _merge_provider_results(results)

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
            isp=_first_string(
                _string(asn, "org"),
                _string(asn, "name"),
                _string(company, "name"),
            ),
            latitude=_first_float(location.get("latitude"), location.get("lat"), data.get("lat")),
            longitude=_first_float(
                location.get("longitude"),
                location.get("lon"),
                data.get("lon"),
            ),
            provider=self.provider_name,
            network_type=_first_string(_string(company, "type"), _string(asn, "type")),
            is_proxy=_bool_any(data, "is_proxy", "proxy") or _bool_any(_mapping(data, "security"), "is_proxy", "proxy") or _bool_any(_mapping(data, "privacy"), "is_proxy", "proxy"),
            is_vpn=_bool_any(data, "is_vpn", "vpn") or _bool_any(_mapping(data, "security"), "is_vpn", "vpn") or _bool_any(_mapping(data, "privacy"), "is_vpn", "vpn"),
            is_tor=_bool_any(data, "is_tor", "tor") or _bool_any(_mapping(data, "security"), "is_tor", "tor") or _bool_any(_mapping(data, "privacy"), "is_tor", "tor"),
            is_hosting=_bool_any(data, "is_hosting", "hosting") or _bool_any(_mapping(data, "security"), "is_hosting", "hosting") or _bool_any(_mapping(data, "privacy"), "is_hosting", "hosting"),
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
            isp=_first_string(_string(connection, "isp"), _string(connection, "org")),
            latitude=_first_float(data.get("latitude"), data.get("lat")),
            longitude=_first_float(data.get("longitude"), data.get("lon")),
            provider="ipwho.is",
            is_proxy=_bool_any(security, "proxy", "is_proxy"),
            is_vpn=_bool_any(security, "vpn", "is_vpn"),
            is_tor=_bool_any(security, "tor", "is_tor"),
            is_hosting=_bool_any(security, "hosting", "is_hosting"),
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
        latitude, longitude = _parse_loc(_string(data, "loc"))
        return IPInfo(
            ip=provider_ip,
            country=_string(data, "country") or None,
            region=_string(data, "region") or None,
            city=_string(data, "city") or None,
            asn=_format_asn(_string(data, "asn")),
            isp=_first_string(_string(data, "org"), _string(data, "hostname")),
            latitude=latitude,
            longitude=longitude,
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
            isp=_first_string(_string(asn, "name"), _string(data, "organisation"), _string(data, "isp")),
            latitude=_first_float(data.get("latitude"), data.get("lat")),
            longitude=_first_float(data.get("longitude"), data.get("lon")),
            provider="ipdata.co",
            is_proxy=_bool_any(threat, "is_proxy", "is_anonymous", "is_icloud") or _bool_any(data, "is_proxy", "is_anonymous", "is_icloud"),
            is_tor=_bool_any(threat, "is_tor") or _bool_any(data, "is_tor"),
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
        "isp",
        "latitude",
        "longitude",
        "network_type",
        "is_proxy",
        "is_vpn",
        "is_tor",
        "is_mobile",
        "is_hosting",
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
        "isp",
        "latitude",
        "longitude",
        "network_type",
        "is_proxy",
        "is_vpn",
        "is_tor",
        "is_mobile",
        "is_hosting",
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
    data.ip_property = _best_property(property_scores)
    data.risk_breakdown = _risk_breakdown(data)
    data.risk_score = _clamp(sum(data.risk_breakdown.values()), 0, 100)
    bot_score = _clamp(_bot_score(data), 0, 100)
    data.bot_percent = float(bot_score)
    data.human_percent = float(100 - bot_score)
    return data


def _property_scores(info: IPInfo) -> dict[str, int]:
    scores = {"机房IP": 0, "家庭IP": 0, "商业IP": 0}
    network_type = (info.network_type or "").lower()
    blob = " ".join(value for value in (info.isp, info.network_type) if value).lower()

    if info.is_hosting:
        scores["机房IP"] += 75
    if info.is_tor:
        scores["机房IP"] += 60
    if info.is_proxy:
        scores["机房IP"] += 35
    if info.is_vpn:
        scores["机房IP"] += 35
    if info.is_mobile:
        scores["家庭IP"] += 60 if scores["机房IP"] < 70 else 10

    if any(word in network_type for word in ("business", "enterprise")):
        scores["商业IP"] += 30
    if any(word in network_type for word in ("residential", "consumer", "home")):
        scores["家庭IP"] += 25
    if any(word in network_type for word in ("hosting", "datacenter", "data center", "cloud")):
        scores["机房IP"] += 35

    if _contains_any(blob, ("hosting", "datacenter", "data center", "cloud", "vps", "server", "colo")):
        scores["机房IP"] += 8
    if scores["机房IP"] < 60 and _contains_any(blob, ("telecom", "broadband", "mobile", "fiber", "cable", "dsl", "isp")):
        scores["家庭IP"] += 12
    if _contains_any(blob, ("inc", "llc", "ltd", "corp", "enterprise")):
        scores["商业IP"] += 6
    if all(value == 0 for value in scores.values()):
        scores["家庭IP"] = 3
    return scores


def _best_property(scores: dict[str, int]) -> str:
    best = "家庭IP"
    if scores["商业IP"] > scores[best]:
        best = "商业IP"
    if scores["机房IP"] >= scores[best] and scores["机房IP"] > 0:
        best = "机房IP"
    return best


def _risk_breakdown(info: IPInfo) -> dict[str, int]:
    breakdown = {"base": 10}
    if info.is_tor:
        breakdown["tor"] = 30
    if info.is_proxy:
        breakdown["proxy"] = 20
    if info.is_vpn:
        breakdown["vpn"] = 16
    if info.is_hosting:
        breakdown["hosting"] = 14
    if info.ip_property == "机房IP":
        breakdown["datacenter"] = 10
    if _contains_any(" ".join(value for value in (info.isp, info.network_type) if value).lower(), ("cloud", "hosting", "vps", "server", "cdn")):
        breakdown["cloud_hint"] = 6
    if info.is_mobile and not any(key in breakdown for key in ("tor", "proxy", "vpn", "hosting")):
        breakdown["mobile"] = -8
    return breakdown


def _bot_score(info: IPInfo) -> int:
    score = 10
    if info.is_tor:
        score += 45
    if info.is_proxy:
        score += 30
    if info.is_vpn:
        score += 22
    if info.is_hosting:
        score += 18
    if info.ip_property == "机房IP":
        score += 10
    elif info.ip_property == "商业IP":
        score += 7
    elif info.ip_property == "家庭IP":
        score -= 8
    if info.is_mobile:
        score -= 12
    return score


def _contains_any(value: str, needles: tuple[str, ...]) -> bool:
    return any(needle in value for needle in needles)


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))

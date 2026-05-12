from typing import Any, Protocol
from urllib.parse import quote

import httpx
from pydantic import BaseModel


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


class IPLookupProvider(Protocol):
    def lookup(self, ip: str) -> IPInfo: ...


IP_LOOKUP_TIMEOUT_SECONDS = 8.0
IP_API_FIELDS = "status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as"


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

    def lookup(self, ip: str) -> IPInfo:
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
                return lookup(ip)
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc

        raise IPLookupUnavailable(str(last_error)) from last_error

    def _get_json(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        response = httpx.get(url, params=params, timeout=IP_LOOKUP_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json()

    def _lookup_ipapi_is(self, ip: str) -> IPInfo:
        data = self._get_json(self.endpoint, params={"q": ip})
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
        )

    def _lookup_ipwho(self, ip: str) -> IPInfo:
        data = self._get_json(f"https://ipwho.is/{quote(ip, safe='')}")
        if data.get("success") is False:
            raise ValueError(_string(data, "message") or "ipwho.is lookup failed")
        provider_ip = _matching_ip(data, "ip", ip, "ipwho.is")

        connection = _mapping(data, "connection")
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
        )

    def _lookup_ipapi_org(self, ip: str) -> IPInfo:
        data = self._get_json(f"https://ipapi.org/api/ip/{quote(ip, safe='')}")
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
        data = self._get_json(f"https://ipinfo.io/{quote(ip, safe='')}/json")
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
        data = self._get_json(f"https://api.ipdata.co/{quote(ip, safe='')}")
        if _string(data, "message") and not _string(data, "ip"):
            raise ValueError(_string(data, "message"))
        provider_ip = _matching_ip(data, "ip", ip, "ipdata.co")
        asn = _mapping(data, "asn")
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
        )


def _mapping(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    return value if isinstance(value, dict) else {}


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


def get_ip_lookup_provider() -> IPLookupProvider:
    return IPAPIIsLookupProvider()

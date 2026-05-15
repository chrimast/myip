import re
import socket
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import quote

import httpx

USER_AGENT = "PurePure/1.0"
REGISTRY_TIMEOUT_SECONDS = 3.0


@dataclass(frozen=True)
class RegistryLookupResult:
    registry: str
    reg_region: str
    source: str


class RegistryLookupUnavailable(RuntimeError):
    pass


WhoisLookup = callable


class RegistryLookupClient:
    def __init__(self, *, timeout: float = REGISTRY_TIMEOUT_SECONDS, whois_lookup=None) -> None:
        self.timeout = timeout
        self.whois_lookup = whois_lookup or whois_reg_country

    def lookup(self, ip: str) -> RegistryLookupResult:
        normalized_ip = str(ip_address(ip))
        ripestat = self._lookup_ripestat(normalized_ip)
        if ripestat is not None:
            return ripestat

        rdap = self._lookup_rdap(normalized_ip)
        whois = self._lookup_whois(normalized_ip)
        if whois is not None and (rdap is None or whois.reg_region != rdap.reg_region):
            return whois
        if rdap is not None:
            return rdap
        if whois is not None:
            return whois
        raise RegistryLookupUnavailable("registry lookup failed")

    def _headers(self, accept: str = "application/json") -> dict[str, str]:
        return {"User-Agent": USER_AGENT, "Accept": accept}

    def _lookup_ripestat(self, ip: str) -> RegistryLookupResult | None:
        try:
            response = httpx.get(
                "https://stat.ripe.net/data/rir/data.json",
                params={"resource": ip, "lod": "2"},
                headers=self._headers(),
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
        except (httpx.HTTPError, ValueError, AttributeError):
            return None

        candidates = data.get("rirs") if isinstance(data, dict) else None
        if isinstance(candidates, list) and candidates:
            best = None
            best_score = -1
            for item in candidates:
                if not isinstance(item, dict):
                    continue
                score = score_resource_specificity(str(item.get("resource") or ""))
                if score > best_score:
                    best_score = score
                    best = item
            if best:
                rir = normalize_rir_name(str(best.get("rir") or ""))
                cc = normalize_country_code(str(best.get("country") or ""))
                if rir or cc:
                    return RegistryLookupResult(rir, cc, "ripestat")

        if isinstance(data, dict):
            rir = normalize_rir_name(str(data.get("rir") or ""))
            cc = normalize_country_code(str(data.get("country") or ""))
            if rir or cc:
                return RegistryLookupResult(rir, cc, "ripestat")
        return None

    def _lookup_rdap(self, ip: str) -> RegistryLookupResult | None:
        endpoints = (
            ("RDAP", "https://rdap.org/ip"),
            ("ARIN", "https://rdap.arin.net/registry/ip"),
            ("RIPE NCC", "https://rdap.db.ripe.net/ip"),
            ("APNIC", "https://rdap.apnic.net/ip"),
            ("LACNIC", "https://rdap.lacnic.net/rdap/ip"),
            ("AFRINIC", "https://rdap.afrinic.net/rdap/ip"),
        )
        for rir, base_url in endpoints:
            try:
                response = httpx.get(
                    f"{base_url}/{quote(ip, safe='')}",
                    headers=self._headers("application/rdap+json, application/json"),
                    timeout=self.timeout,
                )
                response.raise_for_status()
                cc = parse_rdap_country(response.json())
            except (httpx.HTTPError, ValueError, AttributeError):
                continue
            if cc:
                return RegistryLookupResult(normalize_rir_name(rir), cc, "rdap")
        return None

    def _lookup_whois(self, ip: str) -> RegistryLookupResult | None:
        try:
            server, cc = self.whois_lookup(ip)
        except OSError:
            return None
        cc = normalize_country_code(cc)
        if not cc:
            return None
        registry = normalize_rir_name(rir_from_whois_server(server) or "WHOIS")
        return RegistryLookupResult(registry, cc, "whois")


def normalize_country_code(cc: str) -> str:
    value = cc.strip().upper()
    if len(value) != 2 or not value.isalpha():
        return ""
    return value


def normalize_rir_name(rir: str) -> str:
    lowered = rir.strip().lower()
    if not lowered:
        return ""
    if "ripe" in lowered:
        return "RIPE NCC"
    if "rdap.org" in lowered or lowered == "rdap":
        return "RDAP"
    if "arin" in lowered:
        return "ARIN"
    if "apnic" in lowered:
        return "APNIC"
    if "lacnic" in lowered:
        return "LACNIC"
    if "afrinic" in lowered:
        return "AFRINIC"
    return rir.strip()


def score_resource_specificity(resource: str) -> int:
    value = resource.strip()
    if not value:
        return 0
    if "/" in value:
        try:
            return 1000 + int(value.rsplit("/", 1)[1])
        except ValueError:
            return 0
    return 1


def parse_rdap_country(data: dict) -> str:
    cc = normalize_country_code(str(data.get("country") or ""))
    if cc:
        return cc
    network = data.get("network")
    if isinstance(network, dict):
        cc = normalize_country_code(str(network.get("country") or ""))
        if cc:
            return cc
    entities = data.get("entities")
    if isinstance(entities, list):
        for entity in entities:
            if isinstance(entity, dict):
                cc = _rdap_country_from_vcard(entity)
                if cc:
                    return cc
    return ""


def _rdap_country_from_vcard(entity: dict) -> str:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return ""
    for prop in vcard[1]:
        if not isinstance(prop, list) or len(prop) < 4 or str(prop[0]).lower() != "adr":
            continue
        address = prop[3]
        if isinstance(address, list) and address:
            cc = normalize_country_code(str(address[-1] or ""))
            if cc:
                return cc
        if isinstance(address, str):
            cc = normalize_country_code(address)
            if cc:
                return cc
    return ""


def parse_whois_referral(body: str) -> str:
    for line in body.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() in {"refer", "whois", "whois server", "referralserver"}:
            cleaned = value.strip()
            if cleaned.lower().startswith("whois://"):
                cleaned = cleaned[8:]
            return cleaned.split("/", 1)[0].strip()
    return ""


def parse_whois_country(body: str) -> str:
    for line in body.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() == "country":
            cc = normalize_country_code(value)
            if cc:
                return cc
    return ""


def rir_from_whois_server(server: str) -> str:
    lowered = server.lower()
    if "arin" in lowered:
        return "ARIN"
    if "ripe" in lowered:
        return "RIPE NCC"
    if "apnic" in lowered:
        return "APNIC"
    if "lacnic" in lowered:
        return "LACNIC"
    if "afrinic" in lowered:
        return "AFRINIC"
    return ""


def whois_reg_country(ip: str) -> tuple[str, str]:
    referral = whois_query("whois.iana.org", ip)
    server = parse_whois_referral(referral)
    if not server:
        raise OSError("iana: no referral")
    body = whois_query(server, ip)
    return server, parse_whois_country(body)


def whois_query(server: str, query: str) -> str:
    host = server
    port = 43
    if ":" in server:
        host, port_text = server.rsplit(":", 1)
        port = int(port_text)
    with socket.create_connection((host, port), timeout=3.0) as sock:
        sock.settimeout(4.0)
        sock.sendall((query + "\r\n").encode())
        chunks = []
        total = 0
        while total < 256 * 1024:
            chunk = sock.recv(min(4096, 256 * 1024 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks).decode("utf-8", "replace")

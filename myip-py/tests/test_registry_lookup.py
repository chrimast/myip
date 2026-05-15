import httpx

from app.services.registry_lookup import (
    RegistryLookupClient,
    normalize_country_code,
    normalize_rir_name,
    parse_rdap_country,
    parse_whois_country,
    parse_whois_referral,
    score_resource_specificity,
)


def test_registry_lookup_prefers_most_specific_ripestat_rir_result(monkeypatch):
    calls = []

    class FakeResponse:
        status_code = 200
        text = ""

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "data": {
                    "rirs": [
                        {"rir": "RIPE", "country": "NL", "resource": "8.0.0.0/8"},
                        {"rir": "arin", "country": "US", "resource": "8.8.8.0/24"},
                    ]
                }
            }

    def fake_get(url: str, *, headers: dict | None = None, timeout: float, params: dict | None = None) -> FakeResponse:
        calls.append((url, params, headers, timeout))
        return FakeResponse()

    monkeypatch.setattr(httpx, "get", fake_get)

    result = RegistryLookupClient(timeout=2.0).lookup("8.8.8.8")

    assert result.registry == "ARIN"
    assert result.reg_region == "US"
    assert result.source == "ripestat"
    assert calls == [
        (
            "https://stat.ripe.net/data/rir/data.json",
            {"resource": "8.8.8.8", "lod": "2"},
            {"User-Agent": "PurePure/1.0", "Accept": "application/json"},
            2.0,
        )
    ]


def test_registry_lookup_falls_back_to_rdap_and_extracts_vcard_country(monkeypatch):
    calls = []

    class FakeResponse:
        def __init__(self, payload: dict, status_code: int = 200) -> None:
            self.payload = payload
            self.status_code = status_code
            self.text = ""

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise httpx.HTTPStatusError("bad", request=httpx.Request("GET", "https://example.test"), response=httpx.Response(self.status_code))

        def json(self) -> dict:
            return self.payload

    def fake_get(url: str, *, headers: dict | None = None, timeout: float, params: dict | None = None) -> FakeResponse:
        calls.append(url)
        if url == "https://stat.ripe.net/data/rir/data.json":
            raise httpx.ConnectError("ripestat down")
        if url == "https://rdap.org/ip/203.0.113.9":
            return FakeResponse({"entities": [{"vcardArray": ["vcard", [["adr", {}, "text", ["", "", "", "", "", "JP"]]]]}]})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = RegistryLookupClient(timeout=2.0).lookup("203.0.113.9")

    assert result.registry == "RDAP"
    assert result.reg_region == "JP"
    assert result.source == "rdap"
    assert calls == [
        "https://stat.ripe.net/data/rir/data.json",
        "https://rdap.org/ip/203.0.113.9",
    ]


def test_registry_lookup_uses_whois_country_when_it_disagrees_with_rdap(monkeypatch):
    calls = []

    class FakeResponse:
        def __init__(self, payload: dict | None = None, status_code: int = 200) -> None:
            self.payload = payload or {}
            self.status_code = status_code
            self.text = ""

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise httpx.HTTPStatusError("bad", request=httpx.Request("GET", "https://example.test"), response=httpx.Response(self.status_code))

        def json(self) -> dict:
            return self.payload

    def fake_get(url: str, *, headers: dict | None = None, timeout: float, params: dict | None = None) -> FakeResponse:
        calls.append(url)
        if url == "https://stat.ripe.net/data/rir/data.json":
            raise httpx.ConnectError("ripestat down")
        if url == "https://rdap.org/ip/8.8.8.8":
            return FakeResponse({"country": "NL"})
        raise AssertionError(f"unexpected URL: {url}")

    def fake_whois(ip: str) -> tuple[str, str]:
        assert ip == "8.8.8.8"
        return "whois.arin.net", "US"

    monkeypatch.setattr(httpx, "get", fake_get)

    result = RegistryLookupClient(timeout=2.0, whois_lookup=fake_whois).lookup("8.8.8.8")

    assert result.registry == "ARIN"
    assert result.reg_region == "US"
    assert result.source == "whois"


def test_registry_normalizers_and_parsers_match_go_logic():
    assert normalize_country_code(" us ") == "US"
    assert normalize_country_code("United States") == ""
    assert normalize_rir_name("ripe") == "RIPE NCC"
    assert normalize_rir_name("rdap.org") == "RDAP"
    assert score_resource_specificity("8.8.8.0/24") > score_resource_specificity("8.0.0.0/8")
    assert parse_rdap_country({"network": {"country": "de"}}) == "DE"
    assert parse_whois_referral("refer: whois.arin.net\n") == "whois.arin.net"
    assert parse_whois_country("NetName: Example\nCountry: ca\n") == "CA"

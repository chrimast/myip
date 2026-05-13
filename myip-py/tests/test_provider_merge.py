import httpx

from app.services.ip_lookup import IPAPIIsLookupProvider


def test_provider_merges_partial_results_and_tracks_field_sources(monkeypatch):
    calls: list[str] = []

    class FakeResponse:
        def __init__(self, payload: dict) -> None:
            self.payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self.payload

    def fake_get(url: str, *, params: dict[str, str] | None = None, timeout: float) -> FakeResponse:
        calls.append(url)
        if url == "https://api.ipapi.is":
            return FakeResponse(
                {
                    "ip": "8.8.8.8",
                    "location": {"country": {"name": "United States", "code": "US"}},
                    "asn": {"asn": 15169},
                }
            )
        if url == "https://ipwho.is/8.8.8.8":
            return FakeResponse(
                {
                    "success": True,
                    "ip": "8.8.8.8",
                    "region": "California",
                    "city": "Mountain View",
                    "latitude": 37.4056,
                    "longitude": -122.0775,
                    "connection": {"isp": "Google LLC"},
                    "security": {"proxy": True},
                }
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert calls == ["https://api.ipapi.is", "https://ipwho.is/8.8.8.8"]
    assert result.provider == "ipapi.is+ipwho.is"
    assert result.country == "United States"
    assert result.country_code == "US"
    assert result.asn == "AS15169"
    assert result.region == "California"
    assert result.city == "Mountain View"
    assert result.isp == "Google LLC"
    assert result.latitude == 37.4056
    assert result.longitude == -122.0775
    assert result.is_proxy is True
    assert result.field_sources == {
        "ip": "ipapi.is",
        "country": "ipapi.is",
        "country_code": "ipapi.is",
        "asn": "ipapi.is",
        "region": "ipwho.is",
        "city": "ipwho.is",
        "isp": "ipwho.is",
        "latitude": "ipwho.is",
        "longitude": "ipwho.is",
        "is_proxy": "ipwho.is",
    }

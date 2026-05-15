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
                    "location": {"country": {"name": "United States", "code": "US"}, "city": "Mountain View"},
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
                    "connection": {"isp": "Google LLC", "domain": "google.com"},
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
    assert result.asn_domain == "google.com"
    assert result.org_domain == "google.com"
    assert result.field_sources == {
        "ip": "ipapi.is",
        "country": "ipapi.is",
        "country_code": "ipapi.is",
        "asn": "ipapi.is",
        "asn_owner": "ipwho.is",
        "reg_region": "ipapi.is",
        "region": "ipwho.is",
        "city": "ipapi.is",
        "isp": "ipwho.is",
        "latitude": "ipwho.is",
        "longitude": "ipwho.is",
        "asn_domain": "ipwho.is",
        "org_domain": "ipwho.is",
        "is_proxy": "ipwho.is",
    }


def test_provider_maps_extra_ipapi_is_security_flags(monkeypatch):
    class FakeResponse:
        def __init__(self, payload: dict) -> None:
            self.payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self.payload

    def fake_get(url: str, *, params: dict[str, str] | None = None, timeout: float) -> FakeResponse:
        assert url == "https://api.ipapi.is"
        return FakeResponse(
            {
                "ip": "8.8.8.8",
                "location": {"country": {"name": "United States", "code": "US"}, "city": "Mountain View"},
                "asn": {"asn": 15169, "org": "Google LLC"},
                "is_datacenter": True,
                "is_crawler": True,
                "is_abuser": True,
                "is_mobile": True,
            }
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert result.is_hosting is True
    assert result.is_crawler is True
    assert result.is_abuser is True
    assert result.is_mobile is True
    assert result.field_sources["is_hosting"] == "ipapi.is"
    assert result.field_sources["is_crawler"] == "ipapi.is"
    assert result.field_sources["is_abuser"] == "ipapi.is"
    assert result.field_sources["is_mobile"] == "ipapi.is"


def test_provider_maps_extra_ipdata_threat_flags(monkeypatch):
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
            return FakeResponse({"error": "primary down"})
        if url == "https://ipwho.is/8.8.8.8":
            return FakeResponse({"success": False, "message": "fallback down"})
        if url.startswith("http://ip-api.com/json/8.8.8.8"):
            return FakeResponse({"status": "fail", "message": "fallback down"})
        if url == "https://ipapi.org/api/ip/8.8.8.8":
            return FakeResponse({})
        if url == "https://ipinfo.io/8.8.8.8/json":
            return FakeResponse({"error": "fallback down"})
        if url == "https://api.ipdata.co/8.8.8.8":
            return FakeResponse(
                {
                    "ip": "8.8.8.8",
                    "country_name": "United States",
                    "country_code": "US",
                    "city": "Mountain View",
                    "asn": {"asn": "15169", "name": "Google LLC", "domain": "google.com"},
                    "threat": {
                        "is_vpn": True,
                        "is_datacenter": True,
                        "is_known_attacker": True,
                    },
                }
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert "https://api.ipdata.co/8.8.8.8" in calls
    assert result.provider == "ipdata.co"
    assert result.is_vpn is True
    assert result.is_hosting is True
    assert result.is_abuser is True


def test_provider_maps_registry_and_registration_region_from_ipapi_is(monkeypatch):
    class FakeResponse:
        def __init__(self, payload: dict) -> None:
            self.payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self.payload

    def fake_get(url: str, *, params: dict[str, str] | None = None, timeout: float) -> FakeResponse:
        assert url == "https://api.ipapi.is"
        return FakeResponse(
            {
                "ip": "8.8.8.8",
                "location": {"country": {"name": "United States", "code": "US"}, "city": "Mountain View"},
                "asn": {
                    "asn": 15169,
                    "org": "Google LLC",
                    "registry": "arin",
                    "rir": "ARIN",
                    "country": "US",
                    "domain": "google.com",
                },
                "company": {"domain": "google.com"},
            }
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert result.registry == "ARIN"
    assert result.reg_region == "US"
    assert result.field_sources["registry"] == "ipapi.is"
    assert result.field_sources["reg_region"] == "ipapi.is"


def test_provider_maps_asn_and_org_domains_from_ipapi_is(monkeypatch):
    class FakeResponse:
        def __init__(self, payload: dict) -> None:
            self.payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self.payload

    def fake_get(url: str, *, params: dict[str, str] | None = None, timeout: float) -> FakeResponse:
        assert url == "https://api.ipapi.is"
        return FakeResponse(
            {
                "ip": "8.8.8.8",
                "location": {"country": {"name": "United States", "code": "US"}, "city": "Mountain View"},
                "asn": {
                    "asn": 15169,
                    "org": "Google LLC",
                    "domain": "google.com",
                },
                "company": {
                    "name": "Google LLC",
                    "domain": "google.com",
                },
            }
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert result.asn_domain == "google.com"
    assert result.org_domain == "google.com"
    assert result.field_sources["asn_domain"] == "ipapi.is"
    assert result.field_sources["org_domain"] == "ipapi.is"


def test_provider_merge_fills_domains_from_later_provider(monkeypatch):
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
                    "location": {"country": {"name": "United States", "code": "US"}, "city": "Mountain View"},
                    "asn": {"asn": 15169},
                }
            )
        if url == "https://ipwho.is/8.8.8.8":
            return FakeResponse(
                {
                    "success": True,
                    "ip": "8.8.8.8",
                    "country": "United States",
                    "country_code": "US",
                    "city": "Mountain View",
                    "connection": {
                        "asn": 15169,
                        "isp": "Google LLC",
                        "domain": "google.com",
                    },
                }
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert calls == ["https://api.ipapi.is", "https://ipwho.is/8.8.8.8"]
    assert result.asn_domain == "google.com"
    assert result.org_domain == "google.com"
    assert result.field_sources["asn_domain"] == "ipwho.is"
    assert result.field_sources["org_domain"] == "ipwho.is"


def test_provider_pipeline_follows_go_step_order_for_basic_then_domain_backfill(monkeypatch):
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
            return FakeResponse({"ip": "8.8.8.8", "asn": {"asn": 15169}})
        if url == "https://ipwho.is/8.8.8.8":
            return FakeResponse({"success": True, "ip": "8.8.8.8", "country": "United States", "country_code": "US", "city": "Mountain View", "connection": {"asn": 15169, "isp": "Google LLC"}})
        if url == "https://ipinfo.io/8.8.8.8/json":
            return FakeResponse({"ip": "8.8.8.8", "country": "US", "org": "AS15169 Google LLC", "asn": "15169", "asn_domain": "google.com"})
        if url == "https://api.ipdata.co/8.8.8.8":
            return FakeResponse({"ip": "8.8.8.8", "asn": {"asn": "15169", "name": "Google LLC", "domain": "google.com"}})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert calls == [
        "https://api.ipapi.is",
        "https://ipwho.is/8.8.8.8",
        "https://ipinfo.io/8.8.8.8/json",
        "https://api.ipdata.co/8.8.8.8",
    ]
    assert result.asn_domain == "google.com"
    assert result.field_sources["asn_domain"] == "ipinfo.io"


def test_provider_pipeline_skips_basic_fallback_when_primary_has_basic_fields_but_still_fetches_missing_domains(monkeypatch):
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
            return FakeResponse({"ip": "8.8.8.8", "location": {"country": {"name": "United States", "code": "US"}, "city": "Mountain View"}, "asn": {"asn": 15169, "org": "Google LLC"}})
        if url == "https://api.ipdata.co/8.8.8.8":
            return FakeResponse({"ip": "8.8.8.8", "asn": {"asn": "15169", "name": "Google LLC", "domain": "google.com"}})
        if url == "https://ipwho.is/8.8.8.8":
            raise AssertionError("basic fallback should be skipped")
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert calls == ["https://api.ipapi.is", "https://ipinfo.io/8.8.8.8/json", "https://api.ipdata.co/8.8.8.8"]
    assert result.asn_domain == "google.com"

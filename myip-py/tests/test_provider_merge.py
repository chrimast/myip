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
        if url == "https://ipinfo.io/8.8.8.8/json":
            return FakeResponse({"error": "no token data"})
        if url == "https://api.ipdata.co/8.8.8.8":
            return FakeResponse({"message": "no token data"})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert calls == [
        "https://api.ipapi.is",
        "https://ipwho.is/8.8.8.8",
        "https://ipinfo.io/8.8.8.8/json",
        "https://api.ipdata.co/8.8.8.8",
    ]
    assert result.provider == "ipapi.is+ipwho.is"
    assert result.country == "United States"
    assert result.country_code == "US"
    assert result.asn == "AS15169"
    assert result.region == "California"
    assert result.city == "Mountain View"
    assert result.isp == "Google LLC"
    assert result.asn_owner == "Google LLC"
    assert result.org is None
    assert result.latitude == 37.4056
    assert result.longitude == -122.0775
    assert result.is_proxy is True
    assert result.asn_domain is None
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
        "org_domain": "ipwho.is",
        "is_proxy": "ipwho.is",
    }


def test_ipinfo_asn_fallback_does_not_use_asn_org_as_enterprise_or_isp(monkeypatch):
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
                    "ip": "203.0.113.10",
                    "location": {"country": {"name": "Exampleland", "code": "EX"}, "city": "Example City"},
                    "asn": {"asn": 64500, "org": "IPAPI ASN Owner"},
                    "company": {"name": "IPAPI Customer Company", "domain": "customer.example"},
                    "isp": "IPAPI Access ISP",
                }
            )
        if url == "https://ipinfo.io/203.0.113.10/json":
            return FakeResponse(
                {
                    "ip": "203.0.113.10",
                    "country": "EX",
                    "org": "AS64500 Wrong ASN Org String",
                    "asn": {"asn": "AS64500", "name": "IPInfo Better ASN Owner", "domain": "ipinfo-asn.example"},
                }
            )
        if url == "https://api.ipdata.co/203.0.113.10":
            return FakeResponse(
                {
                    "ip": "203.0.113.10",
                    "asn": {"asn": "64500", "name": "IPData ASN Owner", "domain": "ipdata-asn.example"},
                    "organisation": "IPData Organisation",
                    "isp": "IPData ISP",
                }
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("203.0.113.10")

    assert calls == [
        "https://api.ipapi.is",
        "https://ipinfo.io/203.0.113.10/json",
        "https://api.ipdata.co/203.0.113.10",
    ]
    assert result.asn == "AS64500"
    assert result.asn_owner == "IPAPI ASN Owner"
    assert result.org == "IPAPI Customer Company"
    assert result.isp == "IPAPI Access ISP"
    assert result.asn_domain == "ipinfo-asn.example"
    assert result.org_domain == "customer.example"
    assert result.field_sources["asn_owner"] == "ipapi.is"
    assert result.field_sources["org"] == "ipapi.is"
    assert result.field_sources["isp"] == "ipapi.is"
    assert result.field_sources["asn_domain"] == "ipinfo.io"
    assert result.field_sources["org_domain"] == "ipapi.is"


def test_ipinfo_and_ipdata_domain_fallbacks_do_not_fill_go_identity_fields(monkeypatch):
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
                    "ip": "203.0.113.20",
                    "location": {"country": {"name": "Exampleland", "code": "EX"}, "city": "Example City"},
                    "asn": {"asn": 64520},
                    "company": {"name": "IPAPI Customer Company"},
                    "isp": "IPAPI Access ISP",
                }
            )
        if url == "https://ipinfo.io/203.0.113.20/json":
            return FakeResponse(
                {
                    "ip": "203.0.113.20",
                    "org": "AS64520 Misleading IPInfo Org String",
                    "asn": {"asn": "AS64520", "name": "IPInfo ASN Name", "domain": "ipinfo-asn.example"},
                }
            )
        if url == "https://api.ipdata.co/203.0.113.20":
            return FakeResponse(
                {
                    "ip": "203.0.113.20",
                    "asn": {"asn": "64520", "name": "IPData ASN Name", "domain": "ipdata-asn.example"},
                    "organisation": "IPData Organisation",
                    "isp": "IPData ISP",
                }
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("203.0.113.20")

    assert calls == [
        "https://api.ipapi.is",
        "https://ipinfo.io/203.0.113.20/json",
        "https://api.ipdata.co/203.0.113.20",
    ]
    assert result.asn == "AS64520"
    assert result.asn_owner is None
    assert result.org == "IPAPI Customer Company"
    assert result.isp == "IPAPI Access ISP"
    assert result.asn_domain == "ipinfo-asn.example"
    assert "asn_owner" not in result.field_sources
    assert result.field_sources["org"] == "ipapi.is"
    assert result.field_sources["isp"] == "ipapi.is"
    assert result.field_sources["asn_domain"] == "ipinfo.io"


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
                    "asn": {"asn": "15169", "name": "Google LLC", "domain": "google.com", "type": "hosting"},
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
    assert result.network_type == "hosting"
    assert result.is_vpn is True
    assert result.is_hosting is True
    assert result.is_abuser is True


def test_provider_maps_network_type_from_ipapi_is_company_and_asn_types(monkeypatch):
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
                "asn": {"asn": 15169, "org": "Google LLC", "type": "business"},
                "company": {"name": "Google LLC", "type": "isp"},
            }
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert result.network_type == "isp"
    assert result.field_sources["network_type"] == "ipapi.is"


def test_provider_maps_network_type_from_ipwho_connection_type(monkeypatch):
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
            return FakeResponse(
                {
                    "success": True,
                    "ip": "8.8.8.8",
                    "country": "United States",
                    "country_code": "US",
                    "city": "Mountain View",
                    "connection": {"asn": 15169, "isp": "Google LLC", "type": "business"},
                }
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert "https://ipwho.is/8.8.8.8" in calls
    assert result.network_type == "business"
    assert result.field_sources["network_type"] == "ipwho.is"


def test_provider_maps_network_type_from_ipinfo_asn_type(monkeypatch):
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
        if url == "https://ipinfo.io/8.8.8.8/json":
            return FakeResponse({"ip": "8.8.8.8", "country": "US", "org": "AS15169 Google LLC", "asn": {"asn": "AS15169", "domain": "google.com", "type": "hosting"}})
        if url == "https://api.ipdata.co/8.8.8.8":
            return FakeResponse({"ip": "8.8.8.8", "asn": {"asn": "15169", "name": "Google LLC", "domain": "google.com"}})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert calls == ["https://api.ipapi.is", "https://ipinfo.io/8.8.8.8/json", "https://api.ipdata.co/8.8.8.8"]
    assert result.network_type == "hosting"
    assert result.field_sources["network_type"] == "ipinfo.io"


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


def test_ip_source_uses_registered_region_vs_exit_region_not_network_type():
    from app.services.ip_lookup import IPInfo, enrich_ip_intelligence

    broadcast = enrich_ip_intelligence(
        IPInfo(
            ip="203.0.113.1",
            country="Japan",
            country_code="JP",
            asn="AS64500",
            asn_owner="Example ISP",
            org="Example Residential Broadband",
            isp="Example ISP",
            provider="test",
            network_type="residential",
            registry="APNIC",
            reg_region="US",
            is_hosting=False,
        )
    )
    native_hosting = enrich_ip_intelligence(
        IPInfo(
            ip="203.0.113.2",
            country="United States",
            country_code="US",
            asn="AS64501",
            asn_owner="Example Cloud",
            org="Example Cloud",
            isp="Example Cloud",
            provider="test",
            network_type="hosting",
            registry="ARIN",
            reg_region="US",
            is_hosting=True,
        )
    )

    assert broadcast.ip_source == "广播IP"
    assert native_hosting.ip_source == "原生IP"


def test_provider_maps_asn_owner_and_company_separately_from_ipapi_is(monkeypatch):
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
                "asn": {"asn": 15169, "org": "Google LLC", "domain": "google.com"},
                "company": {"name": "Google Enterprise Customer LLC", "domain": "customer.example"},
            }
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert result.asn == "AS15169"
    assert result.asn_owner == "Google LLC"
    assert result.asn_domain == "google.com"
    assert result.org == "Google Enterprise Customer LLC"
    assert result.org_domain == "customer.example"
    assert result.isp == "Google Enterprise Customer LLC"
    assert result.field_sources["asn_owner"] == "ipapi.is"
    assert result.field_sources["org"] == "ipapi.is"
    assert result.field_sources["isp"] == "ipapi.is"


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
        if url == "https://ipinfo.io/8.8.8.8/json":
            return FakeResponse({"ip": "8.8.8.8", "asn_domain": "asn.google"})
        if url == "https://api.ipdata.co/8.8.8.8":
            return FakeResponse({"ip": "8.8.8.8", "asn": {"asn": "15169", "domain": "ipdata.google"}})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert calls == [
        "https://api.ipapi.is",
        "https://ipwho.is/8.8.8.8",
        "https://ipinfo.io/8.8.8.8/json",
        "https://api.ipdata.co/8.8.8.8",
    ]
    assert result.asn_domain == "asn.google"
    assert result.org_domain == "google.com"
    assert result.field_sources["asn_domain"] == "ipinfo.io"
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


def test_provider_merge_keeps_go_identity_fields_separate_from_domain_fallbacks(monkeypatch):
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
                    "location": {"country": {"name": "United States", "code": "US"}, "city": "Primary City"},
                    "asn": {"asn": 15169},
                    "company": {"name": "Primary Company LLC"},
                    "isp": "Primary ISP LLC",
                }
            )
        if url == "https://ipinfo.io/8.8.8.8/json":
            return FakeResponse(
                {
                    "ip": "8.8.8.8",
                    "asn": {"asn": "AS15169", "name": "IPInfo ASN Owner LLC", "domain": "ipinfo.example"},
                    "org": "AS15169 IPInfo Org LLC",
                }
            )
        if url == "https://api.ipdata.co/8.8.8.8":
            return FakeResponse(
                {
                    "ip": "8.8.8.8",
                    "asn": {"asn": "15169", "name": "IPData ASN Owner LLC", "domain": "ipdata.example"},
                }
            )
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = IPAPIIsLookupProvider().lookup("8.8.8.8")

    assert calls == ["https://api.ipapi.is", "https://ipinfo.io/8.8.8.8/json", "https://api.ipdata.co/8.8.8.8"]
    assert result.asn_owner is None
    assert result.org == "Primary Company LLC"
    assert result.isp == "Primary ISP LLC"
    assert result.asn_domain == "ipinfo.example"
    assert "asn_owner" not in result.field_sources
    assert result.field_sources["org"] == "ipapi.is"
    assert result.field_sources["isp"] == "ipapi.is"
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

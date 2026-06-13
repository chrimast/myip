from fastapi import Request
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import get_settings


class AdminAuthSettings:
    ipapi_is_key = ""
    ipapi_org_key = ""
    ipinfo_token = ""
    ipdata_key = ""
    myip_debug = False
    myip_cache_ttl_seconds = 120
    myip_rate_limit_per_minute = 60
    myip_provider_timeout_seconds = 8.0
    myip_doh_timeout_seconds = 5.0
    myip_doh_providers = "cloudflare,google,quad9"
    myip_admin_username = "admin"
    myip_admin_password = "safe-admin-password"
    myip_admin_session_secret = "test-session-secret-minimum-length"

    def key_status(self):
        return {
            "ipapi_is_key": {"configured": False, "source": "missing"},
            "ipapi_org_key": {"configured": False, "source": "missing"},
            "ipinfo_token": {"configured": False, "source": "missing"},
            "ipdata_key": {"configured": False, "source": "missing"},
        }

    def public_config(self):
        return {}

    def doh_provider_names(self):
        return ["cloudflare", "google", "quad9"]


def admin_client() -> TestClient:
    app.dependency_overrides[get_settings] = lambda: AdminAuthSettings()
    client = TestClient(app)
    assert client.post("/admin/login", data={"username": "admin", "password": "safe-admin-password"}, follow_redirects=False).status_code == 303
    return client


def test_merge_upstream_observations_marks_shared_asns_stable_and_single_source_observed():
    from app.services import bgp as bgp_service

    topology = bgp_service.merge_upstream_observations(
        asn=25820,
        name="IT7NET",
        caida=[
            bgp_service.ASNNode(asn=1299, name="Arelion", is_tier1=True),
            bgp_service.ASNNode(asn=6939, name="Hurricane Electric"),
        ],
        ripestat=[
            bgp_service.ASNNode(asn=1299, name="TWELVE99"),
            bgp_service.ASNNode(asn=29802, name="Hivelocity"),
        ],
        cidr=[
            bgp_service.ASNNode(asn=6939, name="HURRICANE"),
            bgp_service.ASNNode(asn=20473, name="Vultr"),
        ],
    )

    assert [node.model_dump() for node in topology.upstreams] == [
        {
            "asn": 1299,
            "name": "Arelion",
            "country_code": None,
            "is_tier1": True,
            "sources": ["caida", "ripestat"],
            "edge_state": "stable",
            "edge_label": "稳定",
            "edge_style": "solid_thick",
        },
        {
            "asn": 6939,
            "name": "Hurricane Electric",
            "country_code": None,
            "is_tier1": False,
            "sources": ["caida", "cidr"],
            "edge_state": "stable",
            "edge_label": "稳定",
            "edge_style": "solid_thick",
        },
        {
            "asn": 29802,
            "name": "Hivelocity",
            "country_code": None,
            "is_tier1": False,
            "sources": ["ripestat"],
            "edge_state": "observed",
            "edge_label": "观测",
            "edge_style": "dashed",
        },
        {
            "asn": 20473,
            "name": "Vultr",
            "country_code": None,
            "is_tier1": False,
            "sources": ["cidr"],
            "edge_state": "observed",
            "edge_label": "观测",
            "edge_style": "dashed",
        },
    ]


def test_fetch_bgp_topology_merges_caida_ripestat_left_and_cidr_upstreams(monkeypatch):
    from app.services import bgp as bgp_service

    calls = []

    class FakePostResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "data": {
                    "asn": {
                        "asn": "25820",
                        "asnName": "IT7NET",
                        "asnLinks": {
                            "edges": [
                                {
                                    "node": {
                                        "relationship": "provider",
                                        "asn0": {"asn": "25820", "asnName": "IT7NET"},
                                        "asn1": {"asn": "1299", "asnName": "Arelion"},
                                    }
                                },
                                {
                                    "node": {
                                        "relationship": "provider",
                                        "asn0": {"asn": "6939", "asnName": "Hurricane Electric"},
                                        "asn1": {"asn": "25820", "asnName": "IT7NET"},
                                    }
                                },
                            ]
                        },
                    }
                }
            }

    class FakeGetResponse:
        def __init__(self, url: str):
            self.url = url
            if "stat.ripe.net" in url:
                self._json = {
                    "status": "ok",
                    "data": {
                        "neighbours": [
                            {"asn": 1299, "type": "left"},
                            {"asn": 29802, "type": "left"},
                            {"asn": 6453, "type": "right"},
                            {"asn": 3356, "type": "uncertain"},
                        ]
                    },
                }
                self.text = ""
            else:
                self._json = {}
                self.text = """
                <pre>
                  Upstream Adjacent AS list
                    <a href="/cgi-bin/as-report?as=AS6939&v=4&view=2.0">AS6939</a>          HURRICANE - Hurricane Electric LLC, US
                    <a href="/cgi-bin/as-report?as=AS20473&v=4&view=2.0">AS20473</a>         AS-VULTR - The Constant Company, LLC, US
                </pre>
                """

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self._json

    def fake_post(url: str, *, json: dict, timeout: float) -> FakePostResponse:
        calls.append(("post", url, timeout))
        return FakePostResponse()

    def fake_get(url: str, *, headers: dict | None = None, timeout: float) -> FakeGetResponse:
        calls.append(("get", url, headers, timeout))
        return FakeGetResponse(url)

    monkeypatch.setattr(bgp_service.httpx, "post", fake_post)
    monkeypatch.setattr(bgp_service.httpx, "get", fake_get)

    topology = bgp_service.fetch_bgp_topology(25820, 10)

    assert calls == [
        ("post", "https://api.asrank.caida.org/v2/graphql", 10.0),
        ("get", "https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS25820&lod=0", {"Accept": "application/json"}, 5.0),
        ("get", "https://www.cidr-report.org/cgi-bin/as-report?as=AS25820&view=2.0", {"User-Agent": "Mozilla/5.0"}, 10.0),
    ]
    assert [(node.asn, node.edge_label, node.edge_style, node.sources) for node in topology.upstreams] == [
        (1299, "稳定", "solid_thick", ["caida", "ripestat"]),
        (6939, "稳定", "solid_thick", ["caida", "cidr"]),
        (29802, "观测", "dashed", ["ripestat"]),
        (20473, "观测", "dashed", ["cidr"]),
    ]


def test_cidr_report_html_parser_extracts_upstream_adjacent_asns():
    from app.services import bgp as bgp_service

    html = """
    <pre>
    25820 IT7NET - IT7 Networks Inc, CA

      Adjacency:    10  Upstream:    10  Downstream:     0
      Upstream Adjacent AS list
        <a href="/cgi-bin/as-report?as=AS29802&v=4&view=2.0">AS29802</a>         HVC-AS - HIVELOCITY, Inc., US
        <a href="/cgi-bin/as-report?as=AS1299&v=4&view=2.0">AS1299</a>          TWELVE99 Arelion, fka Telia Carrier, SE
        <a href="/cgi-bin/as-report?as=AS6939&v=4&view=2.0">AS6939</a>          HURRICANE - Hurricane Electric LLC, US
    </pre>
    """

    upstreams = bgp_service.parse_cidr_report_upstreams(html)

    assert [node.model_dump() for node in upstreams] == [
        {"asn": 29802, "name": "HVC-AS - HIVELOCITY, Inc., US", "country_code": None, "is_tier1": False, "sources": [], "edge_state": "", "edge_label": "", "edge_style": ""},
        {"asn": 1299, "name": "TWELVE99 Arelion, fka Telia Carrier, SE", "country_code": None, "is_tier1": True, "sources": [], "edge_state": "", "edge_label": "", "edge_style": ""},
        {"asn": 6939, "name": "HURRICANE - Hurricane Electric LLC, US", "country_code": None, "is_tier1": False, "sources": [], "edge_state": "", "edge_label": "", "edge_style": ""},
    ]


def test_fetch_bgp_topology_falls_back_to_cidr_report_when_asrank_has_no_upstreams(monkeypatch):
    from app.services import bgp as bgp_service

    calls = []

    class FakePostResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"data": {"asn": {"asn": "25820", "asnName": "IT7NET", "asnLinks": {"edges": []}}}}

    class FakeGetResponse:
        def __init__(self, url: str):
            if "stat.ripe.net" in url:
                self.text = ""
                self._json = {"data": {"neighbours": []}}
            else:
                self.text = """
                <pre>
                  Upstream Adjacent AS list
                    <a href="/cgi-bin/as-report?as=AS29802&v=4&view=2.0">AS29802</a>         HVC-AS - HIVELOCITY, Inc., US
                    <a href="/cgi-bin/as-report?as=AS1299&v=4&view=2.0">AS1299</a>          TWELVE99 Arelion, fka Telia Carrier, SE
                </pre>
                """
                self._json = {}

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self._json

    def fake_post(url: str, *, json: dict, timeout: float) -> FakePostResponse:
        calls.append(("post", url, json, timeout))
        return FakePostResponse()

    def fake_get(url: str, *, headers: dict, timeout: float) -> FakeGetResponse:
        calls.append(("get", url, headers, timeout))
        return FakeGetResponse(url)

    monkeypatch.setattr(bgp_service.httpx, "post", fake_post)
    monkeypatch.setattr(bgp_service.httpx, "get", fake_get)

    topology = bgp_service.fetch_bgp_topology(25820, 2)

    assert calls[0][0] == "post"
    assert calls[1] == (
        "get",
        "https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS25820&lod=0",
        {"Accept": "application/json"},
        5.0,
    )
    assert calls[2] == (
        "get",
        "https://www.cidr-report.org/cgi-bin/as-report?as=AS25820&view=2.0",
        {"User-Agent": "Mozilla/5.0"},
        10.0,
    )
    assert topology.asn == 25820
    assert topology.name == "IT7NET"
    assert [node.model_dump() for node in topology.upstreams] == [
        {"asn": 29802, "name": "HVC-AS - HIVELOCITY, Inc., US", "country_code": None, "is_tier1": False, "sources": ["cidr"], "edge_state": "observed", "edge_label": "观测", "edge_style": "dashed"},
        {"asn": 1299, "name": "TWELVE99 Arelion, fka Telia Carrier, SE", "country_code": None, "is_tier1": True, "sources": ["cidr"], "edge_state": "observed", "edge_label": "观测", "edge_style": "dashed"},
    ]


def test_asrank_graphql_maps_provider_links_to_upstreams(monkeypatch):
    from app.services import bgp as bgp_service

    calls = []

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "data": {
                    "asn": {
                        "asn": "15169",
                        "asnName": "GOOGLE",
                        "asnLinks": {
                            "edges": [
                                {
                                    "node": {
                                        "relationship": "provider",
                                        "asn0": {"asn": "15169", "asnName": "GOOGLE"},
                                        "asn1": {"asn": "3356", "asnName": "LEVEL3"},
                                    }
                                },
                                {
                                    "node": {
                                        "relationship": "peer",
                                        "asn0": {"asn": "15169", "asnName": "GOOGLE"},
                                        "asn1": {"asn": "6939", "asnName": "HURRICANE"},
                                    }
                                },
                                {
                                    "node": {
                                        "relationship": "provider",
                                        "asn0": {"asn": "6453", "asnName": "AS6453"},
                                        "asn1": {"asn": "15169", "asnName": "GOOGLE"},
                                    }
                                },
                            ]
                        },
                    }
                }
            }

    def fake_post(url: str, *, json: dict, timeout: float) -> FakeResponse:
        calls.append({"url": url, "json": json, "timeout": timeout})
        return FakeResponse()

    monkeypatch.setattr(bgp_service.httpx, "post", fake_post)
    monkeypatch.setattr(bgp_service, "fetch_ripestat_left_neighbours", lambda asn: [])
    monkeypatch.setattr(bgp_service, "fetch_cidr_report_upstreams", lambda asn: [])

    topology = bgp_service.fetch_bgp_topology(15169, 2)

    assert calls == [
        {
            "url": "https://api.asrank.caida.org/v2/graphql",
            "json": {"query": bgp_service.build_asrank_query(15169, 2)},
            "timeout": 10.0,
        }
    ]
    query = calls[0]["json"]["query"]
    assert 'asn(asn: "15169")' in query
    assert "asnLinks(first: 2)" in query
    assert "rank" not in query
    assert topology.asn == 15169
    assert topology.name == "GOOGLE"
    assert [node.model_dump() for node in topology.upstreams] == [
        {"asn": 3356, "name": "LEVEL3", "country_code": None, "is_tier1": True, "sources": ["caida"], "edge_state": "observed", "edge_label": "观测", "edge_style": "dashed"},
        {"asn": 6453, "name": "AS6453", "country_code": None, "is_tier1": True, "sources": ["caida"], "edge_state": "observed", "edge_label": "观测", "edge_style": "dashed"},
    ]


def test_bgp_endpoint_resolves_asn_from_raw_ip_query(monkeypatch):
    from app.api import bgp as bgp_module

    calls = []

    def fake_resolve_asn(request: Request, value: str) -> int:
        calls.append((request.url.query, value))
        return 15169

    def fake_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        assert asn == 15169
        return bgp_module.BGPTopology(asn=asn, name="GOOGLE")

    monkeypatch.setattr(bgp_module, "resolve_asn_from_target", fake_resolve_asn)
    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", fake_fetch_topology)
    bgp_module.clear_bgp_topology_cache()

    client = TestClient(app)
    response = client.get("/api/bgp?8.8.8.8&limit=1")

    assert response.status_code == 200
    assert response.json()["asn"] == 15169
    assert calls == [("8.8.8.8&limit=1", "8.8.8.8")]


def test_bgp_endpoint_resolves_asn_from_raw_domain_query(monkeypatch):
    from app.api import bgp as bgp_module

    calls = []

    def fake_resolve_asn(request: Request, value: str) -> int:
        calls.append(value)
        return 13335

    def fake_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        assert asn == 13335
        return bgp_module.BGPTopology(asn=asn, name="CLOUDFLARENET")

    monkeypatch.setattr(bgp_module, "resolve_asn_from_target", fake_resolve_asn)
    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", fake_fetch_topology)
    bgp_module.clear_bgp_topology_cache()

    client = TestClient(app)
    response = client.get("/api/bgp?example.com&limit=1")

    assert response.status_code == 200
    assert response.json()["asn"] == 13335
    assert calls == ["example.com"]


def test_bgp_endpoint_resolves_asn_from_raw_as_query(monkeypatch):
    from app.api import bgp as bgp_module

    def fake_resolve_asn(request: Request, value: str) -> int:
        raise AssertionError("raw AS query should not resolve IP/domain target")

    def fake_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        assert asn == 15169
        return bgp_module.BGPTopology(asn=asn, name="GOOGLE")

    monkeypatch.setattr(bgp_module, "resolve_asn_from_target", fake_resolve_asn)
    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", fake_fetch_topology)
    bgp_module.clear_bgp_topology_cache()

    client = TestClient(app)
    response = client.get("/api/bgp?AS15169")

    assert response.status_code == 200
    assert response.json()["asn"] == 15169


def test_bgp_endpoint_resolves_asn_from_lowercase_raw_as_query(monkeypatch):
    from app.api import bgp as bgp_module

    def fail_resolve_asn(request: Request, value: str) -> int:
        raise AssertionError("raw as query should not resolve IP/domain target")

    def fake_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        assert asn == 15169
        return bgp_module.BGPTopology(asn=asn, name="GOOGLE")

    monkeypatch.setattr(bgp_module, "resolve_asn_from_target", fail_resolve_asn)
    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", fake_fetch_topology)
    bgp_module.clear_bgp_topology_cache()

    client = TestClient(app)
    response = client.get("/api/bgp?as15169")

    assert response.status_code == 200
    assert response.json()["asn"] == 15169


def test_bgp_endpoint_rejects_keyless_equals_query(monkeypatch):
    from app.api import bgp as bgp_module

    def fail_resolve_asn(request: Request, value: str) -> int:
        raise AssertionError("keyless equals BGP query should not resolve target")

    def fail_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        raise AssertionError("keyless equals BGP query should not fetch topology")

    monkeypatch.setattr(bgp_module, "resolve_asn_from_target", fail_resolve_asn)
    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", fail_fetch_topology)
    bgp_module.clear_bgp_topology_cache()

    client = TestClient(app)
    response = client.get("/api/bgp?=example.com")

    assert response.status_code == 400
    assert response.json() == {"ok": False, "error": "invalid target"}


def test_bgp_endpoint_returns_asn_not_found_when_target_has_no_asn(monkeypatch):
    from app.api import bgp as bgp_module

    def fake_resolve_asn(request: Request, value: str) -> int:
        return 0

    def fail_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        raise AssertionError("BGP fetch should not run when ASN cannot be resolved")

    monkeypatch.setattr(bgp_module, "resolve_asn_from_target", fake_resolve_asn)
    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", fail_fetch_topology)
    bgp_module.clear_bgp_topology_cache()

    client = TestClient(app)
    response = client.get("/api/bgp?192.0.2.1")

    assert response.status_code == 400
    assert response.json() == {"ok": False, "error": "asn not found"}


def test_bgp_endpoint_returns_invalid_target_for_empty_query_without_asn(monkeypatch):
    from app.api import bgp as bgp_module

    def fail_resolve_asn(request: Request, value: str) -> int:
        raise AssertionError("empty target should not resolve ASN")

    monkeypatch.setattr(bgp_module, "resolve_asn_from_target", fail_resolve_asn)
    bgp_module.clear_bgp_topology_cache()

    client = TestClient(app)
    response = client.get("/api/bgp")

    assert response.status_code == 400
    assert response.json() == {"ok": False, "error": "invalid target"}


def test_bgp_endpoint_defaults_to_twenty_upstreams_and_clamps_limit_to_fifty(monkeypatch):
    from app.api import bgp as bgp_module

    calls = []

    def fake_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        calls.append((asn, limit))
        return bgp_module.BGPTopology(asn=asn, name="GOOGLE")

    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", fake_fetch_topology)
    bgp_module.clear_bgp_topology_cache()

    client = TestClient(app)

    default_response = client.get("/api/bgp?AS15169")
    clamped_response = client.get("/api/bgp?AS13335&limit=80")

    assert default_response.status_code == 200
    assert clamped_response.status_code == 200
    assert calls == [(15169, 20), (13335, 50)]

def test_bgp_endpoint_returns_go_compatible_topology_for_asn(monkeypatch):
    from app.api import bgp as bgp_module

    def fake_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        assert asn == 15169
        assert limit == 2
        return bgp_module.BGPTopology(
            asn=15169,
            name="GOOGLE",
            upstreams=[
                bgp_module.ASNNode(asn=3356, name="Lumen", is_tier1=True),
                bgp_module.ASNNode(asn=6453, name="Tata Communications"),
                bgp_module.ASNNode(asn=6939, name="Hurricane Electric"),
            ],
        )

    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", fake_fetch_topology)
    bgp_module.clear_bgp_topology_cache()

    client = TestClient(app)

    response = client.get("/api/bgp?AS15169&limit=2")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["asn"] == 15169
    assert body["data"] == {
        "asn": 15169,
        "name": "GOOGLE",
        "external_links": {
            "bgp_tools": "https://bgp.tools/as/15169#connectivity",
            "bgp_he": "https://bgp.he.net/AS15169#_graph4",
        },
        "prefix": "",
        "upstreams": [
            {"asn": 3356, "name": "Lumen", "country_code": None, "is_tier1": True, "sources": [], "edge_state": "", "edge_label": "", "edge_style": ""},
            {"asn": 6453, "name": "Tata Communications", "country_code": None, "is_tier1": False, "sources": [], "edge_state": "", "edge_label": "", "edge_style": ""},
        ],
    }


def test_bgp_endpoint_reuses_cached_topology_within_ttl(monkeypatch):
    from app.api import bgp as bgp_module

    calls = []

    def fake_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        calls.append((asn, limit))
        return bgp_module.BGPTopology(
            asn=asn,
            name="GOOGLE",
            upstreams=[bgp_module.ASNNode(asn=3356, name="LEVEL3", is_tier1=True)],
        )

    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", fake_fetch_topology)
    monkeypatch.setattr(bgp_module.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(bgp_module, "BGP_CACHE_TTL_SECONDS", 60)
    bgp_module.clear_bgp_topology_cache()

    client = TestClient(app)

    first = client.get("/api/bgp?AS15169&limit=1")
    second = client.get("/api/bgp?AS15169&limit=1")

    assert first.status_code == 200
    assert second.status_code == 200
    assert calls == [(15169, 1)]
    assert first.json() == second.json()


def test_bgp_endpoint_refreshes_cache_after_ttl(monkeypatch):
    from app.api import bgp as bgp_module

    now = {"value": 100.0}
    calls = []

    def fake_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        calls.append((asn, limit))
        return bgp_module.BGPTopology(
            asn=asn,
            name=f"GOOGLE-{len(calls)}",
            upstreams=[bgp_module.ASNNode(asn=3356, name=f"LEVEL3-{len(calls)}", is_tier1=True)],
        )

    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", fake_fetch_topology)
    monkeypatch.setattr(bgp_module.time, "monotonic", lambda: now["value"])
    monkeypatch.setattr(bgp_module, "BGP_CACHE_TTL_SECONDS", 60)
    bgp_module.clear_bgp_topology_cache()

    client = TestClient(app)

    first = client.get("/api/bgp?AS15169&limit=1")
    now["value"] = 161.0
    second = client.get("/api/bgp?AS15169&limit=1")

    assert first.status_code == 200
    assert second.status_code == 200
    assert calls == [(15169, 1), (15169, 1)]
    assert first.json()["data"]["name"] == "GOOGLE-1"
    assert second.json()["data"]["name"] == "GOOGLE-2"


def test_bgp_endpoint_returns_stale_cache_when_asrank_refresh_fails(monkeypatch):
    from app.api import bgp as bgp_module

    now = {"value": 100.0}
    calls = []

    def flaky_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        calls.append((asn, limit))
        if len(calls) == 1:
            return bgp_module.BGPTopology(
                asn=asn,
                name="GOOGLE",
                upstreams=[bgp_module.ASNNode(asn=3356, name="LEVEL3", is_tier1=True)],
            )
        raise RuntimeError("ASRank unavailable")

    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", flaky_fetch_topology)
    monkeypatch.setattr(bgp_module.time, "monotonic", lambda: now["value"])
    monkeypatch.setattr(bgp_module, "BGP_CACHE_TTL_SECONDS", 60)
    bgp_module.clear_bgp_topology_cache()

    client = TestClient(app)

    first = client.get("/api/bgp?AS15169&limit=1")
    now["value"] = 161.0
    second = client.get("/api/bgp?AS15169&limit=1")

    assert first.status_code == 200
    assert second.status_code == 200
    assert calls == [(15169, 1), (15169, 1)]
    assert second.json()["ok"] is True
    assert second.json()["stale"] is True
    assert second.json()["error"] == "ASRank unavailable"
    assert second.json()["data"]["name"] == "GOOGLE"


def test_bgp_endpoint_returns_best_effort_error_without_cache(monkeypatch):
    from app.api import bgp as bgp_module

    def failing_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        raise RuntimeError("ASRank unavailable")

    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", failing_fetch_topology)
    bgp_module.clear_bgp_topology_cache()

    client = TestClient(app)

    response = client.get("/api/bgp?AS15169&limit=1")

    assert response.status_code == 200
    assert response.json() == {
        "ok": False,
        "status": "error",
        "http_status": 200,
        "asn": 15169,
        "error": "ASRank unavailable",
        "external_links": {
            "bgp_tools": "https://bgp.tools/as/15169#connectivity",
            "bgp_he": "https://bgp.he.net/AS15169#_graph4",
        },
    }


def test_bgp_endpoint_uses_runtime_settings_for_limit_cache_and_rate_limit(tmp_path, monkeypatch):
    from app.api import bgp as bgp_module
    from app.services import admin_config

    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr(admin_config, "PROVIDER_CONFIG_PATH", config_path)
    bgp_module.clear_bgp_topology_cache()
    now = {"value": 100.0}
    calls = []

    def fake_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        calls.append((asn, limit))
        return bgp_module.BGPTopology(
            asn=asn,
            name=f"GOOGLE-{len(calls)}",
            upstreams=[
                bgp_module.ASNNode(asn=3356, name="LEVEL3", is_tier1=True),
                bgp_module.ASNNode(asn=6453, name="TATA"),
                bgp_module.ASNNode(asn=1299, name="ARELION", is_tier1=True),
            ],
        )

    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", fake_fetch_topology)
    monkeypatch.setattr(bgp_module.time, "monotonic", lambda: now["value"])
    client = admin_client()

    saved = client.put(
        "/api/admin/runtime-settings",
        json={
            "rate_limit": {"bgp_enabled": True, "bgp_per_minute": 1},
            "bgp": {"enabled": True, "default_upstream_limit": 2, "max_upstream_limit": 2, "cache_ttl_seconds": 10},
            "cache": {"bgp_enabled": True, "bgp_ttl_seconds": 10},
        },
    )
    assert saved.status_code == 200

    first = client.get("/api/bgp?AS15169")
    second = client.get("/api/bgp?AS15169")
    third = client.get("/api/bgp?AS15170")

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    assert calls == [(15169, 2)]
    assert len(first.json()["data"]["upstreams"]) == 2
    assert first.json() == second.json()


def test_bgp_runtime_cache_can_be_disabled(tmp_path, monkeypatch):
    from app.api import bgp as bgp_module
    from app.services import admin_config

    config_path = tmp_path / "provider-config.json"
    monkeypatch.setattr(admin_config, "PROVIDER_CONFIG_PATH", config_path)
    bgp_module.clear_bgp_topology_cache()
    calls = []

    def fake_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        calls.append((asn, limit))
        return bgp_module.BGPTopology(asn=asn, name=f"GOOGLE-{len(calls)}")

    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", fake_fetch_topology)
    client = admin_client()
    saved = client.put(
        "/api/admin/runtime-settings",
        json={"cache": {"bgp_enabled": False}, "bgp": {"default_upstream_limit": 1, "max_upstream_limit": 5}},
    )
    assert saved.status_code == 200

    first = client.get("/api/bgp?AS15169")
    second = client.get("/api/bgp?AS15169")

    assert first.status_code == 200
    assert second.status_code == 200
    assert calls == [(15169, 1), (15169, 1)]


def test_bgp_endpoint_rejects_invalid_asn_without_fetch(monkeypatch):
    from app.api import bgp as bgp_module

    def fail_fetch_topology(asn: int, limit: int) -> bgp_module.BGPTopology:
        raise AssertionError("invalid ASN should not call provider")

    monkeypatch.setattr(bgp_module, "fetch_bgp_topology", fail_fetch_topology)
    bgp_module.clear_bgp_topology_cache()

    client = TestClient(app)

    response = client.get("/api/bgp?not-an-asn")

    assert response.status_code == 422
    assert response.json()["detail"][0]["msg"] == "value is not a valid IPv4 or IPv6 address"

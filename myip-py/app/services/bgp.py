import re
from html import unescape
from typing import Any

import httpx
from pydantic import BaseModel, Field

ASRANK_GRAPHQL_URL = "https://api.asrank.caida.org/v2/graphql"
CIDR_REPORT_URL = "https://www.cidr-report.org/cgi-bin/as-report?as=AS{asn}&view=2.0"
ASRANK_TIMEOUT_SECONDS = 10.0
CIDR_REPORT_TIMEOUT_SECONDS = 10.0
TIER1_ASNS = {174, 3356, 2914, 3257, 6762, 1299, 6453, 7018, 3491, 3320, 1239, 5511}


class ASNNode(BaseModel):
    asn: int
    name: str | None = None
    country_code: str | None = None
    is_tier1: bool = False


class BGPTopology(BaseModel):
    asn: int
    name: str | None = None
    external_links: dict[str, str] = Field(default_factory=dict)
    prefix: str = ""
    upstreams: list[ASNNode] = Field(default_factory=list)


def minimal_bgp_topology(asn: int) -> BGPTopology:
    return BGPTopology(
        asn=asn,
        external_links={
            "bgp_tools": f"https://bgp.tools/as/{asn}#connectivity",
            "bgp_he": f"https://bgp.he.net/AS{asn}#_graph4",
        },
    )


def limit_bgp_topology(topology: BGPTopology, limit: int) -> BGPTopology:
    return topology.model_copy(update={"upstreams": topology.upstreams[:limit]})


def build_asrank_query(asn: int, limit: int) -> str:
    return f"""
{{
  asn(asn: "{asn}") {{
    asn
    asnName
    asnLinks(first: {limit}) {{
      edges {{
        node {{
          relationship
          asn0 {{ asn asnName }}
          asn1 {{ asn asnName }}
        }}
      }}
    }}
  }}
}}
""".strip()


def fetch_bgp_topology(asn: int, limit: int) -> BGPTopology:
    response = httpx.post(
        ASRANK_GRAPHQL_URL,
        json={"query": build_asrank_query(asn, limit)},
        timeout=ASRANK_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    topology = _asrank_payload_to_topology(asn, response.json())
    if not topology.upstreams:
        topology.upstreams = fetch_cidr_report_upstreams(asn)[:limit]
    return topology


def fetch_cidr_report_upstreams(asn: int) -> list[ASNNode]:
    response = httpx.get(
        CIDR_REPORT_URL.format(asn=asn),
        headers={"User-Agent": "Mozilla/5.0"},
        timeout=CIDR_REPORT_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return parse_cidr_report_upstreams(response.text)


def parse_cidr_report_upstreams(html: str) -> list[ASNNode]:
    marker = "Upstream Adjacent AS list"
    start = html.find(marker)
    if start < 0:
        return []
    section = html[start:]
    end = section.find("</pre>")
    if end >= 0:
        section = section[:end]

    upstreams: list[ASNNode] = []
    seen: set[int] = set()
    pattern = re.compile(r'<a\s+href="[^"]*as=AS(\d+)[^"]*"[^>]*>AS\d+</a>\s*([^\n<]+)', re.IGNORECASE)
    for match in pattern.finditer(section):
        peer_asn = _int_from_asn(match.group(1))
        if not peer_asn or peer_asn in seen:
            continue
        seen.add(peer_asn)
        upstreams.append(
            ASNNode(
                asn=peer_asn,
                name=_string(unescape(match.group(2))),
                is_tier1=peer_asn in TIER1_ASNS,
            )
        )
    return upstreams


def _asrank_payload_to_topology(asn: int, payload: dict[str, Any]) -> BGPTopology:
    asn_data = ((payload.get("data") or {}).get("asn") or {})
    topology = minimal_bgp_topology(asn)
    topology.name = _string(asn_data.get("asnName"))
    edges = (((asn_data.get("asnLinks") or {}).get("edges")) or [])
    seen: set[int] = set()
    for edge in edges:
        node = (edge or {}).get("node") or {}
        if node.get("relationship") != "provider":
            continue
        peer = _opposite_asn(node, asn)
        peer_asn = _int_from_asn(peer.get("asn"))
        if not peer_asn or peer_asn in seen:
            continue
        seen.add(peer_asn)
        topology.upstreams.append(
            ASNNode(
                asn=peer_asn,
                name=_string(peer.get("asnName")),
                is_tier1=peer_asn in TIER1_ASNS,
            )
        )
    return topology


def _opposite_asn(link_node: dict[str, Any], asn: int) -> dict[str, Any]:
    asn0 = link_node.get("asn0") or {}
    asn1 = link_node.get("asn1") or {}
    return asn1 if _int_from_asn(asn0.get("asn")) == asn else asn0


def _int_from_asn(value: Any) -> int:
    text = str(value or "").strip().upper().removeprefix("AS")
    try:
        return int(text)
    except ValueError:
        return 0


def _string(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None

from app.services.ip_lookup import IPInfo, enrich_ip_intelligence


def test_enrichment_classifies_datacenter_proxy_vpn_tor_and_scores_risk():
    enriched = enrich_ip_intelligence(
        IPInfo(
            ip="203.0.113.10",
            isp="Example Cloud Hosting LLC",
            asn="AS64500",
            provider="test-provider",
            is_proxy=True,
            is_vpn=True,
            is_tor=True,
            is_hosting=True,
        )
    )

    assert enriched.ip_property == "机房IP"
    assert enriched.is_proxy is True
    assert enriched.is_vpn is True
    assert enriched.is_tor is True
    assert enriched.is_mobile is False
    assert enriched.risk_score >= 80
    assert enriched.bot_percent > enriched.human_percent
    assert enriched.risk_breakdown["tor"] > enriched.risk_breakdown["vpn"]


def test_enrichment_classifies_mobile_residential_as_human_leaning_low_risk():
    enriched = enrich_ip_intelligence(
        IPInfo(
            ip="198.51.100.20",
            isp="Example Mobile Broadband",
            provider="test-provider",
            is_mobile=True,
        )
    )

    assert enriched.ip_property == "家庭IP"
    assert enriched.is_mobile is True
    assert enriched.is_proxy is False
    assert enriched.is_vpn is False
    assert enriched.is_tor is False
    assert enriched.risk_score <= 20
    assert enriched.human_percent > enriched.bot_percent


def test_enrichment_classifies_business_from_provider_type():
    enriched = enrich_ip_intelligence(
        IPInfo(
            ip="198.51.100.30",
            isp="Example Enterprise Inc",
            provider="test-provider",
            network_type="business",
        )
    )

    assert enriched.ip_property == "商业IP"
    assert enriched.risk_score < 50

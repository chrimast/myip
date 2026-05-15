from app.services.ip_lookup import IPInfo, enrich_ip_intelligence


def test_enrich_ip_intelligence_scores_datacenter_proxy_vpn_signals():
    info = IPInfo(
        ip="203.0.113.10",
        country="United States",
        country_code="US",
        asn="AS64500",
        isp="Example Cloud Hosting LLC",
        provider="test-provider",
        network_type="hosting",
        is_proxy=True,
        is_vpn=True,
        is_hosting=True,
    )

    result = enrich_ip_intelligence(info)

    assert result.ip_property == "机房IP"
    assert result.ip_source == "原生IP"
    assert result.ip_source_reason == "缺少注册归属地，默认按实际出口地理位置视为一致"
    assert result.ip_property_scores["机房IP"] >= 100
    assert result.risk_breakdown == {
        "base": 10,
        "vpn": 24,
        "proxy": 28,
        "hosting": 20,
        "datacenter": 12,
    }
    assert result.risk_score == 94
    assert result.risk_confidence == 0.85
    assert result.bot_percent == 84.0
    assert result.human_percent == 16.0
    assert result.humanbot_confidence == 0.8


def test_enrich_ip_intelligence_scores_mobile_residential_as_low_risk():
    info = IPInfo(
        ip="198.51.100.22",
        country="United States",
        country_code="US",
        asn="AS64501",
        isp="Example Mobile Broadband",
        provider="test-provider",
        network_type="residential mobile",
        is_mobile=True,
    )

    result = enrich_ip_intelligence(info)

    assert result.ip_property == "家庭IP"
    assert result.ip_source == "原生IP"
    assert result.risk_breakdown == {"base": 10, "mobile_residential_discount": -8}
    assert result.risk_score == 2
    assert result.bot_percent == 0.0
    assert result.human_percent == 100.0
    assert result.risk_confidence == 0.7
    assert result.humanbot_confidence == 0.7


def test_enrich_ip_intelligence_ignores_text_identity_fields_for_scores():
    base = IPInfo(
        ip="203.0.113.30",
        country="United States",
        country_code="US",
        provider="test-provider",
        network_type="business",
    )
    with_text = base.model_copy(
        update={
            "isp": "Cloudflare VPN Proxy Hosting CDN LLC",
            "org": "Akamai Cloud Proxy Inc",
            "asn_owner": "Amazon AWS Hosting VPN LLC",
            "asn_domain": "cloudfront.example",
            "org_domain": "vpn-proxy-cdn.example",
        }
    )

    result_without_text = enrich_ip_intelligence(base)
    result_with_text = enrich_ip_intelligence(with_text)

    assert result_with_text.ip_property_scores == result_without_text.ip_property_scores
    assert result_with_text.ip_property == result_without_text.ip_property
    assert result_with_text.risk_breakdown == result_without_text.risk_breakdown
    assert result_with_text.risk_score == result_without_text.risk_score
    assert result_with_text.bot_percent == result_without_text.bot_percent
    assert result_with_text.human_percent == result_without_text.human_percent


def test_ip_source_is_native_when_registration_and_exit_country_match_even_with_risk_signals():
    info = IPInfo(
        ip="203.0.113.20",
        country="United States",
        country_code="US",
        provider="test-provider",
        registry="ARIN",
        reg_region="US",
        network_type="hosting",
        is_hosting=True,
        is_proxy=True,
        is_vpn=True,
    )

    result = enrich_ip_intelligence(info)

    assert result.ip_property == "机房IP"
    assert result.ip_source == "原生IP"
    assert result.ip_source_reason == "注册归属地/注册机构与实际出口地理位置一致: ARIN/US vs US"


def test_ip_source_is_broadcast_when_registration_and_exit_country_differ_without_risk_signals():
    info = IPInfo(
        ip="203.0.113.21",
        country="Japan",
        country_code="JP",
        provider="test-provider",
        registry="ARIN",
        reg_region="US",
        network_type="residential",
    )

    result = enrich_ip_intelligence(info)

    assert result.ip_property == "家庭IP"
    assert result.ip_source == "广播IP"
    assert result.ip_source_reason == "注册归属地/注册机构与实际出口地理位置不一致: ARIN/US vs JP"


def test_proxy_vpn_tor_do_not_force_ip_property_to_datacenter_without_hosting_signal():
    info = IPInfo(
        ip="198.51.100.42",
        country="United States",
        country_code="US",
        provider="test-provider",
        network_type="residential",
        is_proxy=True,
        is_vpn=True,
        is_tor=True,
    )

    result = enrich_ip_intelligence(info)

    assert result.ip_property == "家庭IP"
    assert result.ip_property_scores["家庭IP"] > result.ip_property_scores["机房IP"]
    assert result.risk_breakdown == {
        "base": 10,
        "tor": 40,
        "vpn": 24,
        "proxy": 28,
    }
    assert result.risk_score == 100
    assert result.bot_percent == 90.0


def test_dynamic_confidence_drops_when_only_minimal_signals_are_available():
    minimal = enrich_ip_intelligence(IPInfo(ip="203.0.113.50", provider="test-provider"))
    richer = enrich_ip_intelligence(
        IPInfo(
            ip="203.0.113.51",
            country="United States",
            country_code="US",
            provider="test-provider",
            network_type="hosting",
            is_hosting=True,
        )
    )

    assert minimal.risk_confidence == 0.45
    assert minimal.humanbot_confidence == 0.4
    assert richer.risk_confidence > minimal.risk_confidence
    assert richer.humanbot_confidence > minimal.humanbot_confidence

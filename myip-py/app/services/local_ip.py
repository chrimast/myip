from ipaddress import ip_address, ip_network

from app.services.ip_lookup import IPInfo

_LOCAL_NETWORKS = tuple(
    ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def local_ip_info(ip: str) -> IPInfo | None:
    parsed = ip_address(ip)
    if any(parsed in network for network in _LOCAL_NETWORKS):
        return IPInfo(ip=ip, isp="Private network", provider="local")
    return None

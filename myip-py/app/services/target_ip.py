import socket
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import unquote_plus

import httpx
from fastapi.exceptions import RequestValidationError

DOH_TIMEOUT_SECONDS = 5.0
DOH_PROVIDERS = [
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("google", "https://dns.google/resolve"),
    ("quad9", "https://dns.quad9.net/dns-query"),
]


class DNSResolutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class TargetResolution:
    input: str
    selected_ip: str
    resolved_ips: list[str]
    dns_provider: str | None = None


def invalid_ip_query_error(raw_ip: str, error_type: str = "ip_any_address", message: str = "value is not a valid IPv4 or IPv6 address") -> RequestValidationError:
    return RequestValidationError(
        [
            {
                "type": error_type,
                "loc": ("query", "ip"),
                "msg": message,
                "input": raw_ip,
            }
        ]
    )


def target_ip_from_query(raw_query: str, client_host: str) -> str:
    if not raw_query:
        return client_host
    if raw_query.startswith("="):
        return normalize_ip_or_resolve_domain(unquote_plus(raw_query[1:]))
    if "=" not in raw_query:
        return normalize_ip_or_resolve_domain(unquote_plus(raw_query))
    raise invalid_ip_query_error(raw_query)


def normalize_ip_or_resolve_domain(value: str) -> str:
    try:
        return str(ip_address(value))
    except ValueError:
        return resolve_target(value).selected_ip


def resolve_target(value: str) -> TargetResolution:
    try:
        parsed_ip = str(ip_address(value))
        return TargetResolution(input=value, selected_ip=parsed_ip, resolved_ips=[parsed_ip])
    except ValueError:
        return resolve_domain(value)


def resolve_domain(hostname: str) -> TargetResolution:
    if not looks_like_domain(hostname):
        raise invalid_ip_query_error(hostname)

    system_error: Exception | None = None
    try:
        system_ips = unique_socket_ips(socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM))
    except socket.gaierror as exc:
        system_error = exc
    except OSError as exc:
        system_error = exc
    else:
        if system_ips:
            return TargetResolution(
                input=hostname,
                selected_ip=system_ips[0],
                resolved_ips=system_ips,
                dns_provider="system",
            )

    last_doh_error: Exception | None = None
    for provider, endpoint in DOH_PROVIDERS:
        try:
            doh_ips = _lookup_doh(hostname, endpoint)
        except (httpx.HTTPError, ValueError) as exc:
            last_doh_error = exc
            continue
        if doh_ips:
            return TargetResolution(
                input=hostname,
                selected_ip=doh_ips[0],
                resolved_ips=doh_ips,
                dns_provider=provider,
            )

    if isinstance(system_error, socket.gaierror) and last_doh_error is None:
        raise invalid_ip_query_error(
            hostname,
            error_type="dns_name_not_found",
            message="domain name could not be resolved",
        )
    raise DNSResolutionError(f"DNS resolvers are temporarily unavailable for {hostname}")


def _lookup_doh(hostname: str, endpoint: str) -> list[str]:
    response = httpx.get(
        endpoint,
        params={"name": hostname, "type": "A"},
        headers={"accept": "application/dns-json"},
        timeout=DOH_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    data = response.json()
    status = data.get("Status")
    if status == 3:
        raise ValueError("domain name could not be resolved")
    if status != 0:
        raise ValueError("DoH lookup failed")
    return unique_doh_ips(data.get("Answer", []))


def looks_like_domain(value: str) -> bool:
    labels = value.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    return all(_valid_domain_label(label) for label in labels)


def _valid_domain_label(label: str) -> bool:
    return bool(label) and not label.startswith("-") and not label.endswith("-") and all(
        character.isalnum() or character == "-" for character in label
    )


def unique_socket_ips(addresses: list[tuple]) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for *_, sockaddr in addresses:
        _append_unique_ip(sockaddr[0], seen, results)
    return results


def unique_doh_ips(answers: list[dict]) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for answer in answers:
        if answer.get("type") in {1, 28}:
            _append_unique_ip(answer.get("data"), seen, results)
    return results


def _append_unique_ip(value: object, seen: set[str], results: list[str]) -> None:
    try:
        parsed_ip = str(ip_address(value))
    except ValueError:
        return
    if parsed_ip not in seen:
        seen.add(parsed_ip)
        results.append(parsed_ip)

import socket
from ipaddress import ip_address

from fastapi.exceptions import RequestValidationError


def invalid_ip_query_error(raw_ip: str) -> RequestValidationError:
    return RequestValidationError(
        [
            {
                "type": "ip_any_address",
                "loc": ("query", "ip"),
                "msg": "value is not a valid IPv4 or IPv6 address",
                "input": raw_ip,
            }
        ]
    )


def target_ip_from_query(raw_query: str, client_host: str) -> str:
    if not raw_query:
        return client_host
    if raw_query.startswith("="):
        return normalize_ip_or_resolve_domain(raw_query[1:])
    if "=" not in raw_query:
        return normalize_ip_or_resolve_domain(raw_query)
    raise invalid_ip_query_error(raw_query)


def normalize_ip_or_resolve_domain(value: str) -> str:
    try:
        return str(ip_address(value))
    except ValueError:
        return resolve_domain(value)


def resolve_domain(hostname: str) -> str:
    if not looks_like_domain(hostname):
        raise invalid_ip_query_error(hostname)
    try:
        addresses = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise invalid_ip_query_error(hostname) from exc

    for parsed_ip in unique_socket_ips(addresses):
        return parsed_ip
    raise invalid_ip_query_error(hostname)


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
        try:
            parsed_ip = str(ip_address(sockaddr[0]))
        except ValueError:
            continue
        if parsed_ip not in seen:
            seen.add(parsed_ip)
            results.append(parsed_ip)
    return results

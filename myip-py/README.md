# myip-py

FastAPI rewrite of the myip IP information query tool.

## API

### Health

```bash
GET /api/health
```

Returns service status.

### IP / domain lookup

Supported URL forms:

```bash
GET /api/ip
GET /api/ip?=8.8.8.8
GET /api/ip?8.8.8.8
GET /api/ip?=example.com
GET /api/ip?example.com
```

Unsupported URL form:

```bash
GET /api/ip?ip=8.8.8.8
```

That named query parameter form intentionally returns `422`. The service accepts only the no-argument form, keyless `?=<value>`, and raw keyless `?<value>` forms.

## Lookup behavior

- No query string: looks up the requester IP from `request.client.host`.
- IP input: normalizes IPv4 / IPv6 and looks it up directly.
- Domain input:
  1. validates that the input looks like a domain;
  2. tries system DNS via `socket.getaddrinfo`;
  3. falls back through DoH providers;
  4. de-duplicates A / AAAA records;
  5. uses the first resolved IP for the geo/IP provider pipeline.

Current DoH fallback order:

1. Cloudflare: `https://cloudflare-dns.com/dns-query`
2. Google: `https://dns.google/resolve`
3. Quad9: `https://dns.quad9.net/dns-query`

The public response currently remains the normalized IP info model. Internally, DNS resolution tracks the selected IP, all resolved IPs, and the DNS provider used, so the API can be extended later without rewriting resolution logic.

## Geo/IP provider fallback

Current provider order:

1. `ipapi.is`
2. `ipwho.is`
3. `ip-api.com`
4. `ipapi.org`
5. `ipinfo.io`
6. `ipdata.co`

Provider responses must include an IP matching the requested IP. Mismatched or malformed provider payloads are treated as provider failures and the lookup falls back to the next provider.

## Local/private IP handling

Private, loopback, link-local, and local IPv6 inputs are handled locally and do not call external providers.

## Error behavior

- `422`: malformed IP/domain input, unsupported named query parameters, or DNS name not found.
- `429`: per-client rate limit exceeded.
- `502`: DNS resolver infrastructure unavailable, or all geo/IP lookup providers unavailable.

## Cache and rate limit

The endpoint has in-memory TTL cache and fixed-window per-client rate limiting. Cache hits still count against the rate limit.

## Development sandbox

This project is intended to be developed and tested inside Docker Compose:

```bash
docker compose -f docker-compose.dev.yml build
docker compose -f docker-compose.dev.yml run --rm myip python -m pytest -q
docker compose -f docker-compose.dev.yml up --build myip
```

Live probes:

```bash
curl 'http://127.0.0.1:8000/api/health'
curl 'http://127.0.0.1:8000/api/ip?=8.8.8.8'
curl 'http://127.0.0.1:8000/api/ip?=example.com'
curl 'http://127.0.0.1:8000/api/ip?=not-an-ip'
```

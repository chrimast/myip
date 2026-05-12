# myip-py

FastAPI rewrite of the myip IP information query tool.

## API

### Health

```bash
GET /api/health
```

Returns service status, key presence, and public runtime config.

### IP / domain lookup

Supported URL forms:

```bash
GET /api/ip
GET /api/ip?=8.8.8.8
GET /api/ip?8.8.8.8
GET /api/ip?=example.com
GET /api/ip?example.com
```

Named query parameters such as `?ip=8.8.8.8` are not part of the API.

## Response shape

`GET /api/ip...` returns geo/IP fields plus resolution metadata:

```json
{
  "ip": "8.8.8.8",
  "country": "United States",
  "country_code": "US",
  "region": "California",
  "city": "Mountain View",
  "asn": "AS15169",
  "isp": "Google LLC",
  "latitude": 37.38605,
  "longitude": -122.08385,
  "provider": "ipapi.is",
  "input": "8.8.8.8",
  "resolved_ip": "8.8.8.8",
  "resolved_ips": ["8.8.8.8"],
  "dns_provider": null,
  "geo_provider": "ipapi.is"
}
```

For domain input, `resolved_ips` contains the de-duplicated A / AAAA results and `dns_provider` is `system`, `cloudflare`, `google`, or `quad9`.

## Lookup behavior

- No query string: looks up the requester IP from `request.client.host`.
- IP input: normalizes IPv4 / IPv6 and looks it up directly.
- Domain input:
  1. validates that the input looks like a domain;
  2. tries system DNS via `socket.getaddrinfo`;
  3. falls back through configured DoH providers;
  4. de-duplicates A / AAAA records;
  5. uses the first resolved IP for the geo/IP provider pipeline.

Default DoH fallback order:

1. Cloudflare: `https://cloudflare-dns.com/dns-query`
2. Google: `https://dns.google/resolve`
3. Quad9: `https://dns.quad9.net/dns-query`

## Geo/IP provider fallback

Current provider order:

1. `ipapi.is`
2. `ipwho.is`
3. `ip-api.com`
4. `ipapi.org`
5. `ipinfo.io`
6. `ipdata.co`

Provider responses must include an IP matching the requested IP. Mismatched or malformed provider payloads are treated as provider failures and the lookup falls back to the next provider.

Configured provider credentials are passed when available:

- `IPAPI_IS_KEY` -> `ipapi.is` `key` param
- `IPAPI_ORG_KEY` -> `ipapi.org` `key` param
- `IPINFO_TOKEN` -> `ipinfo.io` `token` param
- `IPDATA_KEY` -> `ipdata.co` `api-key` param

## Local/private IP handling

Private, loopback, link-local, and local IPv6 inputs are handled locally and do not call external providers.

## Configuration

Environment variables:

- `MYIP_DEBUG`: health/config debug flag, default `false`.
- `MYIP_CACHE_TTL_SECONDS`: IP lookup cache TTL, default `120`.
- `MYIP_RATE_LIMIT_PER_MINUTE`: per-client rate limit, default `60`.
- `MYIP_PROVIDER_TIMEOUT_SECONDS`: geo/IP provider HTTP timeout, default `8.0`.
- `MYIP_DOH_TIMEOUT_SECONDS`: DoH HTTP timeout, default `5.0`.
- `MYIP_DOH_PROVIDERS`: comma-separated DoH provider names, default `cloudflare,google,quad9`.

Supported DoH provider names:

- `cloudflare`
- `google`
- `quad9`

## Error behavior

- `422`: malformed IP/domain input, unsupported query strings, or DNS name not found.
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

# myip-py

FastAPI rewrite of the myip IP information query tool.

## Development sandbox

This project is intended to be developed and tested inside Docker Compose:

```bash
docker compose -f docker-compose.dev.yml build
docker compose -f docker-compose.dev.yml run --rm myip pytest -q
docker compose -f docker-compose.dev.yml up myip
```

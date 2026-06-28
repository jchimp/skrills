# Skrills

Self-hosted safety scanner for AI agent **skills** and **system prompts**.
Paste a SKILL.md or prompt → get a graded report on prompt injection,
tool-poisoning, secrets, and excessive-agency risk.


## Quick start

```bash
docker compose up --build -d
# open http://localhost:8088
```

## What it runs

- **Heuristics** — YAML rule pack seeded from OWASP LLM Top 10 + common jailbreaks
- **Gitleaks** — secret detection on the pasted content
- **LLM Guard** — ML-backed prompt-injection / toxicity / banned-topic scanners
- **Garak** *(optional sidecar)* — NVIDIA's LLM red-team probes; uncomment in `compose.yaml` and set `SKRILLS_GARAK_URL`
- **Snyk Labs** — stubbed (no public no-auth API yet)

## Outputs

- Web dashboard with severity-grouped findings + remediation
- Downloadable **JSON** / **HTML** report — buttons on the results page (generated
  client-side; in internal mode also available at `/scan/{id}/report.{json,html}`)
- API — `POST /api/scan` with `{"content": "..."}`

## Ephemeral mode

Toggle "Ephemeral" on the scan form (or set `SKRILLS_EPHEMERAL_DEFAULT=true`)
to skip persisting the scan to SQLite — useful for sensitive prompts.

## Public deployment

To expose Skrills on the open internet, set `SKRILLS_PUBLIC=true`. In this mode:

- **No persistence / no history** — scans are never written to SQLite. Results are
  shown on the page only; the recent-scans list and the `/scan/{id}` URLs are
  disabled (return 404). Download the JSON / HTML report from the results page —
  it's generated client-side, so it needs no stored copy.
- **Reduced scanner set** — heuristics + gitleaks only. The heavy LLM Guard ML
  scanner (and Garak / Snyk) are force-disabled to limit the DoS surface.
- **Rate limiting** — `SKRILLS_RATE_LIMIT` per client IP (default `10/minute`).
- **Body cap** — pasted content is capped server-side at `SKRILLS_MAX_CONTENT_BYTES`.
- **Security headers** — CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy`.

Run it behind a reverse proxy that terminates **TLS** and forwards
`X-Forwarded-For` (the rate limiter keys off the first hop). The container already
runs as a non-root user.

## Config

| Env var                       | Default                  | Purpose                                  |
|-------------------------------|--------------------------|------------------------------------------|
| `SKRILLS_DB`                  | `/app/data/skrills.db`   | SQLite path                              |
| `SKRILLS_EPHEMERAL_DEFAULT`   | `false`                  | Default state of the ephemeral toggle    |
| `SKRILLS_GARAK_URL`           | *(unset)*                | Garak sidecar base URL                   |
| `SKRILLS_SNYK_ENABLED`        | `false`                  | Reserved for future Snyk Labs probe      |
| `SKRILLS_PUBLIC`              | `false`                  | Public-web posture (see above)           |
| `SKRILLS_MAX_CONTENT_BYTES`   | `200000`                 | Server-side cap on pasted content        |
| `SKRILLS_RATE_LIMIT`          | `10/minute`              | Per-IP rate limit (public mode only)     |

## License

Internal use.

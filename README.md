# Skrills

Self-hosted safety scanner for AI agent **skills** and **system prompts**.
Paste a SKILL.md or prompt → get a graded report on prompt injection,
tool-poisoning, secrets, and excessive-agency risk.

> v1: paste-only, no auth, single Docker container.

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
- Downloadable **JSON** report — `/scan/{id}/report.json`
- Downloadable **HTML** report — `/scan/{id}/report.html`
- API — `POST /api/scan` with `{"content": "..."}`

## Ephemeral mode

Toggle "Ephemeral" on the scan form (or set `SKRILLS_EPHEMERAL_DEFAULT=true`)
to skip persisting the scan to SQLite — useful for sensitive prompts.

## Config

| Env var                       | Default                  | Purpose                                  |
|-------------------------------|--------------------------|------------------------------------------|
| `SKRILLS_DB`                  | `/app/data/skrills.db`   | SQLite path                              |
| `SKRILLS_EPHEMERAL_DEFAULT`   | `false`                  | Default state of the ephemeral toggle    |
| `SKRILLS_GARAK_URL`           | *(unset)*                | Garak sidecar base URL                   |
| `SKRILLS_SNYK_ENABLED`        | `false`                  | Reserved for future Snyk Labs probe      |

## License

Internal use.

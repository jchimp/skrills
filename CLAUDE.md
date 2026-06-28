# Skrills — Context for Claude / Copilot

## Purpose
Skrills is a small self-hosted FastAPI app that scans an AI agent **skill** or
**system prompt** for safety issues: prompt injection, jailbreaks, tool poisoning,
excessive agency, secret leakage, and indirect-injection patterns. v1 is
**paste-only** (no repo upload, no auth). Reports are downloadable as JSON and
HTML. SQLite stores history unless the user enables ephemeral mode.

## Stack
- FastAPI + Jinja2 + Bootstrap 5
- SQLite for scan history
- `uv` for dependency management
- Single Docker container; optional Garak sidecar via compose
- Python 3.12

## Scanners
| Scanner    | Type           | Notes                                                |
|------------|----------------|------------------------------------------------------|
| heuristics | regex + YAML   | OWASP LLM Top 10 rule pack in `src/skrills/rules/`  |
| gitleaks   | CLI subprocess | Binary copied from `zricethezav/gitleaks` image     |
| llm_guard  | Python lib     | PromptInjection + Toxicity + BanTopics              |
| snyk_labs  | stub           | No public no-auth API at v1; plumbing only          |
| garak      | HTTP sidecar   | Optional, off unless `SKRILLS_GARAK_URL` is set      |

## File layout
```
src/skrills/
  main.py            # FastAPI routes
  db.py              # SQLite init/save/list/get
  models.py          # Pydantic models + scoring
  scanners/          # one module per scanner, all subclass Scanner
  rules/             # YAML rule packs (injection, tool_risks)
  reports/           # JSON + HTML report renderers
  templates/         # base, index, results, report, _edu partial
  static/            # css, js
```

## Scoring
- Start at 100. Deductions per finding:
  - critical = 30, high = 15, medium = 7, low = 3, info = 0
- Score is clamped to `[0, 100]`. Banner colors: ≥80 green, ≥50 yellow, else red.

## Environment variables
- `SKRILLS_DB` — SQLite path (default `/app/data/skrills.db`)
- `SKRILLS_EPHEMERAL_DEFAULT` — `true|false` (default false)
- `SKRILLS_GARAK_URL` — Garak sidecar URL (empty = disabled)
- `SKRILLS_SNYK_ENABLED` — placeholder toggle (default false)
- `SKRILLS_PUBLIC` — public-web posture (default false): no persistence/history,
  heuristics+gitleaks only, rate limiting on, `/scan/{id}` routes return 404
- `SKRILLS_MAX_CONTENT_BYTES` — server-side cap on pasted content (default 200000)
- `SKRILLS_RATE_LIMIT` — per-IP rate limit, public mode only (default `10/minute`)

## How to add a scanner
1. Create `src/skrills/scanners/<name>.py` with a class subclassing `Scanner`.
2. Implement `scan(content: str) -> ScannerResult`.
3. Register it in `scanners/__init__.py` and add to `_run_scan` in `main.py`.
4. Add a checkbox in `templates/index.html`.

## How to add a heuristic rule
Edit `src/skrills/rules/injection.yaml` or `tool_risks.yaml`. Each rule:
```yaml
- id: SK-INJ-XXX
  title: "..."
  severity: critical|high|medium|low|info
  category: injection|tool_poisoning|secret|excessive_agency|indirect_injection|other
  pattern: "<python regex, case-insensitive, multi-line>"
  description: "..."
  remediation: "..."
```

## Run locally
```bash
docker compose up --build
# open http://localhost:8088
```

## API
- `POST /api/scan` — JSON body `{ "content": "...", "enable_gitleaks": true, ... }`
- `GET  /scan/{id}/report.json`
- `GET  /scan/{id}/report.html`

## Style preferences for this project
- Tight, drop-in code. No unnecessary abstraction.
- Bootstrap classes only — no custom UI framework.
- Markdown for docs. Code blocks intact.
- No auth in v1; internal use only.
- Phase 2 candidates: repo/zip upload, Git URL clone, Snyk Labs live probe,
  scheduled re-scans, rule pack updates from upstream.

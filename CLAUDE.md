# Skrills — Context for Claude / Copilot

## Purpose
Skrills scans AI agent **skills**, **system prompts**, and entire **repos** for
safety issues: prompt injection, jailbreaks, tool poisoning, excessive agency,
secret leakage, indirect injection, dependency CVEs, and code-security issues.

Three input modes:
- **Paste** — single SKILL.md / prompt / agent manifest
- **Upload** — zip, tar.gz, or single text file
- **Git URL** — public HTTPS clone (host allowlist)

## Stack
- FastAPI + Jinja2 + Bootstrap 5 + SQLite
- `uv` for dependency management
- Python 3.12, single Docker container for the app
- Multi-stage Dockerfile pulls `gitleaks` and `trivy` binaries from upstream images
- Optional sidecars: **semgrep** (always-on in compose), **garak** (commented out)

## Scanners

| Scanner    | Modes      | How it runs                                          |
|------------|------------|------------------------------------------------------|
| heuristics | text + repo| YAML rule packs in `src/skrills/rules/`             |
| gitleaks   | text + repo| Subprocess to baked-in binary                       |
| llm_guard  | text + repo| Python lib; in repo mode runs only on skill-like files |
| semgrep    | repo only  | Tarball POST to `semgrep` sidecar                   |
| trivy      | repo only  | Subprocess to baked-in `trivy fs`                   |
| garak      | text + repo| HTTP to optional sidecar                            |
| snyk_labs  | stub       | Plumbing only; no public no-auth API yet            |

## Architecture

```
src/skrills/
  main.py              # FastAPI routes (pages + submit + reports + status)
  jobs.py              # In-process asyncio job runner
  db.py                # SQLite init/save/list/get + lightweight migrations
  models.py            # Pydantic models, scoring, severity, status enums
  ingest/
    base.py            # IngestResult / IngestError
    limits.py          # Size/count caps, host allowlist, file-type sets
    upload_ingest.py   # bytes -> dir
    zip_ingest.py      # zip + tar safe extract (traversal + bomb guards)
    git_ingest.py      # `git clone --depth 1` with allowlist + timeout
  scanners/
    base.py            # Scanner ABC with scan_text + scan_repo
    heuristics.py
    gitleaks.py
    llm_guard.py
    semgrep.py
    trivy.py
    garak.py
    snyk_labs.py
  rules/               # YAML rule packs (injection, tool_risks)
  reports/             # JSON + standalone HTML renderers
  templates/           # base, index (tabbed), job_status, results, report, _edu
  static/              # CSS, JS (modal trigger, file-tree switch)
sidecars/
  semgrep/server.py    # tiny FastAPI wrapper around `semgrep scan`
```

## Job flow

1. User submits via `/scan/paste`, `/scan/upload`, or `/scan/git`.
2. Route validates size + creates `ScanResult` with `status=pending` and saves to DB.
3. JS modal pops while server processes ingest (paste/upload/git happens in
   background; route returns 303 redirect immediately).
4. `jobs.submit()` schedules an asyncio task that runs ingest then scanners.
5. Client lands on `/scan/{id}` — `view_scan` renders `job_status.html` while
   status is `pending` or `running`. Page polls `/scan/{id}/status.json` every
   1.5s and reloads on completion.
6. On `complete`, results page renders with file-tree sidebar + content viewer.
7. Scratch directory under `$SKRILLS_SCRATCH/{scan_id}` is always rmtree'd in
   `finally` block.

## Scoring
Same as v1 — start at 100, deduct per finding:
critical=30, high=15, medium=7, low=3, info=0. Clamped to [0, 100].

## Persistence rules
- **Paste, non-ephemeral**: store the pasted content in `scan.stored_content` so
  the results page can show it and the user can re-scan.
- **Git, non-ephemeral**: don't store repo contents; store URL so re-scan
  re-clones.
- **Upload, non-ephemeral**: results stored, original archive bytes NOT
  retained, so re-scan is disabled for uploads.
- **Ephemeral mode (any source)**: don't save the scan row at all.

## Environment variables

| Var                            | Default                                  | Purpose                                  |
|--------------------------------|------------------------------------------|------------------------------------------|
| `SKRILLS_DB`                   | `/app/data/skrills.db`                   | SQLite path                              |
| `SKRILLS_SCRATCH`              | `/app/scratch`                           | Per-scan temp dir parent                 |
| `SKRILLS_EPHEMERAL_DEFAULT`    | `false`                                  | Default state of the ephemeral toggle    |
| `SKRILLS_MAX_UPLOAD_MB`        | `50`                                     | Cap on uploaded bytes                    |
| `SKRILLS_MAX_FILE_COUNT`       | `5000`                                   | Cap on extracted/cloned file count       |
| `SKRILLS_MAX_EXTRACTED_MB`     | `200`                                    | Cap on uncompressed size                 |
| `SKRILLS_MAX_ZIP_RATIO`        | `100`                                    | Zip-bomb ratio guard                     |
| `SKRILLS_GIT_CLONE_TIMEOUT`    | `60`                                     | Seconds                                  |
| `SKRILLS_GIT_HOST_ALLOWLIST`   | `github.com,gitlab.com,bitbucket.org`    | Comma-separated allowlist                |
| `SKRILLS_SEMGREP_URL`          | `http://semgrep:9001`                    | Semgrep sidecar base URL                 |
| `SKRILLS_GARAK_URL`            | *(unset)*                                | Garak sidecar base URL                   |
| `SKRILLS_SNYK_ENABLED`         | `false`                                  | Reserved for future Snyk Labs probe      |
| `SKRILLS_RATE_LIMIT`           | `30/minute`                              | Per-IP cap on scan submissions (slowapi) |
| `SKRILLS_REGEX_TIMEOUT`        | `2.0`                                    | Per-file heuristics regex budget (sec)   |

## Hardening
For safer/public exposure (see README "Hardening"):
- Rate limiting (`slowapi`) on the three `/scan/*` submit endpoints, keyed on
  `X-Forwarded-For` first hop — front with a TLS reverse proxy.
- Security headers + strict-`script-src` CSP on every response (`_security_middleware`
  in `main.py`). Inline JS is avoided (job-status polling lives in `skrills.js`,
  driven by a `[data-poll-status]` marker) to keep the CSP strict.
- Oversized request bodies rejected (413) before parsing.
- Heuristics regex runs under a per-file timeout (`SKRILLS_REGEX_TIMEOUT`) using the
  `regex` module to bound catastrophic backtracking.
- Container runs non-root; scanner exceptions are logged, not surfaced to users.

## How to add a scanner
1. Add `src/skrills/scanners/<name>.py` subclassing `Scanner`.
2. Implement `scan_text` and/or `scan_repo`. Set `supports_text` / `supports_repo`.
3. Add field to `ScanOptions` in `models.py`.
4. Add a branch in `jobs._run_scanners`.
5. Register in `scanners/__init__.py`.
6. Add a checkbox in `templates/index.html`.

## How to add a heuristic rule
Append to `src/skrills/rules/injection.yaml` or `tool_risks.yaml`:
```yaml
- id: SK-INJ-XXX
  title: "..."
  severity: critical|high|medium|low|info
  category: injection|tool_poisoning|secret|excessive_agency|indirect_injection|other
  pattern: "<python regex, case-insensitive, multi-line>"
  description: "..."
  remediation: "..."
```

## Run

```bash
docker compose up --build
# http://localhost:8088
```

## Phase 3 candidates
- Authenticated Git (deploy keys / token) for private repos
- Persistent job queue (Redis/RQ) for restart durability
- Scheduled re-scans on saved skills
- Rule-pack auto-updater from upstream Git source
- Webhook output for CI integration

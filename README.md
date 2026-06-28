# Skrills

Self-hosted safety scanner for AI agent **skills**, **prompts**, and **repos**.
Paste, upload a zip, or point at a public Git URL — get a graded report on
prompt injection, tool-poisoning, secrets, excessive agency, dependency CVEs,
and code-security issues.

## Quick start

```bash
docker compose up --build -d
# open http://localhost:8088
```

## Input modes

- **Paste** — a SKILL.md, system prompt, or agent manifest
- **Upload** — `.zip` / `.tar.gz` / single text file (50 MB / 5,000 files cap)
- **Git URL** — public HTTPS clone; host allowlist (`github.com, gitlab.com, bitbucket.org` by default)

## Scanners

| Scanner    | What it catches                                         | Modes        |
|------------|---------------------------------------------------------|--------------|
| Heuristics | OWASP LLM Top 10 patterns, jailbreaks, tool-poisoning   | text + repo  |
| Gitleaks   | Inline secrets / API keys                               | text + repo  |
| LLM Guard  | ML prompt-injection, toxicity, banned topics            | text + repo* |
| Semgrep    | SAST (code security) — runs in sidecar container        | repo only    |
| Trivy      | Dependency CVEs, IaC misconfig, repo secrets            | repo only    |
| Garak      | NVIDIA red-team probes — optional sidecar               | text + repo* |
| Snyk Labs  | stubbed (no public no-auth API yet)                     | —            |

*In repo mode, ML scanners run only on skill-like files (`SKILL.md`, `system.md`,
`agent.md`, `claude.md`, `copilot.md`, `*.skill`, etc.).

## Outputs

- Web dashboard — file-tree sidebar, per-file findings, content viewer
- **JSON** report — `/scan/{id}/report.json`
- **HTML** report — `/scan/{id}/report.html`
- **API** — `POST /scan/paste`, `POST /scan/upload`, `POST /scan/git`
- **Status polling** — `GET /scan/{id}/status.json`

## Re-scan
Paste and Git scans can be re-scanned with one click (paste retains the
content, git re-clones from the stored URL). Uploads cannot be re-scanned —
original bytes are not retained.

## Ephemeral mode
Toggle "Ephemeral" on any tab to skip persistence — useful for sensitive prompts.
No DB row is written; reports are not downloadable later.

## Config

Environment variables.

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
| `SKRILLS_RATE_LIMIT`           | `30/minute`                              | Per-IP cap on scan submissions           |
| `SKRILLS_REGEX_TIMEOUT`        | `2.0`                                    | Per-file heuristics regex budget (sec)   |

## Hardening

Baked in for safer exposure:

- **Rate limiting** — per-client-IP cap on `/scan/{paste,upload,git}` (`SKRILLS_RATE_LIMIT`).
- **Security headers** — CSP (strict `script-src`), `X-Frame-Options`, `nosniff`,
  `Referrer-Policy` on every response.
- **Body cap** — oversized request bodies rejected (413) before parsing, ahead of
  the per-endpoint upload caps.
- **ReDoS guard** — heuristics regex runs under a per-file wall-clock budget
  (`SKRILLS_REGEX_TIMEOUT`); a rule that exceeds it is skipped and logged.
- **Non-root container** — the app runs as an unprivileged user.
- **No info leak** — scanner exceptions are logged server-side, not surfaced to users.

For public exposure, front the app with a reverse proxy that terminates **TLS** and
forwards `X-Forwarded-For` (the rate limiter keys off the first hop).

## Sidecars

- **Semgrep** — always-on in `compose.yaml` (lightweight wrapper in `sidecars/semgrep/`)
- **Garak** — commented out in `compose.yaml`; uncomment if you want red-team probes

## License
Internal use.

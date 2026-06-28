from __future__ import annotations

import base64
import hashlib
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from . import __version__
from .db import get_scan, init_db, list_scans, save_scan
from .models import Finding, ScanResult, Severity
from .reports.html_report import to_html
from .reports.json_report import to_json
from .scanners import (
    GarakScanner,
    GitleaksScanner,
    HeuristicsScanner,
    LLMGuardScanner,
    SnykLabsScanner,
)

BASE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE / "templates"))

_SCAN_ID_RE = re.compile(r"^[a-f0-9]{12}$")

# Content-Security-Policy: strict script-src (no inline JS) keeps XSS surface small;
# Bootstrap is loaded from jsdelivr, and 'unsafe-inline' is allowed for styles only
# (style attributes can't execute script).
_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "img-src 'self' data:; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


# ---- config ----

def _ephemeral_default() -> bool:
    return os.environ.get("SKRILLS_EPHEMERAL_DEFAULT", "false").lower() == "true"


def _public_mode() -> bool:
    """Public-web posture: no persistence, no history routes, reduced scanner set."""
    return os.environ.get("SKRILLS_PUBLIC", "false").lower() == "true"


def _max_content_bytes() -> int:
    try:
        return int(os.environ.get("SKRILLS_MAX_CONTENT_BYTES", "200000"))
    except ValueError:
        return 200000


def _rate_limit() -> str:
    # Internal mode is effectively unlimited; public mode is capped (overridable).
    if not _public_mode():
        return "1000000/minute"
    return os.environ.get("SKRILLS_RATE_LIMIT", "10/minute")


def _client_ip(request: Request) -> str:
    """Trust the first X-Forwarded-For hop when behind a reverse proxy."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return get_remote_address(request)


limiter = Limiter(key_func=_client_ip)

app = FastAPI(title="Skrills", version=__version__)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


@app.middleware("http")
async def _security_middleware(request: Request, call_next):
    # Reject oversized bodies before parsing (covers /api/scan raw dict too).
    # Allow headroom over the content cap for form-field / multipart overhead.
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > _max_content_bytes() + 65536:
                return JSONResponse({"detail": "content too large"}, status_code=413)
        except ValueError:
            pass
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = _CSP
    return response


@app.on_event("startup")
def _startup() -> None:
    if not _public_mode():
        init_db()


def _results_context(result: ScanResult) -> dict:
    """Context for results.html, including base64 report payloads for client-side
    download (so downloads never depend on server-side persistence)."""
    report_json = to_json(result)
    report_html = to_html(result)
    return {
        "scan": result,
        "version": __version__,
        "report_json_b64": base64.b64encode(report_json.encode("utf-8")).decode("ascii"),
        "report_html_b64": base64.b64encode(report_html.encode("utf-8")).decode("ascii"),
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    public = _public_mode()
    recent = [] if public else list_scans(limit=10)
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "recent": recent,
            "ephemeral_default": _ephemeral_default(),
            "public_mode": public,
            "version": __version__,
        },
    )


@app.post("/scan", response_class=HTMLResponse)
@limiter.limit(_rate_limit)
def scan(
    request: Request,
    content: str = Form(...),
    enable_gitleaks: str | None = Form(None),
    enable_llm_guard: str | None = Form(None),
    enable_heuristics: str | None = Form(None),
    enable_snyk: str | None = Form(None),
    enable_garak: str | None = Form(None),
    ephemeral: str | None = Form(None),
):
    if len(content) > _max_content_bytes():
        raise HTTPException(413, "content too large")

    public = _public_mode()
    result = _run_scan(
        content=content,
        enable_gitleaks=enable_gitleaks is not None,
        # Public mode force-disables heavy/optional scanners regardless of the form.
        enable_llm_guard=(enable_llm_guard is not None) and not public,
        enable_heuristics=enable_heuristics is not None,
        enable_snyk=(enable_snyk is not None) and not public,
        enable_garak=(enable_garak is not None) and not public,
        ephemeral=(ephemeral is not None) or public,
    )

    if not public and not result.ephemeral:
        save_scan(result)

    return templates.TemplateResponse(request, "results.html", _results_context(result))


@app.post("/api/scan")
@limiter.limit(_rate_limit)
def api_scan(request: Request, payload: dict):
    content = payload.get("content")
    if not content:
        raise HTTPException(400, "content is required")
    if len(content) > _max_content_bytes():
        raise HTTPException(413, "content too large")

    public = _public_mode()
    result = _run_scan(
        content=content,
        enable_gitleaks=payload.get("enable_gitleaks", True),
        enable_llm_guard=payload.get("enable_llm_guard", True) and not public,
        enable_heuristics=payload.get("enable_heuristics", True),
        enable_snyk=payload.get("enable_snyk", False) and not public,
        enable_garak=payload.get("enable_garak", False) and not public,
        ephemeral=payload.get("ephemeral", _ephemeral_default()) or public,
    )
    if not public and not result.ephemeral:
        save_scan(result)
    return JSONResponse(result.model_dump(mode="json"))


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
def view_scan(request: Request, scan_id: str):
    if _public_mode() or not _SCAN_ID_RE.match(scan_id):
        raise HTTPException(404, "scan not found")
    result = get_scan(scan_id)
    if not result:
        raise HTTPException(404, "scan not found")
    return templates.TemplateResponse(request, "results.html", _results_context(result))


@app.get("/scan/{scan_id}/report.json")
def scan_json(scan_id: str):
    if _public_mode() or not _SCAN_ID_RE.match(scan_id):
        raise HTTPException(404, "scan not found")
    result = get_scan(scan_id)
    if not result:
        raise HTTPException(404, "scan not found")
    return Response(
        content=to_json(result),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="skrills-{scan_id}.json"'},
    )


@app.get("/scan/{scan_id}/report.html")
def scan_html(scan_id: str):
    if _public_mode() or not _SCAN_ID_RE.match(scan_id):
        raise HTTPException(404, "scan not found")
    result = get_scan(scan_id)
    if not result:
        raise HTTPException(404, "scan not found")
    return Response(
        content=to_html(result),
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="skrills-{scan_id}.html"'},
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": __version__}


# ---- core ----

def _run_scan(
    *,
    content: str,
    enable_gitleaks: bool,
    enable_llm_guard: bool,
    enable_heuristics: bool,
    enable_snyk: bool,
    enable_garak: bool,
    ephemeral: bool,
) -> ScanResult:
    scanners = []
    if enable_gitleaks:
        scanners.append(GitleaksScanner())
    if enable_llm_guard:
        scanners.append(LLMGuardScanner())
    if enable_heuristics:
        scanners.append(HeuristicsScanner())
    if enable_snyk:
        scanners.append(SnykLabsScanner())
    if enable_garak:
        scanners.append(GarakScanner())

    scanner_results = [s.scan(content) for s in scanners]
    findings: list[Finding] = []
    for r in scanner_results:
        findings.extend(r.findings)

    # Sort by severity weight then scanner name for stable display
    sev_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    findings.sort(key=lambda f: (sev_order[f.severity], f.scanner, f.rule_id))

    scan_id = uuid.uuid4().hex[:12]
    input_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    return ScanResult(
        id=scan_id,
        created_at=datetime.now(timezone.utc),
        input_hash=input_hash,
        input_size=len(content),
        ephemeral=ephemeral,
        score=ScanResult.compute_score(findings),
        severity_counts=ScanResult.count_severities(findings),
        scanners=scanner_results,
        findings=findings,
    )

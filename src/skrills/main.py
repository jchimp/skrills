from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

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

app = FastAPI(title="Skrills", version=__version__)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


@app.on_event("startup")
def _startup() -> None:
    init_db()


def _ephemeral_default() -> bool:
    return os.environ.get("SKRILLS_EPHEMERAL_DEFAULT", "false").lower() == "true"


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    recent = list_scans(limit=10)
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "recent": recent,
            "ephemeral_default": _ephemeral_default(),
            "version": __version__,
        },
    )


@app.post("/scan", response_class=HTMLResponse)
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
    result = _run_scan(
        content=content,
        enable_gitleaks=enable_gitleaks is not None,
        enable_llm_guard=enable_llm_guard is not None,
        enable_heuristics=enable_heuristics is not None,
        enable_snyk=enable_snyk is not None,
        enable_garak=enable_garak is not None,
        ephemeral=ephemeral is not None,
    )

    if not result.ephemeral:
        save_scan(result)

    return templates.TemplateResponse(
        request,
        "results.html",
        {"scan": result, "version": __version__},
    )


@app.post("/api/scan")
def api_scan(payload: dict):
    content = payload.get("content")
    if not content:
        raise HTTPException(400, "content is required")
    result = _run_scan(
        content=content,
        enable_gitleaks=payload.get("enable_gitleaks", True),
        enable_llm_guard=payload.get("enable_llm_guard", True),
        enable_heuristics=payload.get("enable_heuristics", True),
        enable_snyk=payload.get("enable_snyk", False),
        enable_garak=payload.get("enable_garak", False),
        ephemeral=payload.get("ephemeral", _ephemeral_default()),
    )
    if not result.ephemeral:
        save_scan(result)
    return JSONResponse(result.model_dump(mode="json"))


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
def view_scan(request: Request, scan_id: str):
    result = get_scan(scan_id)
    if not result:
        raise HTTPException(404, "scan not found")
    return templates.TemplateResponse(
        request,
        "results.html",
        {"scan": result, "version": __version__},
    )


@app.get("/scan/{scan_id}/report.json")
def scan_json(scan_id: str):
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

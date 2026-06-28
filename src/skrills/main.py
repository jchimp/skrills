from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import __version__
from .db import get_scan, init_db, list_scans, reap_stale_scans
from .ingest.limits import (
    GIT_HOST_ALLOWLIST,
    MAX_FILE_COUNT,
    MAX_UPLOAD_BYTES,
    MAX_UPLOAD_MB,
)
from .jobs import make_pending, submit
from .models import ScanOptions, ScanResult, ScanStatus, SourceType
from .reports.html_report import to_html
from .reports.json_report import to_json
from .rule_catalog import group_by_category, load_catalog

BASE = Path(__file__).resolve().parent
SCRATCH = Path(os.environ.get("SKRILLS_SCRATCH", "./scratch"))
templates = Jinja2Templates(directory=str(BASE / "templates"))

app = FastAPI(title="Skrills", version=__version__)
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


@app.on_event("startup")
def _startup() -> None:
    init_db()
    SCRATCH.mkdir(parents=True, exist_ok=True)
    reaped = reap_stale_scans()
    if reaped:
        logging.getLogger("skrills").warning(
            "marked %d stale scan(s) as failed on startup", reaped
        )


def _ephemeral_default() -> bool:
    return os.environ.get("SKRILLS_EPHEMERAL_DEFAULT", "false").lower() == "true"


def _opts_from_form(d: dict) -> ScanOptions:
    g = lambda k: d.get(k) is not None  # noqa: E731
    return ScanOptions(
        enable_heuristics=g("enable_heuristics"),
        enable_gitleaks=g("enable_gitleaks"),
        enable_llm_guard=g("enable_llm_guard"),
        enable_semgrep=g("enable_semgrep"),
        enable_trivy=g("enable_trivy"),
        enable_snyk=g("enable_snyk"),
        enable_garak=g("enable_garak"),
        ephemeral=g("ephemeral"),
    )


# ---------- pages ----------

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    recent = list_scans(limit=10)
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "recent": recent,
            "ephemeral_default": _ephemeral_default(),
            "max_upload_mb": MAX_UPLOAD_MB,
            "max_files": MAX_FILE_COUNT,
            "git_allowlist": sorted(GIT_HOST_ALLOWLIST),
            "version": __version__,
        },
    )


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
def view_scan(request: Request, scan_id: str):
    result = get_scan(scan_id)
    if not result:
        raise HTTPException(404, "scan not found")
    if result.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
        return templates.TemplateResponse(
            request,
            "job_status.html",
            {"scan": result, "version": __version__},
        )
    return templates.TemplateResponse(
        request,
        "results.html",
        {"scan": result, "version": __version__, "catalog": load_catalog()},
    )


@app.get("/glossary", response_class=HTMLResponse)
def glossary(request: Request):
    return templates.TemplateResponse(
        request,
        "glossary.html",
        {
            "catalog": load_catalog(),
            "groups": group_by_category(),
            "version": __version__,
        },
    )


@app.get("/scan/{scan_id}/file", response_class=HTMLResponse)
def view_file(request: Request, scan_id: str, path: str):
    """Return file contents for the content viewer. Paste mode only retains
    the single pasted file; repo mode discards scratch after the scan, so for
    repo scans this endpoint returns the inventory snippet stored in DB."""
    result = get_scan(scan_id)
    if not result:
        raise HTTPException(404, "scan not found")
    if result.stored_content and path == "skill.md":
        return HTMLResponse(
            f"<pre class='mb-0'>{_escape(result.stored_content)}</pre>"
        )
    return HTMLResponse(
        "<div class='text-muted small p-3'>File contents not retained after scan "
        "(repo files are scratched). Re-run the scan to inspect again.</div>"
    )


# ---------- submit ----------

@app.post("/scan/paste")
async def submit_paste(
    request: Request,
    content: str = Form(...),
    enable_heuristics: str | None = Form(None),
    enable_gitleaks: str | None = Form(None),
    enable_llm_guard: str | None = Form(None),
    enable_semgrep: str | None = Form(None),
    enable_trivy: str | None = Form(None),
    enable_snyk: str | None = Form(None),
    enable_garak: str | None = Form(None),
    ephemeral: str | None = Form(None),
):
    if len(content.encode("utf-8")) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"content exceeds {MAX_UPLOAD_MB} MB cap")
    opts = _opts_from_form(locals())
    h = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
    scan = make_pending(
        source_type=SourceType.PASTE,
        source_label="<pasted>",
        options=opts,
        input_size=len(content.encode("utf-8")),
        input_hash=h,
    )
    submit(scan, scratch_dir=SCRATCH, paste_content=content)
    return RedirectResponse(f"/scan/{scan.id}", status_code=303)


@app.post("/scan/upload")
async def submit_upload(
    request: Request,
    file: UploadFile = File(...),
    enable_heuristics: str | None = Form(None),
    enable_gitleaks: str | None = Form(None),
    enable_llm_guard: str | None = Form(None),
    enable_semgrep: str | None = Form(None),
    enable_trivy: str | None = Form(None),
    enable_snyk: str | None = Form(None),
    enable_garak: str | None = Form(None),
    ephemeral: str | None = Form(None),
):
    data = await file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"upload exceeds {MAX_UPLOAD_MB} MB cap")
    opts = _opts_from_form(locals())
    h = hashlib.sha256(data).hexdigest()[:16]
    scan = make_pending(
        source_type=SourceType.UPLOAD,
        source_label=file.filename or "upload",
        options=opts,
        input_size=len(data),
        input_hash=h,
    )
    submit(
        scan,
        scratch_dir=SCRATCH,
        upload_bytes=data,
        upload_filename=file.filename or "upload.bin",
    )
    return RedirectResponse(f"/scan/{scan.id}", status_code=303)


@app.post("/scan/git")
async def submit_git(
    request: Request,
    git_url: str = Form(...),
    enable_heuristics: str | None = Form(None),
    enable_gitleaks: str | None = Form(None),
    enable_llm_guard: str | None = Form(None),
    enable_semgrep: str | None = Form(None),
    enable_trivy: str | None = Form(None),
    enable_snyk: str | None = Form(None),
    enable_garak: str | None = Form(None),
    ephemeral: str | None = Form(None),
):
    opts = _opts_from_form(locals())
    h = hashlib.sha256(git_url.encode("utf-8")).hexdigest()[:16]
    scan = make_pending(
        source_type=SourceType.GIT,
        source_label=git_url,
        options=opts,
        input_size=0,
        input_hash=h,
    )
    submit(scan, scratch_dir=SCRATCH, git_url=git_url)
    return RedirectResponse(f"/scan/{scan.id}", status_code=303)


# ---------- rescan ----------

@app.post("/scan/{scan_id}/rescan")
async def rescan(scan_id: str):
    prev = get_scan(scan_id)
    if not prev:
        raise HTTPException(404, "scan not found")
    if prev.source_type == SourceType.PASTE and prev.stored_content:
        scan = make_pending(
            source_type=SourceType.PASTE,
            source_label="<re-scan>",
            options=prev.options,
            input_size=prev.input_size,
            input_hash=prev.input_hash,
        )
        submit(scan, scratch_dir=SCRATCH, paste_content=prev.stored_content)
        return RedirectResponse(f"/scan/{scan.id}", status_code=303)
    if prev.source_type == SourceType.GIT:
        scan = make_pending(
            source_type=SourceType.GIT,
            source_label=prev.source_label,
            options=prev.options,
            input_size=0,
            input_hash=prev.input_hash,
        )
        submit(scan, scratch_dir=SCRATCH, git_url=prev.source_label)
        return RedirectResponse(f"/scan/{scan.id}", status_code=303)
    raise HTTPException(
        400, "cannot re-scan uploaded archives (original bytes not retained)"
    )


# ---------- report downloads ----------

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


@app.get("/scan/{scan_id}/status.json")
def scan_status(scan_id: str):
    result = get_scan(scan_id)
    if not result:
        raise HTTPException(404, "scan not found")
    return JSONResponse({
        "id": result.id,
        "status": result.status.value,
        "score": result.score,
        "error": result.error,
        "file_count": result.file_count,
    })


@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": __version__}


def _escape(s: str) -> str:
    return (
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )

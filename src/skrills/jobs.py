"""In-process background job runner.

Each scan submission is enqueued as an asyncio task. Status + partial result are
persisted to SQLite so the status page can refresh and recover from worker death.

This is intentionally simple — no Redis, no Celery. Trade-off: jobs are lost on
restart. Good enough for a homelab demo tool.
"""
from __future__ import annotations

import asyncio
import hashlib
import shutil
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .db import save_scan
from .ingest import (
    IngestError,
    IngestResult,
    clone_repo,
    extract_upload,
    save_text_file,
)
from .ingest.limits import is_text_file
from .models import (
    FileEntry,
    Finding,
    ScanOptions,
    ScanResult,
    ScanStatus,
    Severity,
    SourceType,
)
from .scanners import (
    GarakScanner,
    GitleaksScanner,
    HeuristicsScanner,
    LLMGuardScanner,
    SemgrepScanner,
    SnykLabsScanner,
    TrivyScanner,
)

SEV_ORDER = {
    Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
    Severity.LOW: 3, Severity.INFO: 4,
}

# Strong references to in-flight tasks. asyncio only holds weak references to
# tasks, so a fire-and-forget task can be garbage-collected mid-run; keeping it
# here until done prevents the scan from being silently cancelled.
_INFLIGHT: set[asyncio.Task] = set()


def new_scan_id() -> str:
    return uuid.uuid4().hex[:12]


def make_pending(
    *,
    source_type: SourceType,
    source_label: str,
    options: ScanOptions,
    input_size: int,
    input_hash: str,
) -> ScanResult:
    return ScanResult(
        id=new_scan_id(),
        created_at=datetime.now(timezone.utc),
        status=ScanStatus.PENDING,
        source_type=source_type,
        source_label=source_label,
        input_hash=input_hash,
        input_size=input_size,
        file_count=0,
        ephemeral=options.ephemeral,
        options=options,
    )


def submit(
    scan: ScanResult,
    *,
    scratch_dir: Path,
    paste_content: str | None = None,
    upload_bytes: bytes | None = None,
    upload_filename: str | None = None,
    git_url: str | None = None,
) -> None:
    """Persist pending row, then schedule the worker."""
    if not scan.ephemeral:
        save_scan(scan)

    task = asyncio.create_task(
        _run(
            scan,
            scratch_dir=scratch_dir,
            paste_content=paste_content,
            upload_bytes=upload_bytes,
            upload_filename=upload_filename,
            git_url=git_url,
        )
    )
    _INFLIGHT.add(task)
    task.add_done_callback(_INFLIGHT.discard)


async def _run(
    scan: ScanResult,
    *,
    scratch_dir: Path,
    paste_content: str | None,
    upload_bytes: bytes | None,
    upload_filename: str | None,
    git_url: str | None,
) -> None:
    work_root = scratch_dir / scan.id
    try:
        scan.status = ScanStatus.RUNNING
        if not scan.ephemeral:
            save_scan(scan)

        # 1. Ingest
        if paste_content is not None:
            ingest = await asyncio.to_thread(save_text_file, paste_content, work_root)
            if not scan.ephemeral:
                scan.stored_content = paste_content
        elif upload_bytes is not None:
            ingest = await asyncio.to_thread(
                extract_upload, upload_bytes, upload_filename or "upload.bin", work_root
            )
        elif git_url is not None:
            ingest = await asyncio.to_thread(clone_repo, git_url, work_root)
        else:
            raise IngestError("no input provided")

        scan.file_count = ingest.file_count
        scan.input_size = ingest.total_bytes
        scan.files = _inventory(ingest)

        # 2. Run scanners
        await asyncio.to_thread(_run_scanners, scan, ingest)

        # 3. Finalize
        scan.findings.sort(key=lambda f: (SEV_ORDER[f.severity], f.file_path or "", f.scanner, f.rule_id))
        scan.score = ScanResult.compute_score(scan.findings)
        scan.severity_counts = ScanResult.count_severities(scan.findings)
        scan.status = ScanStatus.COMPLETE

    except asyncio.CancelledError:
        # Task was cancelled (e.g. GC of an un-referenced task, or shutdown).
        # Mark failed rather than leaving the row stuck at RUNNING, then re-raise
        # so cancellation propagates as asyncio expects.
        scan.status = ScanStatus.FAILED
        scan.error = "scan cancelled before completion"
        raise
    except IngestError as e:
        scan.status = ScanStatus.FAILED
        scan.error = f"ingest: {e}"
    except Exception as e:
        scan.status = ScanStatus.FAILED
        scan.error = f"{type(e).__name__}: {e}\n{traceback.format_exc()[-500:]}"
    finally:
        if not scan.ephemeral:
            save_scan(scan)
        # Always clean scratch
        try:
            if work_root.exists():
                shutil.rmtree(work_root, ignore_errors=True)
        except OSError:
            pass


def _inventory(ingest: IngestResult) -> list[FileEntry]:
    entries: list[FileEntry] = []
    for p in sorted(ingest.root.rglob("*")):
        if not p.is_file():
            continue
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        rel = str(p.relative_to(ingest.root))
        entries.append(FileEntry(
            path=rel,
            size=size,
            is_text=is_text_file(p.name),
            is_skill=p.name.lower() in {"skill.md", "system.md", "agent.md", "claude.md", "copilot.md"},
        ))
    return entries


def _run_scanners(scan: ScanResult, ingest: IngestResult) -> None:
    opts = scan.options
    scanners = []
    if opts.enable_heuristics: scanners.append(HeuristicsScanner())
    if opts.enable_gitleaks:   scanners.append(GitleaksScanner())
    if opts.enable_llm_guard:  scanners.append(LLMGuardScanner())
    if opts.enable_semgrep:    scanners.append(SemgrepScanner())
    if opts.enable_trivy:      scanners.append(TrivyScanner())
    if opts.enable_snyk:       scanners.append(SnykLabsScanner())
    if opts.enable_garak:      scanners.append(GarakScanner())

    is_paste = ingest.source_type == "paste"
    for s in scanners:
        try:
            if is_paste and s.supports_text:
                # For pasted single file, prefer text mode for scanners that support it
                content = (ingest.root / "skill.md").read_text(encoding="utf-8", errors="ignore")
                result = s.scan_text(content)
            else:
                result = s.scan_repo(ingest.root)
        except Exception as e:
            from .models import ScannerResult
            result = ScannerResult(scanner=s.name, ok=False, error=f"{type(e).__name__}: {e}")
        scan.scanners.append(result)
        scan.findings.extend(result.findings)

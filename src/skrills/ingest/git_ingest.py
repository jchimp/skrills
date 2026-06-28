from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from .base import IngestError, IngestResult
from .limits import (
    GIT_CLONE_TIMEOUT,
    GIT_HOST_ALLOWLIST,
    MAX_EXTRACTED_BYTES,
    MAX_FILE_COUNT,
)


def clone_repo(url: str, dest: Path) -> IngestResult:
    _validate_url(url)
    dest.mkdir(parents=True, exist_ok=True)

    if shutil.which("git") is None:
        raise IngestError("git binary not available in container")

    try:
        proc = subprocess.run(
            [
                "git", "clone",
                "--depth", "1",
                "--single-branch",
                "--no-tags",
                "--config", "core.symlinks=false",
                url,
                str(dest),
            ],
            capture_output=True,
            text=True,
            timeout=GIT_CLONE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise IngestError(f"git clone timed out after {GIT_CLONE_TIMEOUT}s")

    if proc.returncode != 0:
        raise IngestError(f"git clone failed: {proc.stderr.strip()[:300]}")

    file_count, total_bytes = _measure_and_check(dest)
    return IngestResult(
        root=dest,
        source_type="git",
        source_label=url,
        file_count=file_count,
        total_bytes=total_bytes,
    )


def _validate_url(url: str) -> None:
    try:
        u = urlparse(url)
    except Exception:
        raise IngestError("invalid URL")
    if u.scheme not in ("https", "http"):
        raise IngestError("only http(s) git URLs allowed")
    host = (u.hostname or "").lower()
    if not host:
        raise IngestError("URL missing hostname")
    if GIT_HOST_ALLOWLIST and host not in GIT_HOST_ALLOWLIST:
        raise IngestError(
            f"host '{host}' not in allowlist ({', '.join(sorted(GIT_HOST_ALLOWLIST))})"
        )


def _measure_and_check(root: Path) -> tuple[int, int]:
    count = 0
    total = 0
    for p in root.rglob("*"):
        if p.is_file():
            count += 1
            if count > MAX_FILE_COUNT:
                raise IngestError(f"repo exceeds {MAX_FILE_COUNT} files")
            try:
                total += p.stat().st_size
            except OSError:
                pass
            if total > MAX_EXTRACTED_BYTES:
                raise IngestError(
                    f"repo size > {MAX_EXTRACTED_BYTES // (1024*1024)} MB cap"
                )
    return count, total

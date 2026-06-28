from __future__ import annotations

from pathlib import Path

from .base import IngestError, IngestResult
from .limits import MAX_FILE_COUNT, MAX_UPLOAD_BYTES
from .zip_ingest import extract_archive


def save_text_file(content: str, dest: Path, filename: str = "skill.md") -> IngestResult:
    """Treat pasted text as a one-file virtual repo."""
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / filename
    data = content.encode("utf-8")
    if len(data) > MAX_UPLOAD_BYTES:
        raise IngestError(f"content exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB cap")
    target.write_bytes(data)
    return IngestResult(
        root=dest,
        source_type="paste",
        source_label="<pasted>",
        file_count=1,
        total_bytes=len(data),
    )


def extract_upload(
    upload_bytes: bytes,
    filename: str,
    dest: Path,
) -> IngestResult:
    """Persist an upload (archive or single text file) to ``dest``."""
    if len(upload_bytes) > MAX_UPLOAD_BYTES:
        raise IngestError(f"upload exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB cap")

    dest.mkdir(parents=True, exist_ok=True)
    name = filename.lower()

    if name.endswith((".zip", ".tar.gz", ".tgz", ".tar")):
        archive_tmp = dest.parent / f"_{dest.name}_{filename}"
        archive_tmp.write_bytes(upload_bytes)
        try:
            return extract_archive(archive_tmp, dest, source_label=filename)
        finally:
            try:
                archive_tmp.unlink()
            except OSError:
                pass

    # Single-file upload — save as-is
    target = dest / Path(filename).name
    target.write_bytes(upload_bytes)
    return IngestResult(
        root=dest,
        source_type="upload",
        source_label=filename,
        file_count=1,
        total_bytes=len(upload_bytes),
    )

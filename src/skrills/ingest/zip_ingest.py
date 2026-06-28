from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

from .base import IngestError, IngestResult
from .limits import MAX_EXTRACTED_BYTES, MAX_FILE_COUNT, MAX_ZIP_RATIO


def extract_archive(archive_path: Path, dest: Path, source_label: str) -> IngestResult:
    """Extract zip / tar.gz / tgz into ``dest`` with traversal + bomb guards."""
    dest.mkdir(parents=True, exist_ok=True)
    name = archive_path.name.lower()

    if name.endswith(".zip"):
        _extract_zip(archive_path, dest)
    elif name.endswith((".tar.gz", ".tgz", ".tar")):
        _extract_tar(archive_path, dest)
    else:
        raise IngestError(f"unsupported archive type: {archive_path.name}")

    file_count, total_bytes = _measure(dest)
    return IngestResult(
        root=dest,
        source_type="upload",
        source_label=source_label,
        file_count=file_count,
        total_bytes=total_bytes,
    )


def _extract_zip(src: Path, dest: Path) -> None:
    dest_res = dest.resolve()
    extracted_total = 0
    compressed_total = max(src.stat().st_size, 1)
    count = 0

    with zipfile.ZipFile(src) as zf:
        for info in zf.infolist():
            count += 1
            if count > MAX_FILE_COUNT:
                raise IngestError(f"archive exceeds {MAX_FILE_COUNT} files")

            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest_res)):
                raise IngestError(f"path traversal in zip: {info.filename}")

            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            extracted_total += info.file_size
            if extracted_total > MAX_EXTRACTED_BYTES:
                raise IngestError(
                    f"extracted size > {MAX_EXTRACTED_BYTES // (1024*1024)} MB cap"
                )
            if extracted_total / compressed_total > MAX_ZIP_RATIO:
                raise IngestError("zip bomb suspected (ratio cap)")

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as zin, open(target, "wb") as out:
                # stream copy with a per-file cap
                remaining = min(info.file_size, MAX_EXTRACTED_BYTES)
                while remaining > 0:
                    chunk = zin.read(min(65536, remaining))
                    if not chunk:
                        break
                    out.write(chunk)
                    remaining -= len(chunk)


def _extract_tar(src: Path, dest: Path) -> None:
    dest_res = dest.resolve()
    extracted_total = 0
    count = 0
    mode = "r:gz" if src.name.lower().endswith((".tar.gz", ".tgz")) else "r:"
    with tarfile.open(src, mode) as tf:
        for m in tf.getmembers():
            count += 1
            if count > MAX_FILE_COUNT:
                raise IngestError(f"archive exceeds {MAX_FILE_COUNT} files")
            target = (dest / m.name).resolve()
            if not str(target).startswith(str(dest_res)):
                raise IngestError(f"path traversal in tar: {m.name}")
            if m.issym() or m.islnk():
                continue  # skip links — safe by default
            extracted_total += max(m.size, 0)
            if extracted_total > MAX_EXTRACTED_BYTES:
                raise IngestError("extracted size cap exceeded")
        tf.extractall(dest)


def _measure(root: Path) -> tuple[int, int]:
    count = 0
    total = 0
    for p in root.rglob("*"):
        if p.is_file():
            count += 1
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return count, total

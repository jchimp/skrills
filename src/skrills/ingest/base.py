from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class IngestError(Exception):
    """Raised when an ingest operation violates a safety limit or fails."""


@dataclass
class IngestResult:
    root: Path
    source_type: str          # paste | upload | git
    source_label: str         # filename, repo URL, or "<pasted>"
    file_count: int
    total_bytes: int

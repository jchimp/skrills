from __future__ import annotations

import time
from abc import ABC
from pathlib import Path

from ..models import ScannerResult


class Scanner(ABC):
    """Base scanner.

    Subclasses override scan_text and/or scan_repo. The default implementations
    fall back to one another where reasonable.
    """

    name: str = "base"
    supports_repo: bool = True
    supports_text: bool = True

    def scan_text(self, content: str) -> ScannerResult:  # pragma: no cover - override
        return ScannerResult(scanner=self.name, ok=False, error="text mode not supported")

    def scan_repo(self, root: Path) -> ScannerResult:  # pragma: no cover - override
        return ScannerResult(scanner=self.name, ok=False, error="repo mode not supported")

    def _timed(self) -> "_Timer":
        return _Timer()


class _Timer:
    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, *a):
        self.elapsed_ms = int((time.perf_counter() - self.start) * 1000)

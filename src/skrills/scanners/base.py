from __future__ import annotations

import time
from abc import ABC, abstractmethod

from ..models import ScannerResult


class Scanner(ABC):
    name: str = "base"

    @abstractmethod
    def scan(self, content: str) -> ScannerResult: ...

    def _timed(self) -> "_Timer":
        return _Timer()


class _Timer:
    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, *a):
        self.elapsed_ms = int((time.perf_counter() - self.start) * 1000)

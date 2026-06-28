from __future__ import annotations

import os
from pathlib import Path

from ..models import ScannerResult
from .base import Scanner


class SnykLabsScanner(Scanner):
    """Stub. No public no-auth API for skill scanning yet."""

    name = "snyk_labs"

    def scan_text(self, content: str) -> ScannerResult:
        return self._stub()

    def scan_repo(self, root: Path) -> ScannerResult:
        return self._stub()

    def _stub(self) -> ScannerResult:
        if os.environ.get("SKRILLS_SNYK_ENABLED", "false").lower() != "true":
            return ScannerResult(
                scanner=self.name, ok=False,
                error="Snyk Labs scanning disabled (no public no-auth API yet).",
            )
        return ScannerResult(scanner=self.name, ok=False, error="Snyk Labs probe not implemented.")

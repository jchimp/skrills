from __future__ import annotations

import os

from ..models import ScannerResult
from .base import Scanner


class SnykLabsScanner(Scanner):
    """Stub. Snyk Labs has no documented public no-auth API for skill scanning today.

    Leave plumbing in place so we can wire it up later if a public endpoint surfaces.
    """

    name = "snyk_labs"

    def scan(self, content: str) -> ScannerResult:
        if os.environ.get("SKRILLS_SNYK_ENABLED", "false").lower() != "true":
            return ScannerResult(
                scanner=self.name,
                ok=False,
                error="Snyk Labs scanning disabled (no public no-auth API available yet).",
            )
        # Placeholder for a future HTTP probe.
        return ScannerResult(
            scanner=self.name,
            ok=False,
            error="Snyk Labs probe not implemented.",
        )

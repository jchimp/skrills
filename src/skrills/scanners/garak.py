from __future__ import annotations

import os

import httpx

from ..models import Finding, ScannerResult, Severity
from .base import Scanner


class GarakScanner(Scanner):
    """Optional sidecar. Calls a Garak HTTP wrapper if SKRILLS_GARAK_URL is set."""

    name = "garak"

    def scan(self, content: str) -> ScannerResult:
        with self._timed() as t:
            url = os.environ.get("SKRILLS_GARAK_URL", "").strip()
            if not url:
                return ScannerResult(
                    scanner=self.name,
                    ok=False,
                    error="Garak sidecar disabled (SKRILLS_GARAK_URL not set).",
                )
            try:
                resp = httpx.post(
                    f"{url.rstrip('/')}/scan",
                    json={"prompt": content},
                    timeout=60.0,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                return ScannerResult(scanner=self.name, ok=False, error=str(e))

            findings: list[Finding] = []
            for item in data.get("findings", []):
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id=item.get("probe", "garak.probe"),
                        title=item.get("title", "Garak probe finding"),
                        severity=Severity(item.get("severity", "medium")),
                        category=item.get("category", "injection"),
                        description=item.get("description", ""),
                        evidence=item.get("evidence"),
                        remediation=item.get("remediation"),
                    )
                )
            res = ScannerResult(scanner=self.name, ok=True, findings=findings)
        res.duration_ms = t.elapsed_ms
        return res

from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path

import httpx

from ..models import Finding, ScannerResult, Severity
from .base import Scanner


class SemgrepScanner(Scanner):
    """Calls the Semgrep sidecar via /scan-tar.

    We package the repo as a tar.gz and stream it to the sidecar so the two
    containers don't need a shared volume.
    """

    name = "semgrep"
    supports_text = False  # semgrep is SAST; needs files

    def scan_text(self, content: str) -> ScannerResult:
        return ScannerResult(
            scanner=self.name, ok=False,
            error="semgrep runs on repos only; use repo upload or git URL",
        )

    def scan_repo(self, root: Path) -> ScannerResult:
        with self._timed() as t:
            url = os.environ.get("SKRILLS_SEMGREP_URL", "").strip()
            if not url:
                return ScannerResult(
                    scanner=self.name, ok=False,
                    error="semgrep sidecar disabled (SKRILLS_SEMGREP_URL not set)",
                )

            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                tf.add(str(root), arcname=".", recursive=True)
            buf.seek(0)

            try:
                resp = httpx.post(
                    f"{url.rstrip('/')}/scan-tar",
                    files={"file": ("repo.tar.gz", buf.read(), "application/gzip")},
                    timeout=httpx.Timeout(300.0, connect=10.0),
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                return ScannerResult(scanner=self.name, ok=False, error=str(e))

            findings: list[Finding] = []
            for item in data.get("findings", []):
                try:
                    sev = Severity(item.get("severity", "low"))
                except ValueError:
                    sev = Severity.LOW
                findings.append(Finding(
                    scanner=self.name,
                    rule_id=item.get("rule_id", "semgrep.rule"),
                    title=item.get("title", "Semgrep finding"),
                    severity=sev,
                    category=item.get("category", "code_security"),
                    description=item.get("description", ""),
                    file_path=item.get("file_path"),
                    line=item.get("line"),
                    evidence=item.get("evidence"),
                    remediation=item.get("remediation"),
                ))
        return ScannerResult(scanner=self.name, ok=True, duration_ms=t.elapsed_ms, findings=findings)

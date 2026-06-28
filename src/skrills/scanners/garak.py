from __future__ import annotations

import logging
import os
from pathlib import Path

import httpx

from ..ingest.limits import is_skill_file
from ..models import Finding, ScannerResult, Severity
from .base import Scanner

logger = logging.getLogger(__name__)


class GarakScanner(Scanner):
    """Optional sidecar. Runs on pasted prompt or each skill-like file in a repo."""

    name = "garak"

    def scan_text(self, content: str) -> ScannerResult:
        with self._timed() as t:
            findings = self._probe(content, file_path=None)
            if findings is None:
                return ScannerResult(scanner=self.name, ok=False, error=self._last_err)
        return ScannerResult(scanner=self.name, ok=True, duration_ms=t.elapsed_ms, findings=findings)

    def scan_repo(self, root: Path) -> ScannerResult:
        with self._timed() as t:
            findings: list[Finding] = []
            for p in root.rglob("*"):
                if not p.is_file() or not is_skill_file(p.name):
                    continue
                try:
                    content = p.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                rel = str(p.relative_to(root))
                got = self._probe(content, file_path=rel)
                if got is None:
                    return ScannerResult(scanner=self.name, ok=False, error=self._last_err)
                findings.extend(got)
        return ScannerResult(scanner=self.name, ok=True, duration_ms=t.elapsed_ms, findings=findings)

    _last_err: str = ""

    def _probe(self, content: str, file_path: str | None) -> list[Finding] | None:
        url = os.environ.get("SKRILLS_GARAK_URL", "").strip()
        if not url:
            self._last_err = "garak sidecar disabled (SKRILLS_GARAK_URL not set)"
            return None
        try:
            resp = httpx.post(
                f"{url.rstrip('/')}/scan",
                json={"prompt": content},
                timeout=60.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            logger.exception("Garak sidecar request failed")
            self._last_err = "garak sidecar request failed; see server logs"
            return None

        out: list[Finding] = []
        for item in data.get("findings", []):
            try:
                sev = Severity(item.get("severity", "medium"))
            except ValueError:
                sev = Severity.MEDIUM
            out.append(Finding(
                scanner=self.name,
                rule_id=item.get("probe", "garak.probe"),
                title=item.get("title", "Garak probe finding"),
                severity=sev,
                category=item.get("category", "injection"),
                description=item.get("description", ""),
                file_path=file_path,
                evidence=item.get("evidence"),
                remediation=item.get("remediation"),
            ))
        return out

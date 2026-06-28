from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..ingest.limits import is_text_file
from ..models import Finding, ScannerResult, Severity
from ..rule_catalog import load_catalog
from .base import Scanner

MAX_FILE_BYTES = 1 * 1024 * 1024  # don't bother scanning huge files


class HeuristicsScanner(Scanner):
    """Regex + YAML-rule pack scanner."""

    name = "heuristics"

    def __init__(self) -> None:
        # Rule definitions come from the shared catalog (single source of truth);
        # here we just compile each pattern into a matcher.
        self.rules: list[dict[str, Any]] = []
        for rule in load_catalog().values():
            try:
                compiled = {**rule, "_re": re.compile(
                    rule["pattern"], re.IGNORECASE | re.MULTILINE
                )}
            except re.error:
                continue
            self.rules.append(compiled)

    def scan_text(self, content: str) -> ScannerResult:
        with self._timed() as t:
            findings = self._scan_content(content, file_path=None)
        return ScannerResult(scanner=self.name, ok=True, duration_ms=t.elapsed_ms, findings=findings)

    def scan_repo(self, root: Path) -> ScannerResult:
        with self._timed() as t:
            findings: list[Finding] = []
            for p in root.rglob("*"):
                if not p.is_file():
                    continue
                if not is_text_file(p.name):
                    continue
                try:
                    if p.stat().st_size > MAX_FILE_BYTES:
                        continue
                    content = p.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                rel = str(p.relative_to(root))
                findings.extend(self._scan_content(content, file_path=rel))
        return ScannerResult(scanner=self.name, ok=True, duration_ms=t.elapsed_ms, findings=findings)

    def _scan_content(self, content: str, file_path: str | None) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for rule in self.rules:
            pattern: re.Pattern[str] = rule["_re"]
            for m in pattern.finditer(content):
                line_no = content[: m.start()].count("\n") + 1
                snippet = lines[line_no - 1] if line_no - 1 < len(lines) else m.group(0)
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id=rule["id"],
                        title=rule["title"],
                        severity=Severity(rule.get("severity", "medium")),
                        category=rule.get("category", "other"),
                        description=rule.get("description", ""),
                        file_path=file_path,
                        evidence=snippet.strip()[:240],
                        line=line_no,
                        remediation=rule.get("remediation"),
                    )
                )
        return findings

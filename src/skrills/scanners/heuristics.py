from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

import regex

from ..ingest.limits import is_text_file
from ..models import Finding, ScannerResult, Severity
from ..rule_catalog import load_catalog
from .base import Scanner

logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 1 * 1024 * 1024  # don't bother scanning huge files


def _regex_timeout() -> float:
    """Per-file wall-clock budget for regex matching (seconds). Bounds catastrophic
    backtracking; the stdlib `re` can't be interrupted, the `regex` module can."""
    try:
        return float(os.environ.get("SKRILLS_REGEX_TIMEOUT", "2.0"))
    except ValueError:
        return 2.0


class HeuristicsScanner(Scanner):
    """Regex + YAML-rule pack scanner."""

    name = "heuristics"

    def __init__(self) -> None:
        # Rule definitions come from the shared catalog (single source of truth);
        # here we just compile each pattern into a matcher.
        self.rules: list[dict[str, Any]] = []
        for rule in load_catalog().values():
            try:
                compiled = {**rule, "_re": regex.compile(
                    rule["pattern"], regex.IGNORECASE | regex.MULTILINE
                )}
            except regex.error:
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
        # Per-file regex time budget: a crafted input can trigger catastrophic
        # backtracking, so cap total matching time and skip rules that exceed it.
        deadline = time.monotonic() + _regex_timeout()
        for rule in self.rules:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                logger.warning(
                    "heuristics: regex time budget exhausted for %s; remaining rules skipped",
                    file_path or "<paste>",
                )
                break
            try:
                matches = list(rule["_re"].finditer(content, timeout=remaining))
            except TimeoutError:
                logger.warning(
                    "heuristics rule %s exceeded regex timeout on %s",
                    rule["id"], file_path or "<paste>",
                )
                continue
            for m in matches:
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

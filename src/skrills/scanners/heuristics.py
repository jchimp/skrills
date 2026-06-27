from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from ..models import Finding, ScannerResult, Severity
from .base import Scanner

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


class HeuristicsScanner(Scanner):
    """Regex + YAML-rule pack scanner. Covers OWASP LLM Top 10 patterns."""

    name = "heuristics"

    def __init__(self) -> None:
        self.rules: list[dict[str, Any]] = []
        for f in ("injection.yaml", "tool_risks.yaml"):
            p = RULES_DIR / f
            if not p.exists():
                continue
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            for r in data.get("rules", []):
                try:
                    r["_re"] = re.compile(r["pattern"], re.IGNORECASE | re.MULTILINE)
                    self.rules.append(r)
                except re.error:
                    continue

    def scan(self, content: str) -> ScannerResult:
        with self._timed() as t:
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
                            evidence=snippet.strip()[:240],
                            line=line_no,
                            remediation=rule.get("remediation"),
                        )
                    )

            res = ScannerResult(scanner=self.name, ok=True, findings=findings)
        res.duration_ms = t.elapsed_ms
        return res

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..models import Finding, ScannerResult, Severity
from .base import Scanner


class GitleaksScanner(Scanner):
    name = "gitleaks"

    def scan(self, content: str) -> ScannerResult:
        with self._timed() as t:
            if shutil.which("gitleaks") is None:
                return ScannerResult(
                    scanner=self.name,
                    ok=False,
                    error="gitleaks binary not on PATH",
                )

            findings: list[Finding] = []
            with tempfile.TemporaryDirectory() as td:
                src = Path(td) / "skill.md"
                src.write_text(content, encoding="utf-8")
                report = Path(td) / "report.json"
                try:
                    proc = subprocess.run(
                        [
                            "gitleaks",
                            "detect",
                            "--no-git",
                            "--source",
                            str(src.parent),
                            "--report-format",
                            "json",
                            "--report-path",
                            str(report),
                            "--exit-code",
                            "0",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                    return ScannerResult(scanner=self.name, ok=False, error=str(e))

                if report.exists():
                    try:
                        data = json.loads(report.read_text() or "[]")
                    except json.JSONDecodeError:
                        data = []
                    for item in data:
                        findings.append(
                            Finding(
                                scanner=self.name,
                                rule_id=item.get("RuleID", "gitleaks-secret"),
                                title=f"Secret detected: {item.get('Description', 'unknown')}",
                                severity=Severity.CRITICAL,
                                category="secret",
                                description=(
                                    f"A potential secret was detected in the skill content "
                                    f"(rule: {item.get('RuleID', 'unknown')})."
                                ),
                                evidence=_redact(item.get("Match", "")),
                                line=item.get("StartLine"),
                                remediation=(
                                    "Remove the secret from the skill content. Rotate any "
                                    "exposed credentials immediately. Reference secrets via "
                                    "environment variables or a vault instead of inlining them."
                                ),
                            )
                        )

            res = ScannerResult(scanner=self.name, ok=True, findings=findings)
        res.duration_ms = t.elapsed_ms
        return res


def _redact(s: str, keep: int = 4) -> str:
    if not s:
        return ""
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}...{s[-keep:]} (redacted)"

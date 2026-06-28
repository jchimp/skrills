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

    def scan_text(self, content: str) -> ScannerResult:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "skill.md"
            src.write_text(content, encoding="utf-8")
            return self.scan_repo(Path(td))

    def scan_repo(self, root: Path) -> ScannerResult:
        with self._timed() as t:
            if shutil.which("gitleaks") is None:
                return ScannerResult(
                    scanner=self.name, ok=False, error="gitleaks binary not on PATH"
                )
            with tempfile.TemporaryDirectory() as td:
                report = Path(td) / "report.json"
                try:
                    subprocess.run(
                        [
                            "gitleaks", "detect",
                            "--no-git",
                            "--source", str(root),
                            "--report-format", "json",
                            "--report-path", str(report),
                            "--exit-code", "0",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                    return ScannerResult(scanner=self.name, ok=False, error=str(e))

                findings: list[Finding] = []
                if report.exists():
                    try:
                        data = json.loads(report.read_text() or "[]")
                    except json.JSONDecodeError:
                        data = []
                    for item in data:
                        file_rel = item.get("File", "")
                        try:
                            file_rel = str(Path(file_rel).resolve().relative_to(root.resolve()))
                        except (ValueError, OSError):
                            pass
                        findings.append(
                            Finding(
                                scanner=self.name,
                                rule_id=item.get("RuleID", "gitleaks-secret"),
                                title=f"Secret detected: {item.get('Description', 'unknown')}",
                                severity=Severity.CRITICAL,
                                category="secret",
                                description=(
                                    f"A potential secret was detected "
                                    f"(rule: {item.get('RuleID', 'unknown')})."
                                ),
                                file_path=file_rel or None,
                                evidence=_redact(item.get("Match", "")),
                                line=item.get("StartLine"),
                                remediation=(
                                    "Remove the secret. Rotate any exposed credentials. "
                                    "Reference secrets via env vars or a vault."
                                ),
                            )
                        )
        return ScannerResult(scanner=self.name, ok=True, duration_ms=t.elapsed_ms, findings=findings)


def _redact(s: str, keep: int = 4) -> str:
    if not s:
        return ""
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}...{s[-keep:]} (redacted)"

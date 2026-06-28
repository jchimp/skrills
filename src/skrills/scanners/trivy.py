from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..models import Finding, ScannerResult, Severity
from .base import Scanner

_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyScanner(Scanner):
    """trivy fs — dependency CVEs + misconfig scanning."""

    name = "trivy"
    supports_text = False

    def scan_text(self, content: str) -> ScannerResult:
        return ScannerResult(
            scanner=self.name, ok=False,
            error="trivy runs on repos only",
        )

    def scan_repo(self, root: Path) -> ScannerResult:
        with self._timed() as t:
            if shutil.which("trivy") is None:
                return ScannerResult(
                    scanner=self.name, ok=False, error="trivy binary not on PATH"
                )

            with tempfile.TemporaryDirectory() as td:
                report = Path(td) / "trivy.json"
                try:
                    subprocess.run(
                        [
                            "trivy", "fs",
                            "--scanners", "vuln,misconfig,secret",
                            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                            "--format", "json",
                            "--output", str(report),
                            "--quiet",
                            "--cache-dir", str(Path(td) / "cache"),
                            "--timeout", "5m",
                            str(root),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=360,
                    )
                except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                    return ScannerResult(scanner=self.name, ok=False, error=str(e))

                findings: list[Finding] = []
                if report.exists():
                    try:
                        data = json.loads(report.read_text() or "{}")
                    except json.JSONDecodeError:
                        data = {}
                    for tgt in data.get("Results", []) or []:
                        target = tgt.get("Target", "")
                        rel = _rel(target, root)
                        for v in tgt.get("Vulnerabilities", []) or []:
                            sev = _SEV_MAP.get(v.get("Severity", "UNKNOWN"), Severity.INFO)
                            findings.append(Finding(
                                scanner=self.name,
                                rule_id=v.get("VulnerabilityID", "trivy-cve"),
                                title=f"{v.get('VulnerabilityID')} in {v.get('PkgName')}",
                                severity=sev,
                                category="dependency_cve",
                                description=(v.get("Title") or v.get("Description") or "")[:500],
                                file_path=rel,
                                remediation=(
                                    f"Upgrade {v.get('PkgName')} to {v.get('FixedVersion')}"
                                    if v.get("FixedVersion") else None
                                ),
                            ))
                        for mc in tgt.get("Misconfigurations", []) or []:
                            sev = _SEV_MAP.get(mc.get("Severity", "UNKNOWN"), Severity.INFO)
                            findings.append(Finding(
                                scanner=self.name,
                                rule_id=mc.get("ID", "trivy-misconfig"),
                                title=mc.get("Title", "Misconfiguration"),
                                severity=sev,
                                category="misconfig",
                                description=(mc.get("Description") or "")[:500],
                                file_path=rel,
                                remediation=mc.get("Resolution"),
                            ))
                        for sec in tgt.get("Secrets", []) or []:
                            findings.append(Finding(
                                scanner=self.name,
                                rule_id=sec.get("RuleID", "trivy-secret"),
                                title=f"Secret: {sec.get('Title','detected')}",
                                severity=Severity.CRITICAL,
                                category="secret",
                                description=sec.get("Match", "")[:200],
                                file_path=rel,
                                line=sec.get("StartLine"),
                                remediation="Rotate the credential and remove from repo.",
                            ))
        return ScannerResult(scanner=self.name, ok=True, duration_ms=t.elapsed_ms, findings=findings)


def _rel(p: str, root: Path) -> str:
    try:
        return str(Path(p).resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        return p

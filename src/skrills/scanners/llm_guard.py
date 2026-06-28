from __future__ import annotations

from pathlib import Path

from ..ingest.limits import is_skill_file
from ..models import Finding, ScannerResult, Severity
from .base import Scanner


class LLMGuardScanner(Scanner):
    """Wraps llm-guard input scanners. Repo mode runs only on skill-like files."""

    name = "llm_guard"

    def scan_text(self, content: str) -> ScannerResult:
        with self._timed() as t:
            findings = self._scan_one(content, file_path=None)
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
                findings.extend(self._scan_one(content, file_path=rel))
        return ScannerResult(scanner=self.name, ok=True, duration_ms=t.elapsed_ms, findings=findings)

    def _scan_one(self, content: str, file_path: str | None) -> list[Finding]:
        try:
            from llm_guard.input_scanners import BanTopics, PromptInjection, Toxicity
            from llm_guard.input_scanners.prompt_injection import MatchType
        except Exception as e:
            return [
                Finding(
                    scanner=self.name,
                    rule_id="llmguard.unavailable",
                    title="llm-guard unavailable",
                    severity=Severity.INFO,
                    category="other",
                    description=str(e),
                    file_path=file_path,
                )
            ]

        findings: list[Finding] = []
        try:
            pi = PromptInjection(threshold=0.5, match_type=MatchType.FULL)
            _, valid, score = pi.scan(content)
            if not valid:
                findings.append(Finding(
                    scanner=self.name,
                    rule_id="llmguard.prompt_injection",
                    title="Prompt injection pattern detected",
                    severity=Severity.HIGH if score >= 0.75 else Severity.MEDIUM,
                    category="injection",
                    description=f"llm-guard PromptInjection scanner risk score {score:.2f}.",
                    file_path=file_path,
                    remediation=(
                        "Strip user directives from skill context; delimit untrusted input."
                    ),
                ))
        except Exception:
            pass

        try:
            tox = Toxicity(threshold=0.7)
            _, valid, score = tox.scan(content)
            if not valid:
                findings.append(Finding(
                    scanner=self.name,
                    rule_id="llmguard.toxicity",
                    title="Toxic / harmful language detected",
                    severity=Severity.MEDIUM,
                    category="other",
                    description=f"Toxicity score {score:.2f} exceeds threshold.",
                    file_path=file_path,
                ))
        except Exception:
            pass

        try:
            topics = BanTopics(topics=["violence", "self-harm", "illegal"], threshold=0.7)
            _, valid, score = topics.scan(content)
            if not valid:
                findings.append(Finding(
                    scanner=self.name,
                    rule_id="llmguard.banned_topics",
                    title="Banned topic detected",
                    severity=Severity.MEDIUM,
                    category="other",
                    description=f"BanTopics score {score:.2f}.",
                    file_path=file_path,
                ))
        except Exception:
            pass

        return findings

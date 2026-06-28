from __future__ import annotations

import logging

from ..models import Finding, ScannerResult, Severity
from .base import Scanner

logger = logging.getLogger(__name__)


class LLMGuardScanner(Scanner):
    """Wraps llm-guard input scanners. Falls back gracefully if not installed."""

    name = "llm_guard"

    def scan(self, content: str) -> ScannerResult:
        with self._timed() as t:
            try:
                # Lazy import — heavy library, only load on first use
                from llm_guard.input_scanners import PromptInjection, BanTopics, Toxicity
                from llm_guard.input_scanners.prompt_injection import MatchType
            except Exception:  # pragma: no cover
                logger.exception("llm-guard import failed")
                return ScannerResult(
                    scanner=self.name,
                    ok=False,
                    error="llm-guard not available; see server logs.",
                )

            findings: list[Finding] = []
            try:
                pi = PromptInjection(threshold=0.5, match_type=MatchType.FULL)
                _, valid, score = pi.scan(content)
                if not valid:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            rule_id="llmguard.prompt_injection",
                            title="Prompt injection pattern detected",
                            severity=Severity.HIGH if score >= 0.75 else Severity.MEDIUM,
                            category="injection",
                            description=(
                                f"llm-guard PromptInjection scanner flagged this content "
                                f"with risk score {score:.2f}."
                            ),
                            remediation=(
                                "Review the content for instructions that attempt to override "
                                "system behavior. Strip user-supplied directives from skill "
                                "context, and clearly delimit untrusted input."
                            ),
                        )
                    )
            except Exception:
                logger.exception("llm-guard PromptInjection scan failed")
                findings.append(
                    Finding(
                        scanner=self.name,
                        rule_id="llmguard.prompt_injection.error",
                        title="PromptInjection scanner error",
                        severity=Severity.INFO,
                        category="other",
                        description="Scanner failed to run; see server logs.",
                    )
                )

            try:
                tox = Toxicity(threshold=0.7)
                _, valid, score = tox.scan(content)
                if not valid:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            rule_id="llmguard.toxicity",
                            title="Toxic / harmful language detected",
                            severity=Severity.MEDIUM,
                            category="other",
                            description=f"Toxicity score {score:.2f} exceeds threshold.",
                            remediation="Sanitize abusive or harmful phrasing in the skill.",
                        )
                    )
            except Exception:
                pass  # Toxicity model may not be available in slim images

            try:
                topics = BanTopics(topics=["violence", "self-harm", "illegal"], threshold=0.7)
                _, valid, score = topics.scan(content)
                if not valid:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            rule_id="llmguard.banned_topics",
                            title="Banned topic detected",
                            severity=Severity.MEDIUM,
                            category="other",
                            description=f"BanTopics score {score:.2f}.",
                        )
                    )
            except Exception:
                pass

            res = ScannerResult(scanner=self.name, ok=True, findings=findings)
        res.duration_ms = t.elapsed_ms
        return res

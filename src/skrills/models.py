from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


class Finding(BaseModel):
    scanner: str
    rule_id: str
    title: str
    severity: Severity
    category: str  # injection | tool_poisoning | secret | excessive_agency | indirect_injection | other
    description: str
    evidence: str | None = None
    line: int | None = None
    remediation: str | None = None


class ScannerResult(BaseModel):
    scanner: str
    ok: bool = True
    duration_ms: int = 0
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None


class ScanRequest(BaseModel):
    content: str
    enable_gitleaks: bool = True
    enable_llm_guard: bool = True
    enable_heuristics: bool = True
    enable_snyk: bool = False
    enable_garak: bool = False
    ephemeral: bool = False


class ScanResult(BaseModel):
    id: str
    created_at: datetime
    input_hash: str
    input_size: int
    ephemeral: bool
    score: int
    severity_counts: dict[str, int]
    scanners: list[ScannerResult]
    findings: list[Finding]

    @classmethod
    def compute_score(cls, findings: list[Finding]) -> int:
        deduction = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
        return max(0, 100 - deduction)

    @classmethod
    def count_severities(cls, findings: list[Finding]) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in findings:
            out[f.severity.value] += 1
        return out


class ScanSummary(BaseModel):
    id: str
    created_at: datetime
    score: int
    input_size: int
    severity_counts: dict[str, int]

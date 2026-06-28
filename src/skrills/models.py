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


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class SourceType(str, Enum):
    PASTE = "paste"
    UPLOAD = "upload"
    GIT = "git"


class Finding(BaseModel):
    scanner: str
    rule_id: str
    title: str
    severity: Severity
    category: str
    description: str
    file_path: str | None = None
    evidence: str | None = None
    line: int | None = None
    remediation: str | None = None


class ScannerResult(BaseModel):
    scanner: str
    ok: bool = True
    duration_ms: int = 0
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None


class FileEntry(BaseModel):
    path: str
    size: int
    is_text: bool
    is_skill: bool


class ScanOptions(BaseModel):
    enable_heuristics: bool = True
    enable_gitleaks: bool = True
    enable_llm_guard: bool = True
    enable_semgrep: bool = False
    enable_trivy: bool = False
    enable_snyk: bool = False
    enable_garak: bool = False
    ephemeral: bool = False


class ScanResult(BaseModel):
    id: str
    created_at: datetime
    status: ScanStatus = ScanStatus.COMPLETE
    source_type: SourceType
    source_label: str
    input_hash: str
    input_size: int
    file_count: int = 1
    ephemeral: bool
    score: int = 100
    severity_counts: dict[str, int] = Field(default_factory=dict)
    scanners: list[ScannerResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    files: list[FileEntry] = Field(default_factory=list)
    options: ScanOptions = Field(default_factory=ScanOptions)
    error: str | None = None
    # Stored content for paste mode (so we can re-show / re-scan).
    # None when ephemeral, or for repo scans (we don't store entire repos).
    stored_content: str | None = None

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
    status: ScanStatus
    source_type: SourceType
    source_label: str
    score: int
    input_size: int
    file_count: int
    severity_counts: dict[str, int]

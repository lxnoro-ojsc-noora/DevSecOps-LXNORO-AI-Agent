"""Shared data structures for the DevSecOps LXNORO AI Agent."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITY_ORDER)}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Finding:
    id: str
    rule_id: str
    title: str
    severity: str
    path: str
    line: int
    evidence: str  # always redacted
    explanation: str
    impact: str
    remediation: str
    source: str = "deterministic"
    fixable: bool = False  # a deterministic fixer exists for this rule


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # performed | unavailable | skipped
    detail: str = ""


@dataclass(frozen=True)
class Hygiene:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    hygiene: list[Hygiene] = field(default_factory=list)
    files_scanned: int = 0
    scanned_at: str = ""


def sort_findings(findings):
    return sorted(
        findings, key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.path, f.line)
    )


def count_by_severity(findings) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts

"""Scan pipeline: built-in rules + Bandit + dependency advisories, for live or simulation mode.

The same function backs the first analysis, the post-fix residual scan and every rescan, so
fingerprints stay comparable across stages.
"""
from __future__ import annotations

from .engines import bandit_scan, osv_scan, simulated_dependency_scan
from .models import Check, ScanResult, sort_findings, utc_now
from .scanners import scan_project

MODES = ("live", "simulation")
_REPLACED = ("Dependency vulnerability", "External SAST")


def run_scans(text_files: dict, other_paths=(), mode: str = "live", osv_post=None) -> ScanResult:
    base = scan_project(text_files, other_paths)
    checks = [c for c in base.checks if not c.name.startswith(_REPLACED)]
    occupied = {(f.path, f.line) for f in base.findings}
    bandit_findings, bandit_check = bandit_scan(text_files, occupied)
    if mode == "simulation":
        dep_findings, dep_check = simulated_dependency_scan(text_files)
    else:
        dep_findings, dep_check = osv_scan(text_files, osv_post)
    checks += [
        bandit_check,
        dep_check,
        Check("Semgrep", "unavailable",
              "Not integrated in the app; GitLab CI runs Semgrep SAST on this tool's own repository only."),
    ]
    merged = {f.id: f for f in base.findings + bandit_findings + dep_findings}
    return ScanResult(findings=sort_findings(list(merged.values())), checks=checks, hygiene=base.hygiene,
                      files_scanned=base.files_scanned, scanned_at=utc_now())

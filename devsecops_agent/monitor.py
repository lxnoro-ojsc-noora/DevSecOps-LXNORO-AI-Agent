"""Stage 7: on-demand rescan history. This is NOT continuous monitoring."""
from __future__ import annotations

from dataclasses import dataclass

from .models import count_by_severity, utc_now

DRIFT_PATH = "lxnoro_simulated_drift.py"
DRIFT_CONTENT = (
    "# SIMULATED DRIFT injected by the demo button (not real project code)\n"
    "import subprocess\n\n\n"
    "def run(cmd, expr):\n"
    "    subprocess.run(cmd, shell=" + "True)\n"
    "    return ev" + "al(expr)\n"
)


def fingerprint(finding) -> tuple:
    """Line-independent identity so that import insertion does not make old findings look new."""
    return (finding.rule_id, finding.path, finding.evidence)


@dataclass
class ScanRecord:
    ts: str
    kind: str
    status: str
    total: int
    new: int
    resolved: int
    counts: str


def record_scan(history: list, kind: str, scan, baseline):
    """Append a record. `baseline` is a set of fingerprints, or None to record the baseline itself."""
    current = {fingerprint(f) for f in scan.findings}
    if baseline is None:
        new, resolved, status = [], set(), "baseline recorded"
    else:
        new = [f for f in scan.findings if fingerprint(f) not in baseline]
        resolved = baseline - current
        status = f"{len(new)} new finding(s)" if new else "no new findings"
    counts = ", ".join(f"{k}={v}" for k, v in count_by_severity(scan.findings).items() if v)
    history.append(ScanRecord(utc_now(), kind, status, len(scan.findings), len(new), len(resolved), counts or "none"))
    return new, resolved


def simulate_drift(files: dict) -> dict:
    out = dict(files)
    out[DRIFT_PATH] = DRIFT_CONTENT
    return out

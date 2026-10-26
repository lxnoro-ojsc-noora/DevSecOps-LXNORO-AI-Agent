"""Stage 6: deployment SIMULATION. No application is ever deployed by this module."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .models import utc_now


def gate(pending: int, residual_high_critical: int, accepted: bool) -> list[str]:
    reasons = []
    if pending:
        reasons.append(f"{pending} change(s) are still awaiting a human approval decision")
    if residual_high_critical and not accepted:
        reasons.append(
            f"{residual_high_critical} high/critical finding(s) remain open: acknowledge the residual risk to continue"
        )
    return reasons


def package_digest(text_files: dict, binary_files: dict) -> str:
    h = hashlib.sha256()
    for path in sorted(set(text_files) | set(binary_files)):
        data = text_files[path].encode("utf-8") if path in text_files else binary_files[path]
        h.update(path.encode("utf-8") + b"\0" + hashlib.sha256(data).digest())
    return h.hexdigest()


@dataclass
class DeploymentRecord:
    project: str
    kind: str = "simulation"
    real_deployment: bool = False
    status: str = "simulated"
    started_at: str = ""
    finished_at: str = ""
    digest: str = ""
    url: str = ""  # always empty: nothing is deployed
    steps: list = field(default_factory=list)


def simulate_deployment(project: str, text_files: dict, binary_files: dict, residual: list,
                        pending: int = 0, accepted_residual_risk: bool = False) -> DeploymentRecord:
    hc = sum(1 for f in residual if f.severity in ("critical", "high"))
    reasons = gate(pending, hc, accepted_residual_risk)
    if reasons:
        raise ValueError("; ".join(reasons))
    started = utc_now()
    digest = package_digest(text_files, binary_files)
    steps = [
        {"step": "Policy gate", "status": "passed", "nature": "computed",
         "detail": f"No pending approvals; {hc} high/critical finding(s) open"
                   + (" (residual risk acknowledged)" if hc else "")},
        {"step": "Package corrected source", "status": "done", "nature": "computed",
         "detail": f"{len(text_files) + len(binary_files)} file(s), sha256 {digest[:16]}..."},
        {"step": "Security scan of package", "status": "done", "nature": "computed",
         "detail": f"{len(residual)} open finding(s) in the packaged code"},
        {"step": "Build container image", "status": "simulated", "nature": "simulated",
         "detail": "No image was built"},
        {"step": "Release to an environment", "status": "simulated", "nature": "simulated",
         "detail": "Nothing was deployed; no URL exists"},
        {"step": "Health check", "status": "simulated", "nature": "simulated",
         "detail": "No service is running to check"},
    ]
    return DeploymentRecord(project=project, started_at=started, finished_at=utc_now(), digest=digest, steps=steps)

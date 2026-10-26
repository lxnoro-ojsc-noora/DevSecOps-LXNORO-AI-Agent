"""Session state, workflow actions and callbacks. No HTML here: presentation lives elsewhere.

Security decisions (approval gating, path safety, redaction) are enforced in devsecops_agent;
this module only wires user actions to those backend operations.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone

import streamlit as st

from devsecops_agent import ai as ai_mod
from devsecops_agent import orchestrator as orch
from devsecops_agent import deploy, export, github_io, intake, monitor, remediation
from devsecops_agent import report as report_mod
from devsecops_agent.ai import llm
from devsecops_agent.demo import demo_project
from devsecops_agent.models import Check, utc_now
from devsecops_agent.safe_zip import UnsafeArchiveError
from devsecops_agent.pipeline import run_scans

S = st.session_state

SCOPES = {
    "p2": {"decisions": "decisions", "logged": "logged", "apply": "apply_result", "label": "remediation"},
    "p5": {"decisions": "decisions5", "logged": "logged5", "apply": "apply5", "label": "post-deployment"},
}


def cfg_get(key: str):
    try:
        value = st.secrets.get(key)
    except Exception:
        value = None
    return (str(value) if value else None) or os.environ.get(key)


def safe_name(name: str, limit: int = 40) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(name))[:limit].strip("-.") or "project"


def _defaults() -> dict:
    return {
        "stage": 1, "project": None, "scan": None, "ai": None, "plan": [], "decisions": {}, "logged": set(),
        "apply_result": None, "corrected": None, "zip_bytes": None, "residual": None,
        "deployment": None, "deploy_err": "", "live_files": None, "baseline": None, "history": [],
        "rescan_new": [], "last_scan": None, "last_rescan": None, "plan5": [], "decisions5": {},
        "logged5": set(), "apply5": None, "gh_access": None, "gh_result": None, "audit": [],
        "gitlab_session": None, "gitlab_output": [], "gitlab_msg": "", "gitlab_ok": "", "sim_paths": set(),
        "ai_health": None, "ai_triage": None, "ai_fixes": None, "ai_validation": None, "ai_rescan": None,
        "ai_msg": "", "base_plan": [],
    }


def init_state() -> None:
    for key, value in _defaults().items():
        if key not in S:
            S[key] = value
    if "mode" not in S:
        S["mode"] = "live"
    if "branch_default" not in S:
        S["branch_default"] = "lxnoro-agent/fixes-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def reset_workflow() -> None:
    for key, value in _defaults().items():
        S[key] = value


# ---------------------------------------------------------------- navigation

def reach() -> dict:
    return {
        1: True, 2: S.project is not None, 3: S.scan is not None, 4: S.scan is not None,
        5: S.scan is not None, 6: S.corrected is not None, 7: S.deployment is not None,
    }


def done_map() -> dict:
    return {
        1: S.project is not None, 2: S.scan is not None, 3: S.scan is not None,
        4: S.apply_result is not None, 5: S.zip_bytes is not None, 6: S.deployment is not None,
        7: len(S.history) > 1,
    }


def nav_states() -> dict:
    can, done = reach(), done_map()
    states = {}
    for n in range(1, 8):
        if n == S.stage:
            states[n] = "active"
        elif not can[n]:
            states[n] = "locked"
        else:
            states[n] = "done" if done[n] else "ready"
    return states


def goto(n: int) -> None:
    if reach().get(n):
        S.stage = n


# ---------------------------------------------------------------- derived data

def current_report() -> dict:
    statuses = S.apply_result.statuses if S.apply_result else {}
    notes = S.ai.notes if S.ai else {}
    label = S.ai.label if S.ai else ""
    return report_mod.build_report(S.project.name, S.scan, notes, label, statuses)


def residual_scan():
    if S.residual is None:
        S.residual = run_scans(S.corrected, list(S.project.binary_files), S.mode)
    return S.residual


def pending_count() -> int:
    statuses = S.apply_result.statuses if S.apply_result else {}
    return sum(
        1 for r in S.plan
        if r.needs_approval and statuses.get(r.finding_id, "pending_approval") == "pending_approval"
    )


# ---------------------------------------------------------------- actions

def load_project(loader, label: str) -> None:
    ok = False
    with st.status(f"Importing via {label}: validating (nothing is executed)...", expanded=True) as status:
        try:
            project = loader()
        except (UnsafeArchiveError, github_io.GitHubError) as exc:
            status.update(label="Import rejected", state="error")
            st.error(str(exc))
            return
        except Exception as exc:
            status.update(label="Import failed", state="error")
            st.error(f"Unexpected error ({type(exc).__name__}). The project was not loaded.")
            return
        reset_workflow()
        S.project = project
        remediation.audit_event(S.audit, "system", "project_loaded", "intake",
                                detail=f"{project.name} via {project.source}; {len(project.text_files)} text file(s)")
        status.update(label="Project validated and loaded", state="complete")
        ok = True
    if ok:
        S.stage = 2
        st.rerun()


def run_analysis(provider_id: str) -> None:
    bar = st.progress(5, text="Running deterministic checks (static; nothing is executed)...")
    scan = run_scans(S.project.text_files, list(S.project.binary_files), S.mode)
    bar.progress(55, text="Deterministic checks complete.")
    ai_res = None
    cfg = ai_mod.load_config(cfg_get) if provider_id == "external" else None
    if provider_id == "external" and cfg:
        def tick(i, n):
            bar.progress(55 + int(40 * i / max(n, 1)), text=f"AI explanations {i}/{n}...")

        ai_res = ai_mod.explain_findings(cfg, scan.findings, progress=tick)
        detail = f"{len(ai_res.notes)} of {ai_res.attempted} explanation(s) from {ai_res.label}"
        if ai_res.failed:
            detail += f"; {ai_res.failed} failed ({', '.join(sorted(set(ai_res.errors)))})"
        scan.checks.append(Check("AI explanations (external API)", "performed" if ai_res.ok else "unavailable", detail))
    elif provider_id == "gitlab":
        scan.checks.append(Check("AI triage (GitLab Duo Agent Platform)", "skipped",
                                 "Asynchronous: submit it below; results are produced inside GitLab."))
    else:
        scan.checks.append(Check("AI explanations", "unavailable", "No AI provider selected; deterministic results only."))
    S.scan, S.ai = scan, ai_res
    S.plan = remediation.plan_remediations(S.project.text_files, scan.findings)
    S.decisions, S.logged, S.apply_result = {}, set(), None
    S.corrected, S.zip_bytes, S.residual = None, None, None
    S.deployment, S.live_files, S.baseline, S.history = None, None, None, []
    S.gitlab_session, S.gitlab_output, S.gitlab_msg, S.gitlab_ok = None, [], "", ""
    S.ai_triage, S.ai_fixes, S.ai_validation, S.ai_rescan, S.ai_msg = None, None, None, None, ""
    S.base_plan = list(S.plan)
    remediation.audit_event(S.audit, "system", "analysis_completed", "analysis",
                            detail=f"{len(scan.findings)} finding(s); AI explanations: {'yes' if ai_res and ai_res.ok else 'no'}")
    bar.progress(100, text="Analysis complete.")


def gitlab_test() -> None:
    cfg = ai_mod.load_gitlab_config(cfg_get)
    if not cfg:
        S.gitlab_msg, S.gitlab_ok = "GitLab AI is not configured.", ""
        return
    ok, message = ai_mod.check_access(cfg)
    S.gitlab_ok, S.gitlab_msg = (message, "") if ok else ("", message)


def gitlab_submit() -> None:
    cfg = ai_mod.load_gitlab_config(cfg_get)
    if not cfg or not S.scan:
        S.gitlab_msg = "GitLab AI is not configured or there is no scan to triage."
        return
    try:
        session = ai_mod.submit_triage(cfg, S.scan.findings)
    except ai_mod.GitLabAIError as exc:
        S.gitlab_msg, S.gitlab_ok = str(exc), ""
        return
    S.gitlab_session, S.gitlab_msg, S.gitlab_output = session, "", []
    remediation.audit_event(S.audit, "system", "gitlab_session_submitted", "analysis",
                            detail=f"Read-only Duo session {session.id} ({session.status or 'unknown status'})")


def gitlab_refresh() -> None:
    cfg = ai_mod.load_gitlab_config(cfg_get)
    if not cfg or not S.gitlab_session:
        return
    try:
        S.gitlab_session = ai_mod.get_session(cfg, S.gitlab_session.id)
        S.gitlab_output = ai_mod.get_output(cfg, S.gitlab_session.id)
        S.gitlab_msg = ""
    except ai_mod.GitLabAIError as exc:
        S.gitlab_msg = str(exc)


def set_mode() -> None:
    """Switch between live and simulation. The workflow is reset so results never mix modes."""
    choice = S.get("mode_choice")
    if choice in ("live", "simulation") and choice != S.mode:
        reset_workflow()
        S.mode = choice
        S.stage = 1


def ai_client():
    """Return (client, reason). Live mode never falls back to the simulated client."""
    if S.mode == "simulation":
        return orch.SimulatedClient(), ""
    cfg = ai_mod.load_config(cfg_get)
    if cfg is None:
        return None, ("Live AI is unavailable: no external provider is configured "
                      "(set AI_PROVIDER, AI_API_KEY and AI_MODEL as secrets). Switch to Simulation mode for a labelled demo.")
    return orch.LiveClient(cfg), ""


def load_demo() -> None:
    if S.mode != "simulation":
        return
    project = demo_project()
    reset_workflow()
    S.project = project
    remediation.audit_event(S.audit, "system", "project_loaded", "intake",
                            detail="SIMULATED demo project (built-in, never executed)")
    S.stage = 2


def ai_test() -> None:
    client, reason = ai_client()
    if client is None:
        S.ai_health = {"state": "unavailable", "detail": reason}
    elif not client.live:
        S.ai_health = {"state": "simulated", "detail": "Simulation mode: no model is called."}
    else:
        res = llm.ping(client.cfg)
        detail = f"{res.message} ({res.latency_ms} ms)" if res.ok else f"{res.kind}: {res.message}"
        S.ai_health = {"state": "verified" if res.ok else "failed", "detail": detail, "ts": utc_now()}


def _ai_run(action: str, scope: str, fn) -> None:
    client, reason = ai_client()
    if client is None:
        S.ai_msg = reason
        return
    try:
        detail = fn(client)
    except llm.AIError as exc:
        S.ai_msg = f"{action} failed ({exc.kind}): {exc}"
        return
    S.ai_msg = ""
    remediation.audit_event(S.audit, "system", action, scope, detail=f"{client.label}: {detail}")


def ai_triage_action() -> None:
    if not S.scan:
        return

    def run(client):
        S.ai_triage = orch.triage(client, S.scan.findings)
        return f"{len(S.ai_triage.priorities)} ranked, {S.ai_triage.discarded} discarded"

    _ai_run("ai_triage", "analysis", run)


def ai_fixes_action() -> None:
    if not S.scan:
        return

    def run(client):
        S.ai_fixes = orch.propose_fixes(client, S.project.text_files, S.scan.findings)
        S.plan = list(S.base_plan) + S.ai_fixes.candidates
        return (f"{len(S.ai_fixes.candidates)} candidate(s) passed deterministic checks, "
                f"{len(S.ai_fixes.rejected)} rejected")

    _ai_run("ai_fixes_proposed", "remediation", run)


def ai_validation_action() -> None:
    if not S.apply_result:
        return

    def run(client):
        facts = orch.validation_facts(S.plan, S.apply_result.statuses)
        S.ai_validation = orch.summarize(client, "validation", facts)
        return "validation summary produced"

    _ai_run("ai_validation_summary", "remediation", run)


def ai_rescan_action() -> None:
    if not (S.last_scan and S.last_rescan):
        S.ai_msg = "Run a rescan first: there is nothing to interpret yet."
        return

    def run(client):
        lr = S.last_rescan
        facts = orch.rescan_facts(lr["kind"], lr["baseline"], S.last_scan.findings, S.rescan_new, lr["resolved"])
        S.ai_rescan = orch.summarize(client, "rescan", facts)
        return "rescan interpretation produced"

    _ai_run("ai_rescan_interpretation", "post-deployment", run)


def decide(prefix: str, item, decision: str) -> None:
    sc = SCOPES[prefix]
    try:
        remediation.record_decision(S[sc["decisions"]], S.audit, item, decision,
                                    S.get(f"{prefix}_approver", ""), scope=sc["label"])
        S[f"{prefix}_err"] = ""
    except ValueError as exc:
        S[f"{prefix}_err"] = str(exc)


def rescan(kind: str) -> None:
    scan = run_scans(S.live_files, list(S.project.binary_files), S.mode)
    new, resolved = monitor.record_scan(S.history, kind, scan, S.baseline)
    S.rescan_new, S.last_scan = new, scan
    S.last_rescan = {"kind": kind, "baseline": len(S.baseline or ()), "current": len(scan.findings),
                     "new": len(new), "resolved": len(resolved)}
    S.plan5 = remediation.plan_remediations(S.live_files, new)
    remediation.audit_event(S.audit, "system", "rescan", "post-deployment",
                            detail=f"{kind}: {len(new)} new, {len(resolved)} resolved")


def simulate_drift() -> None:
    S.live_files = monitor.simulate_drift(S.live_files)
    S.sim_paths = set(S.sim_paths) | {monitor.DRIFT_PATH}
    remediation.audit_event(S.audit, "system", "drift_simulated", "post-deployment",
                            detail="SIMULATION: test vulnerabilities injected into the in-memory copy")
    rescan("rescan after simulated drift")


def sync_corrected() -> int:
    """Make the canonical corrected project (download and publish source) match the live copy.

    Simulated drift files are excluded: they are demo artefacts and must never be exported.
    Returns how many real files changed.
    """
    new = {p: c for p, c in S.live_files.items() if p not in S.sim_paths}
    changed = sum(1 for p, c in new.items() if S.corrected.get(p) != c)
    S.corrected = new
    S.zip_bytes = export.build_zip(new, S.project.binary_files)
    S.residual = None
    return changed


def apply_fixes(prefix: str) -> None:
    sc = SCOPES[prefix]
    if prefix == "p2":
        base, plan = S.project.text_files, S.plan
    else:
        base, plan = S.live_files, S.plan5
    result = remediation.apply_and_audit(base, plan, S[sc["decisions"]], S.audit, S[sc["logged"]], sc["label"])
    S[sc["apply"]] = result
    if prefix == "p2":
        S.corrected = result.files
        S.zip_bytes = export.build_zip(result.files, S.project.binary_files)
        S.residual = None
        S.deployment, S.live_files, S.baseline, S.history = None, None, None, []
        S.rescan_new, S.plan5, S.decisions5, S.apply5 = [], [], {}, None
        S.last_scan, S.last_rescan = None, None
        S.sim_paths = set()
    else:
        S.live_files = result.files
        exported = sync_corrected()
        for r in plan:
            if r.path in S.sim_paths and result.statuses.get(r.finding_id) == "applied":
                result.statuses[r.finding_id] = "applied_simulated"
                remediation.audit_event(S.audit, "system", "simulated_fix_not_exported", "post-deployment",
                                        finding_id=r.finding_id, path=r.path,
                                        detail="Applied to a simulated drift file only; not part of the exported project")
        if exported:
            remediation.audit_event(S.audit, "system", "export_updated", "post-deployment",
                                    detail=f"Corrected project updated: {exported} file(s) changed after deployment")
        rescan("post-remediation rescan")


def deploy_now() -> None:
    residual = residual_scan()
    try:
        record = deploy.simulate_deployment(
            S.project.name, S.corrected, S.project.binary_files, residual.findings,
            pending_count(), bool(S.get("deploy_ack", False)),
        )
    except ValueError as exc:
        S.deploy_err = str(exc)
        return
    S.deploy_err = ""
    S.deployment = record
    S.live_files = dict(S.corrected)
    S.sim_paths = set()
    S.baseline = {monitor.fingerprint(f) for f in residual.findings}
    S.history = []
    monitor.record_scan(S.history, "deployment baseline", residual, None)
    S.rescan_new, S.plan5, S.decisions5, S.apply5 = [], [], {}, None
    S.last_scan, S.last_rescan = residual, None
    remediation.audit_event(S.audit, "system", "deployment_simulated", "deployment",
                            detail=f"SIMULATION only; package sha256 {record.digest[:16]}")

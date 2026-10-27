"""Stage views 6 and 7: Deployment simulation and On-demand rescan."""
from __future__ import annotations

import os

import streamlit as st

from devsecops_agent import deploy, export
from devsecops_agent.scanners import redact

from . import components as C
from .state import S, deploy_now, goto, pending_count, rescan, residual_scan, simulate_drift
from .ai_panel import render_ai_rescan
from .views_remediate import render_queue

LANGS = {".py": "python", ".js": "javascript", ".ts": "typescript", ".json": "json", ".yml": "yaml",
         ".yaml": "yaml", ".md": "markdown", ".sh": "bash", ".html": "html", ".css": "css"}


def view_deploy() -> None:
    C.hero("Deployment (Simulation)",
           "Review the remediated project and run a clearly labelled deployment simulation. Nothing is deployed.",
           "rocket", "STAGE 06")
    C.banner("SIMULATION: no application is built, deployed or hosted by this tool. Only the policy gate, package digest "
             "and security scan are computed; build, release and health check are simulated and labelled.")
    if S.corrected is None:
        C.empty_state("rocket", "Nothing to deploy yet", "Apply fixes in the Remediation stage first.")
        return
    statuses = S.apply_result.statuses
    residual = residual_scan()
    hc = sum(1 for f in residual.findings if f.severity in ("critical", "high"))
    pending = pending_count()
    C.kpi_grid([
        ("Files changed", len(export.changed_files(S.project.text_files, S.corrected)), "", "#22d3ee", "file"),
        ("Fixes applied", sum(1 for v in statuses.values() if v == "applied"), "", "#34d399", "shield-check"),
        ("Awaiting approval", pending, "blocks deployment", "#ffd23f", "lock"),
        ("Rejected", sum(1 for v in statuses.values() if v == "rejected"), "", "#ff3b6b", "x"),
        ("Open high/critical", hc, "in corrected code", "#ff8a3d", "alert"),
    ])
    with st.container(border=True):
        C.section("Deployment gate", "Backend policy: pending approvals block; residual high/critical risk needs acknowledgement.", "lock")
        if hc:
            st.checkbox("I acknowledge the residual high/critical risk and want to continue", key="deploy_ack")
        ack = bool(S.get("deploy_ack", False))
        reasons = deploy.gate(pending, hc, ack)
        C.checklist([
            ("ok" if not pending else "warn", "No change is awaiting a human approval decision"),
            ("ok" if (not hc or ack) else "warn", "No unacknowledged high/critical finding remains in the corrected code"),
        ])
        st.button("Run deployment simulation", on_click=deploy_now, disabled=bool(reasons), key="btn_deploy",
                  icon=":material/rocket_launch:", type="primary")
        if S.deploy_err:
            st.error(S.deploy_err)
    rec = S.deployment
    with st.container(border=True):
        C.section("Pipeline", "Computed steps run for real on your files; simulated steps do nothing.", "activity")
        C.md(C.stepper(rec.steps if rec else None))
        if rec:
            C.banner(f"SIMULATED deployment recorded at {rec.finished_at}. Real deployment: {rec.real_deployment}. "
                     f"URL: none. Package sha256 {rec.digest[:24]}...")
    with st.container(border=True):
        C.section("Corrected code", "Changed files are listed first.", "terminal")
        paths = sorted(export.changed_files(S.project.text_files, S.corrected)) or sorted(S.corrected)[:50]
        if paths:
            choice = st.selectbox("Corrected file", paths, key="view_file", label_visibility="collapsed")
            body = redact("\n".join(S.corrected[choice].split("\n")[:400]))
            st.code(body, language=LANGS.get(os.path.splitext(choice)[1].lower()))
    if rec:
        st.button("Continue to rescan", on_click=goto, args=(7,), key="cta_6", icon=":material/arrow_forward:", type="primary")


def view_rescan() -> None:
    C.hero("On-Demand Rescan",
           "Analyze the deployed copy again, compare it with the deployment baseline, and handle new findings under the same approval rules.",
           "refresh", "STAGE 07")
    if S.deployment is None:
        C.empty_state("refresh", "No baseline yet", "Run the deployment simulation first; its scan becomes the comparison baseline.")
        return
    last = S.history[-1]
    lr = S.last_rescan or {}
    C.kpi_grid([
        ("Last scan (UTC)", last.ts.replace("T", " ")[11:19], last.kind, "#22d3ee", "clock"),
        ("Status", last.status, "", "#8b5cf6", "activity"),
        ("Baseline findings", len(S.baseline or ()), "at deployment", "#5aa9ff", "layers"),
        ("Current findings", len(S.last_scan.findings) if S.last_scan else "-", "", "#ffd23f", "bug"),
        ("New", lr.get("new", 0), "since baseline", "#ff3b6b", "alert"),
        ("Resolved", lr.get("resolved", 0), "since baseline", "#34d399", "check-circle"),
    ])
    with st.container(border=True):
        C.section("Scan controls", "On-demand only. This is not continuous monitoring.", "radar")
        b1, b2 = st.columns(2)
        b1.button("Rescan now (on-demand)", on_click=rescan, args=("on-demand rescan",), key="btn_rescan",
                  icon=":material/refresh:", type="primary")
        b2.button("Simulate drift (inject test vulnerabilities)", on_click=simulate_drift, key="btn_drift",
                  icon=":material/science:")
        st.caption("The drift button is a SIMULATION: it adds a fake vulnerable file to the in-memory copy to demonstrate "
                   "detection. New high or critical findings are never fixed without a named human approval.")
    with st.container(border=True):
        C.section("New findings", "Findings that were not present at the deployment baseline.", "alert")
        if S.rescan_new:
            fixable = {r.finding_id for r in S.plan5}
            statuses = S.apply5.statuses if S.apply5 else {}
            st.dataframe([
                {"severity": f.severity, "rule": f.rule_id, "location": f"{f.path}:{f.line}", "evidence": f.evidence,
                 "status": statuses.get(f.id) or ("fix proposed" if f.id in fixable else "manual remediation required")}
                for f in S.rescan_new
            ], hide_index=True)
        elif S.last_rescan:
            C.checklist([("ok", "No new findings compared with the deployment baseline.")])
        else:
            C.empty_state("radar", "No rescan yet", "Press Rescan now to compare the current copy with the baseline.")
    if S.rescan_new:
        render_queue("p5", S.plan5)
    render_ai_rescan()
    with st.container(border=True):
        C.section("Remaining risks", "Everything the latest scan still reports, including baseline findings.", "bug")
        remaining = S.last_scan.findings if S.last_scan else []
        if remaining:
            st.dataframe([{"severity": f.severity, "rule": f.rule_id, "location": f"{f.path}:{f.line}", "evidence": f.evidence}
                          for f in remaining[:100]], hide_index=True)
        else:
            C.checklist([("ok", "The latest scan reports no findings (this does not prove the code is secure).")])
    with st.container(border=True):
        C.section("Scan history", "Every scan since deployment.", "clock")
        from dataclasses import asdict
        st.dataframe([asdict(r) for r in S.history], hide_index=True)
        C.section("Audit trail", "All decisions and actions, newest first.", "list")
        C.md(C.timeline(S.audit))
    st.caption("Scheduled scans: the GitLab CI self-scan job can run on a pipeline schedule, but it scans this tool's own "
               "repository, not your deployed application. Continuous monitoring is not implemented.")

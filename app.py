"""DevSecOps LXNORO AI Agent: Streamlit UI wiring all seven stages together.

Real: ZIP/GitHub intake, static scanning, report, approval-gated remediation, ZIP export,
on-demand rescan. Optional/unverified: AI explanations, GitHub publishing (need secrets).
Simulated: deployment and the drift demo button. Nothing here executes uploaded code.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
from dataclasses import asdict
from datetime import datetime, timezone

import streamlit as st

from devsecops_agent import ai as ai_mod
from devsecops_agent import deploy, export, github_io, intake, monitor, remediation
from devsecops_agent import report as report_mod
from devsecops_agent.models import Check, count_by_severity
from devsecops_agent.safe_zip import UnsafeArchiveError
from devsecops_agent.scanners import scan_project

st.set_page_config(page_title="DevSecOps LXNORO AI Agent", page_icon="🛡️", layout="wide")
S = st.session_state

CSS = """
<style>
:root { --lx-green:#1a8f45; --lx-panel:#0b100b; --lx-border:rgba(26,143,69,.45); --lx-muted:#9fb0a2; }
.stApp { background:#050705; color:#ffffff; }
.block-container { padding-top:1.1rem; max-width:1250px; }
.lx-brand { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:1.7rem; font-weight:700; letter-spacing:.04em; color:#ffffff; }
.lx-brand b { color:var(--lx-green); }
.lx-sub { color:var(--lx-muted); font-size:.85rem; margin-bottom:.4rem; }
.lx-chip { display:inline-block; padding:.15rem .6rem; margin:.15rem .3rem .15rem 0; border:1px solid var(--lx-border); border-radius:4px; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.74rem; color:#ffffff; background:#0a0f0a; }
.lx-chip.ok { border-color:var(--lx-green); }
.lx-chip.ok::before { content:'\25CF  '; color:var(--lx-green); }
.lx-chip.off::before { content:'\25CB  '; color:#7d8a7f; }
.lx-chip.sim { border-color:#8a6d00; }
.lx-chip.sim::before { content:'\25C6  '; color:#c99a00; }
.lx-steps { display:flex; flex-wrap:wrap; gap:.35rem; margin:.5rem 0 1rem 0; }
.lx-step { border:1px solid var(--lx-border); border-radius:4px; padding:.25rem .6rem; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.75rem; color:var(--lx-muted); background:#080c08; }
.lx-step b { color:var(--lx-muted); margin-right:.3rem; }
.lx-step.done { color:#ffffff; border-color:var(--lx-green); background:#0c1b10; }
.lx-step.done b { color:var(--lx-green); }
.lx-panel-head { display:flex; align-items:center; gap:.7rem; border-bottom:1px solid var(--lx-border); padding-bottom:.45rem; margin-bottom:.4rem; }
.lx-panel-num { font-family:ui-monospace,Menlo,Consolas,monospace; color:var(--lx-green); font-weight:700; }
.lx-panel-title { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:1.1rem; letter-spacing:.06em; text-transform:uppercase; color:#ffffff; }
.lx-panel-desc { color:var(--lx-muted); font-size:.85rem; margin-bottom:.6rem; }
.lx-sim-banner { border:1px solid #8a6d00; background:#161200; color:#f3dc8c; padding:.5rem .8rem; border-radius:4px; font-size:.85rem; margin:.4rem 0 .6rem 0; }
.lx-foot { color:var(--lx-muted); font-size:.75rem; margin-top:1rem; }
div[data-testid='stVerticalBlockBorderWrapper'] { background:var(--lx-panel); border-color:var(--lx-border) !important; }
.stButton > button, .stDownloadButton > button { background:#0f2415; color:#ffffff; border:1px solid var(--lx-green); border-radius:4px; }
.stButton > button:hover, .stDownloadButton > button:hover { background:#153220; border-color:#2fbf64; color:#ffffff; }
.stButton > button:disabled, .stDownloadButton > button:disabled { opacity:.4; }
</style>
"""

SCOPES = {
    "p2": {"decisions": "decisions", "logged": "logged", "apply": "apply_result", "label": "analysis"},
    "p5": {"decisions": "decisions5", "logged": "logged5", "apply": "apply5", "label": "post-deployment"},
}
STAGES = ["Intake", "Analysis", "Report", "Remediation", "Export", "Deploy (simulated)", "Rescan (on-demand)"]
LANGS = {".py": "python", ".js": "javascript", ".ts": "typescript", ".json": "json",
         ".yml": "yaml", ".yaml": "yaml", ".md": "markdown", ".sh": "bash", ".html": "html", ".css": "css"}


# ---------------------------------------------------------------- helpers

def esc(value) -> str:
    return html.escape(str(value))


def safe_label(text, limit: int = 70) -> str:
    """Strip markdown/HTML-significant characters from untrusted names used in labels."""
    return re.sub(r"[^\w\s./:\-]", "_", str(text))[:limit]


def chip(text: str, kind: str = "off") -> str:
    return f'<span class="lx-chip {kind}">{esc(text)}</span>'


def panel_header(num: str, icon: str, title: str, desc: str) -> None:
    st.markdown(
        f'<div class="lx-panel-head"><span class="lx-panel-num">{esc(icon)} {esc(num)}</span>'
        f'<span class="lx-panel-title">{esc(title)}</span></div>'
        f'<div class="lx-panel-desc">{esc(desc)}</div>',
        unsafe_allow_html=True,
    )


def cfg_get(key: str):
    try:
        value = st.secrets.get(key)
    except Exception:
        value = None
    return (str(value) if value else None) or os.environ.get(key)


def _defaults() -> dict:
    return {
        "project": None, "scan": None, "ai": None, "plan": [], "decisions": {}, "logged": set(),
        "apply_result": None, "corrected": None, "zip_bytes": None, "residual": None,
        "deployment": None, "deploy_err": "", "live_files": None, "baseline": None, "history": [],
        "rescan_new": [], "plan5": [], "decisions5": {}, "logged5": set(), "apply5": None,
        "gh_access": None, "gh_result": None, "audit": [],
    }


def init_state() -> None:
    for key, value in _defaults().items():
        if key not in S:
            S[key] = value
    if "branch_default" not in S:
        S["branch_default"] = "lxnoro-agent/fixes-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def reset_workflow() -> None:
    for key, value in _defaults().items():
        S[key] = value


def lang_for(path: str):
    return LANGS.get(os.path.splitext(path)[1].lower())


def current_report() -> dict:
    statuses = S.apply_result.statuses if S.apply_result else {}
    notes = S.ai.notes if S.ai else {}
    label = S.ai.label if S.ai else ""
    return report_mod.build_report(S.project.name, S.scan, notes, label, statuses)


def residual_scan():
    if S.residual is None:
        S.residual = scan_project(S.corrected, list(S.project.binary_files))
    return S.residual


def pending_count() -> int:
    statuses = S.apply_result.statuses if S.apply_result else {}
    return sum(
        1 for r in S.plan
        if r.needs_approval and statuses.get(r.finding_id, "pending_approval") == "pending_approval"
    )


# ---------------------------------------------------------------- callbacks

def _decide(prefix: str, item, decision: str) -> None:
    sc = SCOPES[prefix]
    try:
        remediation.record_decision(S[sc["decisions"]], S.audit, item, decision,
                                    S.get(f"{prefix}_approver", ""), scope=sc["label"])
        S[f"{prefix}_err"] = ""
    except ValueError as exc:
        S[f"{prefix}_err"] = str(exc)


def _rescan(kind: str) -> None:
    scan = scan_project(S.live_files, list(S.project.binary_files))
    new, resolved = monitor.record_scan(S.history, kind, scan, S.baseline)
    S.rescan_new = new
    S.plan5 = remediation.plan_remediations(S.live_files, new)
    remediation.audit_event(S.audit, "system", "rescan", "post-deployment",
                            detail=f"{kind}: {len(new)} new, {len(resolved)} resolved")


def _simulate_drift() -> None:
    S.live_files = monitor.simulate_drift(S.live_files)
    remediation.audit_event(S.audit, "system", "drift_simulated", "post-deployment",
                            detail="SIMULATION: test vulnerabilities injected into the in-memory copy")
    _rescan("rescan after simulated drift")


def _apply(prefix: str) -> None:
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
    else:
        S.live_files = result.files
        _rescan("post-remediation rescan")


def _deploy_now() -> None:
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
    S.baseline = {monitor.fingerprint(f) for f in residual.findings}
    S.history = []
    monitor.record_scan(S.history, "deployment baseline", residual, None)
    S.rescan_new, S.plan5, S.decisions5, S.apply5 = [], [], {}, None
    remediation.audit_event(S.audit, "system", "deployment_simulated", "deployment",
                            detail=f"SIMULATION only; package sha256 {record.digest[:16]}")


def load_project(loader, label: str) -> None:
    with st.status(f"Importing via {label} (validating; nothing is executed)...", expanded=True) as status:
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


def run_analysis(use_ai: bool, ai_cfg) -> None:
    bar = st.progress(5, text="Running deterministic checks (static; nothing is executed)...")
    scan = scan_project(S.project.text_files, list(S.project.binary_files))
    bar.progress(55, text="Deterministic checks complete.")
    ai_res = None
    if use_ai and ai_cfg:
        def tick(i, n):
            bar.progress(55 + int(40 * i / max(n, 1)), text=f"AI explanations {i}/{n}...")

        ai_res = ai_mod.explain_findings(ai_cfg, scan.findings, progress=tick)
        detail = f"{len(ai_res.notes)} of {ai_res.attempted} explanation(s) from {ai_res.label}"
        if ai_res.failed:
            detail += f"; {ai_res.failed} failed ({', '.join(sorted(set(ai_res.errors)))})"
        scan.checks.append(Check("AI-assisted explanations", "performed" if ai_res.ok else "unavailable", detail))
    else:
        scan.checks.append(Check("AI-assisted explanations", "unavailable",
                                 "Not enabled or no provider configured; deterministic results only."))
    S.scan, S.ai = scan, ai_res
    S.plan = remediation.plan_remediations(S.project.text_files, scan.findings)
    S.decisions, S.logged, S.apply_result = {}, set(), None
    S.corrected, S.zip_bytes, S.residual = None, None, None
    S.deployment, S.live_files, S.baseline, S.history = None, None, None, []
    remediation.audit_event(S.audit, "system", "analysis_completed", "analysis",
                            detail=f"{len(scan.findings)} finding(s); AI explanations: {'yes' if ai_res and ai_res.ok else 'no'}")
    bar.progress(100, text="Analysis complete.")


# ---------------------------------------------------------------- shared widgets

def render_queue(prefix: str, plan: list, base_files: dict) -> None:
    sc = SCOPES[prefix]
    if not plan:
        st.info("No deterministic fixes are available for the current findings. Remaining findings need manual remediation (see the plan).")
        return
    decisions = S[sc["decisions"]]
    result = S[sc["apply"]]
    statuses = result.statuses if result else {}
    st.text_input("Approver name (required to approve or reject high-risk changes)", key=f"{prefix}_approver", max_chars=80)
    for r in plan:
        digest = hashlib.sha256(r.finding_id.encode("utf-8")).hexdigest()[:10]
        d = decisions.get(r.finding_id)
        state = statuses.get(r.finding_id) or (d.decision if d else ("awaiting approval" if r.needs_approval else "ready (auto)"))
        tag = "HUMAN APPROVAL REQUIRED" if r.needs_approval else "AUTO-ELIGIBLE (low risk)"
        with st.expander(f"{r.severity.upper()} | {tag} | {safe_label(r.path)}:{r.line} | {state}"):
            st.markdown(f"**Proposed change:** {r.description}  \nFix risk: `{r.fix_risk}`")
            st.code(r.diff or "(no diff)", language="diff")
            if r.needs_approval:
                c1, c2 = st.columns(2)
                c1.button("Approve", key=f"{prefix}_ok_{digest}", on_click=_decide, args=(prefix, r, "approved"), icon=":material/check:")
                c2.button("Reject", key=f"{prefix}_no_{digest}", on_click=_decide, args=(prefix, r, "rejected"), icon=":material/close:")
                if d:
                    st.caption(f"Decision: {d.decision} by {d.approver} at {d.ts}")
    if S.get(f"{prefix}_err"):
        st.warning(S[f"{prefix}_err"])
    st.button("Apply low-risk fixes and approved changes", key=f"{prefix}_apply", on_click=_apply, args=(prefix,),
              icon=":material/build:", type="primary")
    if result:
        counts = {}
        for v in statuses.values():
            counts[v] = counts.get(v, 0) + 1
        st.caption("Last apply: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) +
                   ". High/critical changes without an approval stay unapplied.")


def render_audit() -> None:
    st.markdown("**Audit trail** (decisions and remediation actions, UTC)")
    if S.audit:
        st.dataframe(S.audit, hide_index=True)
    else:
        st.caption("No events recorded yet.")


# ---------------------------------------------------------------- page sections

def render_header() -> None:
    ai_cfg = ai_mod.load_config(cfg_get)
    pub = github_io.load_publish_config(cfg_get)
    st.markdown('<div class="lx-brand">DevSecOps <b>LXNORO</b> AI Agent</div>'
                '<div class="lx-sub">Static security analysis, approval-gated remediation, export and rescan. Uploaded code is never executed.</div>',
                unsafe_allow_html=True)
    chips = [
        chip("AI explanations: configured", "ok") if ai_cfg else chip("AI explanations: not configured (deterministic only)", "off"),
        chip("GitHub publishing: enabled", "ok") if pub else chip("GitHub publishing: disabled", "off"),
        chip("Deployment: SIMULATION only", "sim"),
        chip("Monitoring: on-demand rescan", "sim"),
    ]
    st.markdown("".join(chips), unsafe_allow_html=True)
    done = [S.project is not None, S.scan is not None, S.scan is not None, S.apply_result is not None,
            S.zip_bytes is not None, S.deployment is not None, len(S.history) > 1]
    steps = "".join(
        f'<span class="lx-step {"done" if d else "todo"}"><b>{i}</b>{esc(name)}</span>'
        for i, (name, d) in enumerate(zip(STAGES, done), start=1)
    )
    st.markdown(f'<div class="lx-steps">{steps}</div>', unsafe_allow_html=True)


def render_intake() -> None:
    with st.container(border=True):
        panel_header("01", "◧", "Project Intake",
                     "Upload a source-code ZIP or import a public GitHub repository. Content is validated and never executed.")
        tab_zip, tab_gh = st.tabs(["ZIP upload", "GitHub import"])
        with tab_zip:
            up = st.file_uploader("Drag and drop a source-code ZIP here (max 25 MB)", type=["zip"], key="zip_upload")
            if st.button("Validate and load ZIP", icon=":material/verified_user:", disabled=up is None, key="btn_zip"):
                load_project(lambda: intake.load_zip(up.name, up.getvalue()), "ZIP upload")
        with tab_gh:
            url = st.text_input("GitHub repository URL", placeholder="https://github.com/owner/repository", key="gh_url")
            st.caption("Public repositories only (unauthenticated GitHub API, so rate limits apply). The repository is downloaded as an archive, never cloned or executed.")
            if st.button("Import repository", icon=":material/cloud_download:", disabled=not url.strip(), key="btn_gh"):
                load_project(lambda: intake.load_github(url), "GitHub")
        p = S.project
        if p:
            st.markdown(f"**Selected project:** `{p.name}` &nbsp;|&nbsp; source: {esc(p.source)}", unsafe_allow_html=True)
            c1, c2, c3 = st.columns(3)
            c1.metric("Text files (analyzed)", len(p.text_files))
            c2.metric("Binary files (kept, not analyzed)", len(p.binary_files))
            c3.metric("Entries skipped", len(p.skipped))
            if p.skipped:
                with st.expander("Skipped entries (excluded from analysis and from the corrected ZIP)"):
                    st.dataframe([{"path": s.path, "reason": s.reason} for s in p.skipped], hide_index=True)
        else:
            st.info("No project loaded yet.")


def render_analysis() -> None:
    with st.container(border=True):
        panel_header("02", "◈", "AI Security Analysis, Reports and Approval",
                     "Deterministic scanner results are authoritative. Optional AI text is advisory and labelled separately.")
        if not S.project:
            st.info("Load a project in Panel 01 first.")
            return
        ai_cfg = ai_mod.load_config(cfg_get)
        use_ai = st.checkbox("Add AI-generated explanations", value=False, disabled=ai_cfg is None, key="use_ai",
                             help="Sends only rule titles, locations and redacted evidence to the configured provider.")
        if ai_cfg is None:
            st.caption("AI provider not configured (set AI_PROVIDER, AI_API_KEY and AI_MODEL as Streamlit secrets). Deterministic analysis works without it.")
        if st.button("Run security analysis", icon=":material/radar:", type="primary", key="btn_scan"):
            run_analysis(bool(use_ai and ai_cfg), ai_cfg)
        scan = S.scan
        if not scan:
            return
        rep = current_report()
        counts = rep["summary"]["counts"]
        cols = st.columns(6)
        cols[0].metric("Risk level", rep["summary"]["risk_level"])
        cols[1].metric("Findings", rep["summary"]["total"])
        for col, sev in zip(cols[2:], ("critical", "high", "medium", "low")):
            col.metric(sev.capitalize(), counts[sev])
        with st.expander("Checks: completed vs unavailable", expanded=True):
            for c in scan.checks:
                mark = {"performed": "●", "unavailable": "○", "skipped": "○"}.get(c.status, "○")
                st.markdown(f"{mark} **{c.name}**: `{c.status}` {c.detail}")
        t_find, t_sw, t_plan, t_appr, t_rep = st.tabs(
            ["Findings", "Strengths and weaknesses", "Remediation plan", "Approvals and audit", "Report"])
        with t_find:
            if not scan.findings:
                st.success("No findings from the checks that were performed (this does not prove the code is secure).")
            for f in scan.findings[:100]:
                with st.expander(f"{f.severity.upper()} | {safe_label(f.title)} | {safe_label(f.path)}:{f.line}"):
                    st.caption(f"Deterministic rule {f.rule_id}")
                    st.code(f.evidence or "(none)", language=None)
                    st.markdown(f"**Explanation:** {f.explanation}\n\n**Impact:** {f.impact}\n\n**Remediation:** {f.remediation}")
                    note = S.ai.notes.get(f.id) if S.ai else None
                    if note:
                        st.caption(f"AI-generated explanation ({S.ai.label}): advisory, not a scanner result")
                        st.text(note)
            if len(scan.findings) > 100:
                st.caption(f"Showing the first 100 of {len(scan.findings)} findings; the report contains all of them.")
        with t_sw:
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Strengths**")
                for x in rep["strengths"] or ["None identified by the checks performed"]:
                    st.markdown(f"- {x}")
            with c2:
                st.markdown("**Weaknesses**")
                for x in rep["weaknesses"] or ["None identified by the checks performed"]:
                    st.markdown(f"- {x}")
        with t_plan:
            if rep["remediation_plan"]:
                st.dataframe(rep["remediation_plan"], hide_index=True)
            else:
                st.caption("Nothing to remediate.")
        with t_appr:
            render_queue("p2", S.plan, S.project.text_files)
            render_audit()
        with t_rep:
            name = safe_label(S.project.name, 40).replace("/", "-")
            c1, c2, c3 = st.columns(3)
            c1.download_button("Report (JSON)", json.dumps(rep, indent=2), file_name=f"{name}-report.json", mime="application/json", key="dl_json")
            c2.download_button("Report (Markdown)", report_mod.report_markdown(rep), file_name=f"{name}-report.md", mime="text/markdown", key="dl_md")
            c3.download_button("GitLab Duo hand-off brief", report_mod.duo_handoff(rep), file_name=f"{name}-duo-handoff.md", mime="text/markdown", key="dl_duo")
            st.caption("The hand-off brief is text you can paste into a GitLab Duo flow yourself; this app does not call GitLab Duo.")
            st.caption("Evidence in reports is redacted. Reports and findings are not stored on the server beyond this browser session.")


def render_outputs() -> None:
    with st.container(border=True):
        panel_header("03", "▣", "Outputs and GitHub Publishing",
                     "Download the corrected project, review the diff, and optionally publish a new branch and pull request.")
        if S.corrected is None:
            st.info("Run the analysis and press 'Apply low-risk fixes and approved changes' in Panel 02 first.")
            st.download_button("Download corrected project (ZIP)", b"", disabled=True, key="dl_zip_off")
            return
        changed = export.changed_files(S.project.text_files, S.corrected)
        st.download_button("Download corrected project (ZIP)", S.zip_bytes, file_name=f"{safe_label(S.project.name, 40).replace('/', '-')}-corrected.zip",
                           mime="application/zip", icon=":material/download:", key="dl_zip")
        st.caption(f"{len(changed)} file(s) changed. Entries skipped at intake (symlinks, oversize, VCS/dependency folders) are not in the ZIP.")
        diffs = export.diff_summary(S.project.text_files, S.corrected)
        with st.expander(f"Review changes before publishing ({len(diffs)} file(s))", expanded=bool(diffs)):
            if not diffs:
                st.caption("No files changed yet.")
            for path, diff in diffs:
                st.markdown(f"`{safe_label(path, 120)}`")
                st.code(diff, language="diff")
        st.markdown("**GitHub publishing (new branch + pull request only)**")
        pub = github_io.load_publish_config(cfg_get)
        missing = github_io.publish_blockers(cfg_get)
        if missing:
            st.warning("Publishing is disabled. Missing settings: " + ", ".join(missing) + ". Configure them as Streamlit secrets; never put them in source control.")
        else:
            st.success(f"Publishing is configured for {pub.repo}. Access has not been verified yet." if not S.gh_access else f"Publishing is configured for {pub.repo}.")
        if st.button("Verify GitHub access", disabled=pub is None, icon=":material/lock_open:", key="gh_verify") and pub:
            S.gh_access = github_io.verify_access(pub.token, pub.repo)
        access = S.gh_access
        if access:
            (st.success if access.ok and access.can_push else st.error)(access.message)
        ready = bool(pub and access and access.ok and access.can_push and changed)
        if pub and access and access.ok and access.can_push:
            st.text_input("Base branch", value=access.default_branch, key="gh_base")
            st.text_input("New branch (the default branch is refused)", value=S.branch_default, key="gh_branch")
            key = st.text_input("Publish key", type="password", key="gh_key")
            confirm = st.checkbox(f"I approve creating this branch and a pull request in {pub.repo}", key="gh_confirm")
            if not changed:
                st.caption("There are no changed files to publish.")
            if st.button("Publish branch and pull request", disabled=not (ready and key and confirm), icon=":material/publish:", key="gh_publish"):
                if not github_io.key_matches(pub, key):
                    st.error("Publish key is incorrect.")
                else:
                    with st.status("Publishing to GitHub...", expanded=True) as status:
                        try:
                            res = github_io.publish_changes(
                                pub.token, pub.repo, S.gh_base, S.gh_branch, changed,
                                "Security remediation by DevSecOps LXNORO AI Agent",
                                "Security remediation by DevSecOps LXNORO AI Agent",
                                "Automated remediation. Low-risk fixes were applied automatically; high-risk changes only after named human approval (see audit trail). Review before merging.\n\nChanged files:\n" + "\n".join(f"- {p}" for p in sorted(changed)),
                            )
                            S.gh_result = res
                            remediation.audit_event(S.audit, "human:publisher", "github_pr_created", "export",
                                                    detail=f"{res.repo} branch {res.branch} commit {res.commit_sha[:8]}")
                            status.update(label="Pull request created", state="complete")
                        except github_io.GitHubError as exc:
                            status.update(label="Publishing failed", state="error")
                            st.error(str(exc))
        elif pub:
            st.caption("Verify access to unlock the publishing form.")
        res = S.gh_result
        if res:
            st.success(f"Published to {res.repo}: branch `{res.branch}`, commit `{res.commit_sha[:8]}`.")
            if res.pr_url:
                st.markdown(f"Pull request: [{res.pr_url}]({res.pr_url})")


def render_deployment() -> None:
    with st.container(border=True):
        panel_header("04", "▶", "Secure Deployment and Corrected Code",
                     "Review the remediated project and run a clearly labelled deployment simulation.")
        if S.corrected is None:
            st.info("Apply fixes in Panel 02 first.")
            return
        statuses = S.apply_result.statuses
        residual = residual_scan()
        hc = sum(1 for f in residual.findings if f.severity in ("critical", "high"))
        pending = pending_count()
        c = st.columns(5)
        c[0].metric("Files changed", len(export.changed_files(S.project.text_files, S.corrected)))
        c[1].metric("Fixes applied", sum(1 for v in statuses.values() if v == "applied"))
        c[2].metric("Awaiting approval", pending)
        c[3].metric("Rejected", sum(1 for v in statuses.values() if v == "rejected"))
        c[4].metric("Open high/critical", hc)
        st.markdown('<div class="lx-sim-banner">SIMULATION: no application is built, deployed or hosted by this tool. Only the policy gate, package digest and scan are computed.</div>', unsafe_allow_html=True)
        if hc:
            st.checkbox("I acknowledge the residual high/critical risk and want to continue", key="deploy_ack")
        reasons = deploy.gate(pending, hc, bool(S.get("deploy_ack", False)))
        for reason in reasons:
            st.warning(reason)
        st.button("Run deployment simulation", on_click=_deploy_now, disabled=bool(reasons), icon=":material/rocket_launch:", key="btn_deploy")
        if S.deploy_err:
            st.error(S.deploy_err)
        rec = S.deployment
        if rec:
            st.markdown(f'<div class="lx-sim-banner">SIMULATED deployment recorded at {esc(rec.finished_at)}. Real deployment: {esc(rec.real_deployment)}. URL: none.</div>', unsafe_allow_html=True)
            st.dataframe(rec.steps, hide_index=True)
            st.caption(f"Package sha256: {rec.digest}")
        paths = sorted(export.changed_files(S.project.text_files, S.corrected)) or sorted(S.corrected)[:50]
        if paths:
            choice = st.selectbox("Corrected code viewer", paths, key="view_file")
            st.code("\n".join(S.corrected[choice].split("\n")[:400]), language=lang_for(choice))


def render_monitoring() -> None:
    with st.container(border=True):
        panel_header("05", "◉", "Post-Deployment Monitoring and Remediation",
                     "On-demand rescans of the remediated project. This is not continuous monitoring.")
        if S.deployment is None:
            st.info("Run the deployment simulation in Panel 04 first.")
            return
        last = S.history[-1]
        pending5 = sum(1 for r in S.plan5 if r.needs_approval and (S.apply5.statuses.get(r.finding_id) if S.apply5 else "pending_approval") in (None, "pending_approval"))
        c = st.columns(4)
        c[0].metric("Last scan (UTC)", last.ts.replace("T", " ")[:19])
        c[1].metric("Scan status", last.status)
        c[2].metric("New findings", len(S.rescan_new))
        c[3].metric("Awaiting approval", pending5)
        b1, b2 = st.columns(2)
        b1.button("Rescan now (on-demand)", on_click=_rescan, args=("on-demand rescan",), icon=":material/refresh:", key="btn_rescan")
        b2.button("Simulate drift (inject test vulnerabilities)", on_click=_simulate_drift, icon=":material/science:", key="btn_drift")
        st.caption("The drift button is a SIMULATION: it adds a fake vulnerable file to the in-memory copy to demonstrate detection. A new high or critical finding is never fixed without a named human approval.")
        if S.rescan_new:
            statuses = S.apply5.statuses if S.apply5 else {}
            fixable = {r.finding_id for r in S.plan5}
            rows = [{"severity": f.severity, "rule": f.rule_id, "location": f"{f.path}:{f.line}", "evidence": f.evidence,
                     "status": statuses.get(f.id) or ("fix proposed" if f.id in fixable else "manual remediation required")}
                    for f in S.rescan_new]
            st.markdown("**New findings since the deployment baseline**")
            st.dataframe(rows, hide_index=True)
            render_queue("p5", S.plan5, S.live_files)
        st.markdown("**Scan history**")
        st.dataframe([asdict(r) for r in S.history], hide_index=True)
        render_audit()
        st.caption("Scheduled scans: the GitLab CI `self-scan` job can run on a pipeline schedule, but it scans this tool's own repository, not your deployed application. Continuous monitoring is not implemented.")


def main() -> None:
    init_state()
    st.markdown(CSS, unsafe_allow_html=True)
    render_header()
    render_intake()
    render_analysis()
    render_outputs()
    render_deployment()
    render_monitoring()
    st.markdown('<div class="lx-foot">MIT License. Copyright (c) 2026 NOORA AL-MAOLAI. Research Center: LXNORO OJSC. Static analysis only: results are not a guarantee of security.</div>', unsafe_allow_html=True)


main()

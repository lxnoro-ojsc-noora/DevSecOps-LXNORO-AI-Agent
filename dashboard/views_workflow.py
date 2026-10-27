"""Stage views 1 to 3: Intake, Analysis and Report."""
from __future__ import annotations

import json

import streamlit as st

from devsecops_agent import ai as ai_mod
from devsecops_agent import intake
from devsecops_agent import report as report_mod
from devsecops_agent.models import SEVERITY_ORDER, count_by_severity

from . import components as C
from .icons import svg
from .ai_panel import ai_markdown, render_ai_panel, render_ai_report_section
from .state import (
    S, cfg_get, current_report, goto, gitlab_refresh, gitlab_submit, gitlab_test, load_demo, load_project,
    run_analysis, safe_name, gitlab_flow_enabled, gitlab_run_flow, gitlab_refresh_flow,
)


def view_intake() -> None:
    C.hero("Project Intake", "Bring in the code you want to secure. Everything is validated in memory and nothing is ever executed.",
           "upload", "STAGE 01")
    if S.mode == "simulation":
        with st.container(border=True):
            C.section("Simulated demo project",
                      "Built-in, deliberately insecure sample. Deterministic and repeatable; it is only read, never executed.", "flask")
            st.button("Load SIMULATED demo project", on_click=load_demo, key="btn_demo", icon=":material/science:",
                      type="primary")
    left, right = st.columns(2, gap="large")
    with left:
        with st.container(border=True):
            C.section("Upload a ZIP", "Drag and drop a source-code archive (max 25 MB).", "upload")
            up = st.file_uploader("Source-code ZIP", type=["zip"], key="zip_upload", label_visibility="collapsed")
            if st.button("Validate and load ZIP", icon=":material/verified_user:", disabled=up is None,
                         key="btn_zip", type="primary"):
                load_project(lambda: intake.load_zip(up.name, up.getvalue()), "ZIP upload")
    with right:
        with st.container(border=True):
            C.section("Import from GitHub", "Paste a public repository URL.", "github")
            url = st.text_input("Repository URL", placeholder="https://github.com/owner/repository",
                                key="gh_url", label_visibility="collapsed")
            if st.button("Import repository", icon=":material/cloud_download:", disabled=not url.strip(),
                         key="btn_gh", type="primary"):
                load_project(lambda: intake.load_github(url), "GitHub")
            st.caption("Public repositories only. The repository is downloaded as an archive (never cloned) through the "
                       "unauthenticated GitHub API, so rate limits apply.")
    p = S.project
    if p:
        with st.container(border=True):
            C.section("Project loaded", f"{p.name} - {p.source}", "folder")
            C.kpi_grid([
                ("Text files analyzed", len(p.text_files), "", "#22d3ee", "file"),
                ("Binary files kept", len(p.binary_files), "not analyzed", "#8b5cf6", "package"),
                ("Entries skipped", len(p.skipped), "excluded from ZIP", "#ffd23f", "alert"),
            ])
            if p.skipped:
                with st.expander("Skipped entries and reasons"):
                    st.dataframe([{"path": s.path, "reason": s.reason} for s in p.skipped], hide_index=True)
            st.button("Continue to security analysis", on_click=goto, args=(2,), key="cta_1",
                      icon=":material/arrow_forward:", type="primary")
    else:
        C.empty_state("folder", "No project loaded yet",
                      "Upload a ZIP or import a public repository to begin. The next stages unlock as you progress.")
    with st.container(border=True):
        C.section("Intake safeguards", "What happens to untrusted code before analysis.", "lock")
        C.checklist([
            ("ok", "Archives are read in memory only; nothing is written to disk."),
            ("ok", "Path traversal, absolute paths, symlinks, encrypted entries and ZIP bombs are rejected or skipped."),
            ("ok", "Size, entry-count and compression-ratio limits are enforced."),
            ("ok", "Uploaded code is never executed, imported or evaluated."),
            ("ok", "Secret-like values are redacted before display, reporting or any AI request."),
        ])


def _provider_grid(statuses, selected: str) -> str:
    icons = {"none": "shield", "external": "cpu", "gitlab": "link", "gitlab-chat": "lock"}
    tones = {"ready": ("ok", "READY"), "unconfigured": ("warn", "NOT CONFIGURED"), "unsupported": ("bad", "UNSUPPORTED")}
    cards = []
    for s in statuses:
        tone, label = tones.get(s.state, ("muted", s.state.upper()))
        missing = f'<div class="d">Missing: {C.esc(", ".join(s.missing))}</div>' if s.missing else ""
        mark = C.badge("Selected", "info", "check") if s.id == selected else ""
        cards.append(
            f'<div class="lx-check">{svg(icons.get(s.id, "info"), 20, C.TONES[tone])}<div>'
            f'<div class="n">{C.esc(s.label)}</div><div>{C.badge(label, tone)} {mark}</div>'
            f'<div class="d">{C.esc(s.detail)}</div>{missing}</div></div>'
        )
    return f'<div class="lx-checks">{"".join(cards)}</div>'


def _gitlab_card() -> None:
    with st.container(border=True):
        C.section("GitLab Duo Agent Platform triage",
                  "Asynchronous, read-only session that runs inside GitLab. Not a synchronous API.", "link")
        st.caption("Submits a redacted summary of the findings as a Flows API session (read-only privileges). It runs in "
                   "GitLab CI, uses your GitLab Duo quota, and its output appears in GitLab. Plan, permissions and "
                   "availability are enforced by GitLab and are only known after a request succeeds.")
        c1, c2 = st.columns(2)
        c1.button("Test GitLab access", on_click=gitlab_test, icon=":material/lock_open:", key="gl_test")
        c2.button("Submit read-only triage session", on_click=gitlab_submit, icon=":material/send:",
                  type="primary", key="gl_submit", disabled=S.scan is None)
        if S.gitlab_ok:
            st.success(S.gitlab_ok)
        if S.gitlab_msg:
            st.error(S.gitlab_msg)
        sess = S.gitlab_session
        if sess:
            link = f' - <a href="{C.esc(sess.web_url)}" target="_blank">open session in GitLab</a>' if sess.web_url else ""
            C.md(f'<div class="lx-q">{C.badge("Session " + str(sess.id), "info", "link")}'
                 f'{C.badge(sess.status or "status unknown", "warn")}<span class="loc">Submitted{link}</span></div>')
            st.button("Refresh status and output", on_click=gitlab_refresh, icon=":material/refresh:", key="gl_refresh")
            if S.gitlab_output:
                st.caption("Raw session output (advisory; experimental trace API, format not verified):")
                for chunk in S.gitlab_output:
                    st.text(chunk)


def _gitlab_flow_card() -> None:
    from devsecops_agent.scanners import redact

    cfg = ai_mod.load_gitlab_config(cfg_get)
    with st.container(border=True):
        C.section("GitLab Duo flow",
                  "Runs the flow already enabled in your GitLab project. No external model key is used.", "link")
        st.caption("The flow triages the CI security findings (the self-scan report) of a merge request in the configured "
                   "GitLab project and posts one comment, which this card reads back. It does not analyse the project you "
                   "uploaded here. It runs asynchronously in GitLab CI and uses your GitLab Duo quota.")
        st.text_input("Merge request number", value=cfg.mr_iid if cfg else "", key="gl_mr", max_chars=9,
                      placeholder="for example 2")
        c1, c2 = st.columns(2)
        c1.button("Test GitLab access", on_click=gitlab_test, icon=":material/lock_open:", key="gl_test")
        c2.button("Run the GitLab flow", on_click=gitlab_run_flow, icon=":material/play_arrow:", type="primary",
                  key="gl_run")
        if S.gitlab_ok:
            st.success(S.gitlab_ok)
        if S.gitlab_msg:
            st.error(S.gitlab_msg)
        sess = S.gitlab_session
        if sess and S.gitlab_kind == "flow":
            tone, label = ai_mod.describe_status(sess.status)
            link = f' - <a href="{C.esc(sess.web_url)}" target="_blank">open session in GitLab</a>' if sess.web_url else ""
            C.md(f'<div class="lx-q">{C.badge("Session " + str(sess.id), "info", "link")}{C.badge(label, tone)}'
                 f'<span class="loc">Merge request !{C.esc(S.gitlab_mr)}{link}</span></div>')
            st.button("Refresh status and result", on_click=gitlab_refresh_flow, icon=":material/refresh:",
                      key="gl_refresh_flow")
            if sess.status not in ai_mod.TERMINAL and ai_mod.session_age_minutes(sess) > ai_mod.SLOW_AFTER_MINUTES:
                st.warning(f"The session has not finished after {ai_mod.SLOW_AFTER_MINUTES} minutes. Open it in GitLab "
                           "to see where it is waiting.")
            res = S.gitlab_result
            if res:
                C.md(f'<div class="lx-q">{C.badge("LIVE: comment posted by the GitLab Duo flow", "ok", "sparkles")}'
                     f'<span class="loc">{C.esc(res.author)} - {C.esc(res.created_at)}</span></div>')
                if res.note_url:
                    st.markdown(f"[Open the comment in GitLab]({res.note_url})")
                st.markdown(redact(res.body)[:6000])


def view_analysis() -> None:
    C.hero("Security Analysis", "Deterministic checks are authoritative. AI explanations are optional, advisory and clearly labelled.",
           "radar", "STAGE 02")
    p = S.project
    statuses = ai_mod.provider_statuses(cfg_get)
    by_id = {s.id: s for s in statuses}
    with st.container(border=True):
        C.section("AI provider", "Choose how explanations are produced. Findings never depend on AI.", "sparkles")
        choice = st.segmented_control("AI provider", ["none", "external", "gitlab"],
                                      format_func=lambda i: by_id[i].label, default="none",
                                      key="ai_provider", label_visibility="collapsed") or "none"
        C.md(_provider_grid(statuses, choice))
        effective = choice if S.mode == "live" else "none"
        if S.mode == "simulation":
            st.info("Simulation mode: per-finding AI explanations and GitLab Duo are disabled. Use the simulated "
                    "orchestration below.")
        elif by_id[choice].state != "ready":
            st.warning(f"{by_id[choice].label} is not ready, so the analysis will use deterministic checks only.")
            effective = "none"
    with st.container(border=True):
        C.section("Run analysis", f"Target: {p.name}", "radar")
        st.caption("Static pattern checks over text files. No project code is executed, imported or evaluated.")
        if st.button("Run security analysis", icon=":material/radar:", type="primary", key="btn_scan"):
            run_analysis(effective)
    scan = S.scan
    if not scan:
        C.empty_state("radar", "No analysis yet",
                      "Run the analysis to see findings, severity, evidence and a prioritized remediation plan.")
        return
    rep = current_report()
    summary = rep["summary"]
    left, right = st.columns([1, 2], gap="large")
    with left:
        with st.container(border=True):
            C.section("Risk level", f"{summary['total']} finding(s)", "activity")
            C.md(C.risk_ring(summary["risk_score"], summary["risk_level"]))
    with right:
        with st.container(border=True):
            C.section("Severity and scan modules", "Completed, skipped and unavailable checks are listed honestly.", "layers")
            C.md(C.sev_bar(summary["counts"]))
            C.md(C.check_grid(scan.checks))
    if S.mode == "live" and choice == "gitlab" and by_id["gitlab"].state == "ready":
        _gitlab_flow_card() if gitlab_flow_enabled() else _gitlab_card()
    with st.container(border=True):
        C.section("Findings", "Every finding is traceable to a rule, file and line. Evidence is redacted.", "bug")
        sel = st.segmented_control("Severity filter", list(SEVERITY_ORDER), selection_mode="multi",
                                   default=list(SEVERITY_ORDER), key="sev_filter", label_visibility="collapsed")
        wanted = list(SEVERITY_ORDER) if sel is None else sel
        shown = [f for f in scan.findings if f.severity in wanted]
        if not scan.findings:
            C.empty_state("shield-check", "No findings from the checks performed",
                          "This does not prove the code is secure: unavailable checks are listed above.")
        elif not shown:
            st.info("No findings match the selected severities.")
        else:
            notes = S.ai.notes if S.ai else {}
            label = S.ai.label if S.ai else ""
            C.md("".join(C.finding_card(f, notes.get(f.id, ""), label) for f in shown[:100]))
            if len(shown) > 100:
                st.caption(f"Showing the first 100 of {len(shown)} findings; the report contains all of them.")
    render_ai_panel()
    st.button("Continue to the report", on_click=goto, args=(3,), key="cta_2", icon=":material/arrow_forward:", type="primary")


def view_report() -> None:
    C.hero("Security Report", "A traceable summary with strengths, weaknesses, a prioritized plan and stated limitations.",
           "file", "STAGE 03")
    rep = current_report()
    summary = rep["summary"]
    with st.container(border=True):
        left, right = st.columns([1, 2], gap="large")
        with left:
            C.md(C.risk_ring(summary["risk_score"], summary["risk_level"]))
        with right:
            C.section("Executive summary", f"{rep['project']} - generated {rep['generated_at']}", "activity")
            C.md(C.sev_bar(summary["counts"]))
            st.markdown(f"**{summary['total']}** finding(s) across **{summary['files_scanned']}** scanned text file(s). "
                        f"Risk level: **{summary['risk_level']}**. Deterministic findings are listed separately from any AI text.")
    c1, c2 = st.columns(2, gap="large")
    with c1:
        with st.container(border=True):
            C.section("Strengths", "Hygiene checks that passed.", "check-circle")
            C.checklist([("ok", x) for x in rep["strengths"]] or [("muted", "None identified by the checks performed")])
    with c2:
        with st.container(border=True):
            C.section("Weaknesses", "Gaps and risks that need attention.", "alert")
            C.checklist([("warn", x) for x in rep["weaknesses"]] or [("muted", "None identified by the checks performed")])
    with st.container(border=True):
        C.section("Prioritized remediation plan", "Ordered by severity.", "list")
        if rep["remediation_plan"]:
            st.dataframe(rep["remediation_plan"], hide_index=True)
        else:
            C.empty_state("shield-check", "Nothing to remediate", "The checks performed produced no findings.")
    render_ai_report_section()
    with st.container(border=True):
        C.section("Limitations", "What this report does not claim.", "info")
        C.checklist([("warn", x) for x in rep["limitations"]])
    with st.container(border=True):
        C.section("Download", "Evidence is redacted. Nothing is stored server-side beyond this browser session.", "download")
        name = safe_name(S.project.name)
        d1, d2, d3 = st.columns(3)
        d1.download_button("Report (JSON)", json.dumps(rep, indent=2), file_name=f"{name}-report.json",
                           mime="application/json", key="dl_json", icon=":material/data_object:")
        d2.download_button("Report (Markdown)", report_mod.report_markdown(rep) + ai_markdown(rep), file_name=f"{name}-report.md",
                           mime="text/markdown", key="dl_md", icon=":material/description:")
        d3.download_button("GitLab Duo hand-off brief", report_mod.duo_handoff(rep), file_name=f"{name}-duo-handoff.md",
                           mime="text/markdown", key="dl_duo", icon=":material/assignment:")
        st.caption("The hand-off brief is text you can paste into a GitLab Duo flow yourself.")
    st.button("Continue to remediation", on_click=goto, args=(4,), key="cta_3", icon=":material/arrow_forward:", type="primary")

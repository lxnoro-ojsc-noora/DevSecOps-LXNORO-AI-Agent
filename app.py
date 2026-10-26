"""DevSecOps LXNORO AI Agent: futuristic security command center (Streamlit entry point).

Seven connected stages share one session state and call the real backend in devsecops_agent:
Intake, Analysis, Report, Remediation, Export, Deploy (simulation) and Rescan (on-demand).
Uploaded code is never executed. Security decisions are enforced in the backend.
"""
from __future__ import annotations

import streamlit as st

from dashboard import components as C
from dashboard import state, theme, views_ops, views_remediate, views_workflow
from dashboard.icons import svg
from devsecops_agent import ai as ai_mod
from devsecops_agent import github_io
from devsecops_agent import report as report_mod

st.set_page_config(page_title="DevSecOps LXNORO AI Agent", page_icon="\U0001F6E1", layout="wide",
                   initial_sidebar_state="collapsed")
S = st.session_state

VIEWS = {
    1: views_workflow.view_intake,
    2: views_workflow.view_analysis,
    3: views_workflow.view_report,
    4: views_remediate.view_remediation,
    5: views_remediate.view_export,
    6: views_ops.view_deploy,
    7: views_ops.view_rescan,
}


def render_top() -> None:
    ready = [s for s in ai_mod.provider_statuses(state.cfg_get) if s.id in ("external", "gitlab") and s.state == "ready"]
    pub = github_io.load_publish_config(state.cfg_get)
    pills = [
        C.pill("AI explanations: configured", "ok") if ready
        else C.pill("AI explanations: not configured (deterministic only)", "off"),
        C.pill("GitHub publishing: enabled", "ok") if pub else C.pill("GitHub publishing: disabled", "off"),
        C.pill("Deployment: SIMULATION only", "warn"),
        C.pill("Monitoring: on-demand rescan", "warn"),
    ]
    C.md(
        f'<div class="lx-top"><div class="lx-brand"><div class="lx-logo">{svg("shield-check", 26, "#22d3ee")}</div>'
        f'<div><div class="lx-title">DevSecOps LXNORO AI Agent</div>'
        f'<div class="lx-tag">Security command center</div></div></div><div class="lx-pills">{"".join(pills)}</div></div>'
    )


def render_nav() -> None:
    states = state.nav_states()
    st.markdown(f"<style>{theme.nav_css(states)}</style>", unsafe_allow_html=True)
    for (n, name, _icon), col in zip(theme.STAGES, st.columns(7, gap="small")):
        col.button(name, key=f"nav_{n}", on_click=state.goto, args=(n,), disabled=states[n] == "locked")


def mission_kpis() -> list:
    scan = S.scan
    level = report_mod.risk_level(scan.findings) if scan else "-"
    applied = sum(1 for v in S.apply_result.statuses.values() if v == "applied") if S.apply_result else "-"
    last = S.history[-1].ts.replace("T", " ")[11:19] + " UTC" if S.history else "-"
    return [
        ("Project", S.project.name if S.project else "None loaded", S.project.source if S.project else "Load one in stage 1", "#22d3ee", "folder"),
        ("Risk level", level, "from the latest analysis", C.LEVEL_COLORS.get(level, "#8b93a7"), "activity"),
        ("Findings", len(scan.findings) if scan else "-", "deterministic rules", "#8b5cf6", "bug"),
        ("Fixes applied", applied, "in the corrected copy", "#34d399", "shield-check"),
        ("Awaiting approval", state.pending_count() if scan else "-", "human decisions", "#ffd23f", "lock"),
        ("Deployment", "SIMULATED" if S.deployment else "Not run", "simulation only", "#ffd23f", "rocket"),
        ("Last rescan", last, "on-demand", "#5aa9ff", "refresh"),
    ]


def main() -> None:
    state.init_state()
    st.markdown(f"<style>{theme.BASE_CSS}</style>", unsafe_allow_html=True)
    if not state.reach().get(S.stage, False):
        S.stage = 1
    render_top()
    nav_slot = st.container()
    kpi_slot = st.container()
    VIEWS[S.stage]()
    with nav_slot:
        render_nav()
    with kpi_slot:
        C.kpi_grid(mission_kpis())
    C.md('<div class="lx-foot">MIT License. Copyright (c) 2026 NOORA AL-MAOLAI. Research Center: LXNORO OJSC. '
         'Static analysis only: results are not a guarantee of security.</div>')


main()

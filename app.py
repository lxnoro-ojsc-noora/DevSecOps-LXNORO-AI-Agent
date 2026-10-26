"""DevSecOps LXNORO AI Agent: futuristic security command center (Streamlit entry point).

Seven connected stages share one session state and call the real backend in devsecops_agent:
Intake, Analysis (built-in rules, Bandit, OSV.dev), Report, Remediation, Export, Deploy
(simulation) and Rescan (on-demand). A visible Live/Simulation selector decides whether real
integrations or labelled deterministic fixtures are used. Uploaded code is never executed.
"""
from __future__ import annotations

import streamlit as st

from dashboard import components as C
from dashboard import state, theme, views_ops, views_remediate, views_workflow
from dashboard.icons import svg
from devsecops_agent import ai as ai_mod
from devsecops_agent import engines, github_io
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
    live = S.mode == "live"
    ai_ready = ai_mod.load_config(state.cfg_get) is not None
    if not live:
        ai_pill = C.pill("AI: SIMULATED (not a model)", "warn")
    elif ai_ready:
        ai_pill = C.pill("AI explanations: configured", "ok")
    else:
        ai_pill = C.pill("AI explanations: not configured (deterministic only)", "off")
    pub = github_io.load_publish_config(state.cfg_get) if live else None
    if pub:
        pub_pill = C.pill("GitHub publishing: enabled", "ok")
    elif live:
        pub_pill = C.pill("GitHub publishing: disabled", "off")
    else:
        pub_pill = C.pill("GitHub publishing: disabled (simulation)", "off")
    pills = [
        C.pill("Mode: LIVE", "ok") if live else C.pill("Mode: SIMULATION", "warn"),
        ai_pill,
        pub_pill,
        C.pill("Bandit: available", "ok") if engines.bandit_available() else C.pill("Bandit: unavailable", "off"),
        C.pill("Dependencies: OSV.dev (network)", "ok") if live else C.pill("Dependencies: SIMULATED fixture", "warn"),
        C.pill("Deployment: SIMULATION only", "warn"),
        C.pill("Monitoring: on-demand rescan", "warn"),
    ]
    C.md(
        f'<div class="lx-top"><div class="lx-brand"><div class="lx-logo">{svg("shield-check", 26, "#22d3ee")}</div>'
        f'<div><div class="lx-title">DevSecOps LXNORO AI Agent</div>'
        f'<div class="lx-tag">Security command center</div></div></div><div class="lx-pills">{"".join(pills)}</div></div>'
    )


def render_mode() -> None:
    left, right = st.columns([1, 3])
    with left:
        st.radio("Mode", ["live", "simulation"], format_func=lambda m: "LIVE" if m == "live" else "SIMULATION",
                 horizontal=True, key="mode_choice", on_change=state.set_mode, label_visibility="collapsed")
    with right:
        if S.mode == "live":
            st.caption("LIVE: real scanners (built-in rules, Bandit, OSV.dev) and your configured AI provider. "
                       "Deployment is still a simulation: no deployment provider is implemented. "
                       "Switching mode resets the workflow.")
        else:
            C.banner("SIMULATION MODE: deterministic fixtures and templates, clearly labelled. No external changes are "
                     "made; GitHub publishing and GitLab AI are disabled. Switching mode resets the workflow.")


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
        ("Mode", "LIVE" if S.mode == "live" else "SIMULATION", "results are labelled by origin",
         "#34d399" if S.mode == "live" else "#ffd23f", "layers"),
        ("Project", S.project.name if S.project else "None loaded", S.project.source if S.project else "Load one in stage 1", "#22d3ee", "folder"),
        ("Risk level", level, "from the latest analysis", C.LEVEL_COLORS.get(level, "#8b93a7"), "activity"),
        ("Findings", len(scan.findings) if scan else "-", "all engines combined", "#8b5cf6", "bug"),
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
    render_mode()
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

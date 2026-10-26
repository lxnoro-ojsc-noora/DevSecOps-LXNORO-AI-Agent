"""AI orchestration panels for the Analysis, Report, Remediation and Rescan stages.

Every AI result is labelled LIVE or SIMULATED with its provider. Failures are shown as errors;
there is no silent fallback. AI never applies changes: candidates go to the approval queue.
"""
from __future__ import annotations

import streamlit as st

from . import components as C
from .state import (
    S, ai_client, ai_fixes_action, ai_rescan_action, ai_test, ai_triage_action, ai_validation_action,
)

HEALTH_TONE = {"verified": "ok", "failed": "bad", "unavailable": "warn", "simulated": "warn"}


def _origin(result) -> str:
    return C.badge("LIVE AI", "ok", "sparkles") if result.live else C.badge("SIMULATED", "warn", "flask")


def _line(result, text: str) -> None:
    C.md(f'<div class="lx-q">{_origin(result)}<span class="loc">{C.esc(result.label)}: {C.esc(text)}</span></div>')


def _show_triage() -> None:
    t = S.ai_triage
    if not t:
        return
    by_id = {f.id: f for f in S.scan.findings}
    _line(t, f"advisory prioritisation; {t.discarded} invalid model entries discarded.")
    if t.summary:
        st.text(t.summary)
    rows = [{"rank": p.rank, "severity": by_id[p.finding_id].severity,
             "location": f"{by_id[p.finding_id].path}:{by_id[p.finding_id].line}", "rationale (AI)": p.rationale}
            for p in t.priorities if p.finding_id in by_id]
    if rows:
        st.dataframe(rows, hide_index=True)


def _show_fixes() -> None:
    r = S.ai_fixes
    if not r:
        return
    _line(r, f"{len(r.candidates)} candidate(s) passed the deterministic checks; {len(r.rejected)} rejected.")
    if r.candidates:
        st.info("Candidates are in the Remediation stage and need a named human approval before they can be applied.")
    if r.attempted == 0 and not r.rejected:
        st.caption("No eligible findings: only Python findings without a deterministic fixer are sent to the model.")
    if r.rejected:
        with st.expander(f"Rejected proposals ({len(r.rejected)})"):
            st.dataframe([{"finding": i, "reason": why} for i, why in r.rejected], hide_index=True)


def render_ai_panel() -> None:
    client, reason = ai_client()
    with st.container(border=True):
        C.section("AI orchestration", "The model coordinates and explains. Scanners, validation and approvals stay authoritative.",
                  "sparkles")
        if S.mode == "simulation":
            C.banner("SIMULATION: results come from deterministic templates, not from a model.")
        elif client is None:
            C.checklist([("warn", reason)])
        else:
            C.checklist([
                ("ok", f"Provider configured: {client.label}. Not verified until Test connection succeeds."),
                ("ok", "Findings, syntax checks, policy and approvals are enforced by deterministic code."),
            ])
        health = S.ai_health
        if health:
            C.md(f'<div class="lx-q">{C.badge(health["state"].upper(), HEALTH_TONE.get(health["state"], "muted"))}'
                 f'<span class="loc">{C.esc(health["detail"])}</span></div>')
        ready = client is not None and S.scan is not None
        c1, c2, c3 = st.columns(3)
        c1.button("Test connection", on_click=ai_test, key="ai_test", icon=":material/refresh:")
        c2.button("Prioritise findings", on_click=ai_triage_action, key="ai_triage", icon=":material/radar:",
                  disabled=not ready)
        c3.button("Propose candidate fixes", on_click=ai_fixes_action, key="ai_fixes", icon=":material/build:",
                  disabled=not ready)
        if S.ai_msg:
            st.error(S.ai_msg)
        _show_triage()
        _show_fixes()


def render_ai_remediation() -> None:
    client, reason = ai_client()
    with st.container(border=True):
        C.section("AI assistance", "Candidate fixes and validation summaries. AI never applies anything.", "sparkles")
        c1, c2 = st.columns(2)
        c1.button("Propose candidate fixes", on_click=ai_fixes_action, key="ai_fixes_rem", icon=":material/build:",
                  disabled=client is None or S.scan is None)
        c2.button("Summarise validation results", on_click=ai_validation_action, key="ai_validation",
                  icon=":material/description:", disabled=client is None or S.apply_result is None)
        if client is None:
            st.caption(reason)
        elif S.apply_result is None:
            st.caption("Apply changes first to enable the validation summary.")
        if S.ai_msg:
            st.error(S.ai_msg)
        _show_fixes()
        if S.ai_validation:
            _line(S.ai_validation, "advisory summary of the validation results.")
            st.text(S.ai_validation.text)


def render_ai_rescan() -> None:
    client, reason = ai_client()
    with st.container(border=True):
        C.section("AI interpretation", "Advisory reading of the rescan and drift. Deterministic results stay authoritative.", "sparkles")
        st.button("Interpret rescan and drift", on_click=ai_rescan_action, key="ai_rescan", icon=":material/radar:",
                  disabled=client is None or S.last_rescan is None)
        if client is None:
            st.caption(reason)
        elif S.last_rescan is None:
            st.caption("Run a rescan first.")
        if S.ai_msg:
            st.error(S.ai_msg)
        if S.ai_rescan:
            _line(S.ai_rescan, "advisory interpretation of the latest rescan.")
            st.text(S.ai_rescan.text)


def render_ai_report_section() -> None:
    with st.container(border=True):
        C.section("AI analysis (advisory)", "Clearly separated from the deterministic findings above.", "sparkles")
        shown = False
        if S.ai_triage:
            shown = True
            _line(S.ai_triage, "prioritisation summary.")
            st.text(S.ai_triage.summary or "(no summary returned)")
        if S.ai_validation:
            shown = True
            _line(S.ai_validation, "validation summary.")
            st.text(S.ai_validation.text)
        if S.ai_rescan:
            shown = True
            _line(S.ai_rescan, "rescan interpretation.")
            st.text(S.ai_rescan.text)
        if not shown:
            st.caption("No AI analysis was run. This report contains deterministic findings only.")


def ai_markdown(rep: dict) -> str:
    ai = rep.get("ai_analysis") or {}
    if not ai:
        return "\n## AI analysis\n- No AI analysis was run.\n"
    lines = ["", "## AI analysis (advisory, not scanner results)"]
    for key, item in ai.items():
        lines.append(f"### {key.replace('_', ' ')} (origin: {item.get('origin')}, provider: {item.get('provider')})")
        for field in ("summary", "text"):
            if item.get(field):
                lines.append(str(item[field]).replace("\n", " "))
        for p in item.get("priorities", []):
            lines.append(f"- {p['rank']}. {p['finding_id']}: {p['rationale']}")
        if "accepted_for_approval" in item:
            lines.append(f"- {item['accepted_for_approval']} candidate(s) accepted for human approval; {len(item['rejected'])} rejected.")
    return "\n".join(lines) + "\n"

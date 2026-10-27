"""HTML components for the command center.

Every dynamic value is HTML-escaped. Builders return single-line HTML (no blank lines or
indentation) so Streamlit's markdown parser cannot reinterpret it.
"""
from __future__ import annotations

import html
import re

import streamlit as st

from devsecops_agent.models import SEVERITY_ORDER

from .icons import svg

SEV_COLORS = {"critical": "#ff3b6b", "high": "#ff8a3d", "medium": "#ffd23f", "low": "#34d399", "info": "#5aa9ff"}
LEVEL_COLORS = {"Critical": "#ff3b6b", "High": "#ff8a3d", "Medium": "#ffd23f", "Low": "#34d399", "None detected": "#34d399"}
TONES = {"ok": "#34d399", "warn": "#ffd23f", "bad": "#ff3b6b", "info": "#22d3ee", "muted": "#8b93a7"}
_HEX = re.compile(r"^#[0-9a-fA-F]{6}$")

STATUS_TONES = {
    "applied": ("ok", "Applied"), "approved": ("info", "Approved, not yet applied"),
    "rejected": ("bad", "Rejected"), "pending_approval": ("warn", "Awaiting approval"),
    "awaiting_approval": ("warn", "Awaiting approval"), "ready": ("ok", "Ready to apply"),
    "skipped": ("muted", "Skipped (file changed or rewrite invalid)"),
    "applied_simulated": ("muted", "Applied to a simulated file only (not exported)"),
}

AUDIT_TONES = {
    "approved": "ok", "applied_after_approval": "ok", "rejected": "bad", "auto_applied": "info",
    "skipped": "warn", "deployment_simulated": "warn", "drift_simulated": "warn",
    "github_pr_created": "ok", "gitlab_session_submitted": "info",
}


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def _one_line(value) -> str:
    return esc(re.sub(r"\s+", " ", str(value)).strip())


def _br(value) -> str:
    return esc(value).replace("\r\n", "\n").replace("\n", "<br>")


def _tone(tone: str) -> str:
    return tone if tone in TONES else "muted"


def _accent(color: str) -> str:
    return color if _HEX.match(color or "") else "#22d3ee"


def md(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def badge(text: str, tone: str = "muted", icon_name: str = "") -> str:
    tone = _tone(tone)
    icon = svg(icon_name, 12, TONES[tone], 2) if icon_name else ""
    return f'<span class="lx-badge {tone}">{icon}{esc(text)}</span>'


def pill(text: str, tone: str = "off") -> str:
    tone = tone if tone in ("ok", "warn", "off") else "off"
    return f'<span class="lx-pill {tone}"><i></i>{esc(text)}</span>'


def sev_badge(severity: str) -> str:
    sev = severity if severity in SEV_COLORS else "info"
    return f'<span class="lx-sev {sev}">{esc(sev.upper())}</span>'


def status_badge(status: str) -> str:
    tone, label = STATUS_TONES.get(status, ("muted", str(status)))
    return badge(label, tone)


def hero(title: str, desc: str, icon_name: str, eyebrow: str = "") -> None:
    md(
        f'<div class="lx-hero"><div class="lx-hero-ic">{svg(icon_name, 28, "#22d3ee")}</div>'
        f'<div><div class="lx-eyebrow">{esc(eyebrow)}</div><div class="lx-hero-t">{esc(title)}</div>'
        f'<div class="lx-hero-d">{esc(desc)}</div></div></div>'
    )


def section(title: str, desc: str, icon_name: str) -> None:
    md(
        f'<div class="lx-sec"><div class="ic">{svg(icon_name, 20, "#22d3ee")}</div>'
        f'<div><div class="t">{esc(title)}</div><div class="d">{esc(desc)}</div></div></div>'
    )


def kpi(label: str, value, sub: str = "", accent: str = "#22d3ee", icon_name: str = "") -> str:
    icon = svg(icon_name, 13, "#8b93a7", 2) if icon_name else ""
    subline = f'<div class="s">{esc(sub)}</div>' if sub else ""
    return (
        f'<div class="lx-kpi" style="--accent:{_accent(accent)}"><div class="k">{icon}{esc(label)}</div>'
        f'<div class="v">{esc(value)}</div>{subline}</div>'
    )


def kpi_grid(items) -> None:
    md('<div class="lx-kpis">' + "".join(kpi(*it) for it in items) + "</div>")


def empty_state(icon_name: str, title: str, text: str) -> None:
    md(
        f'<div class="lx-empty"><div class="ic">{svg(icon_name, 30, "#22d3ee")}</div>'
        f'<div class="t">{esc(title)}</div><div class="d">{esc(text)}</div></div>'
    )


def banner(text: str, icon_name: str = "flask") -> None:
    md(f'<div class="lx-banner">{svg(icon_name, 20, "#ffd23f")}<div>{esc(text)}</div></div>')


def checklist(items) -> None:
    """items: (tone, text) where tone is ok | warn | bad | muted."""
    icons = {"ok": "check-circle", "warn": "alert", "bad": "x", "muted": "clock"}
    rows = "".join(
        f'<div class="lx-li">{svg(icons.get(t, "info"), 17, TONES[_tone(t)])}<div>{esc(text)}</div></div>'
        for t, text in items
    )
    md(f'<div class="lx-list">{rows}</div>')


def risk_ring(score: int, level: str) -> str:
    color = LEVEL_COLORS.get(level, "#22d3ee")
    circ = 2 * 3.14159 * 52
    dash = circ * max(0, min(100, int(score))) / 100
    return (
        f'<div class="lx-ring"><svg viewBox="0 0 140 140" width="160" height="160">'
        f'<circle cx="70" cy="70" r="52" fill="none" stroke="rgba(139,147,255,.15)" stroke-width="10"/>'
        f'<circle cx="70" cy="70" r="52" fill="none" stroke="{color}" stroke-width="10" stroke-linecap="round" '
        f'stroke-dasharray="{dash:.1f} {circ:.1f}" transform="rotate(-90 70 70)" style="filter:drop-shadow(0 0 6px {color})"/></svg>'
        f'<div class="lx-ring-c"><div class="n" style="color:{color}">{int(score)}</div><div class="l">{esc(level)}</div></div></div>'
    )


def sev_bar(counts: dict) -> str:
    total = sum(counts.get(s, 0) for s in SEVERITY_ORDER)
    legend = "".join(
        f'<span><i style="background:{SEV_COLORS[s]}"></i>{s.upper()} <b>{int(counts.get(s, 0))}</b></span>'
        for s in SEVERITY_ORDER
    )
    if not total:
        return f'<div><div class="lx-sevbar"></div><div class="lx-legend">{legend}</div></div>'
    segs = "".join(
        f'<span style="flex:{int(counts[s])};background:{SEV_COLORS[s]}"></span>' for s in SEVERITY_ORDER if counts.get(s)
    )
    return f'<div><div class="lx-sevbar">{segs}</div><div class="lx-legend">{legend}</div></div>'


def check_grid(checks) -> str:
    tones = {"performed": ("ok", "check-circle", "PERFORMED"), "unavailable": ("warn", "alert", "UNAVAILABLE"),
             "skipped": ("muted", "clock", "SKIPPED")}
    cards = []
    for c in checks:
        tone, icon_name, label = tones.get(c.status, ("muted", "info", str(c.status).upper()))
        detail = f'<div class="d">{esc(c.detail)}</div>' if c.detail else ""
        cards.append(
            f'<div class="lx-check">{svg(icon_name, 18, TONES[tone])}<div><div class="n">{esc(c.name)}</div>'
            f'<div>{badge(label, tone)}</div>{detail}</div></div>'
        )
    return f'<div class="lx-checks">{"".join(cards)}</div>'


def finding_card(f, ai_note: str = "", ai_label: str = "") -> str:
    color = SEV_COLORS.get(f.severity, "#5aa9ff")
    fix = badge("Fix available", "ok", "shield-check") if f.fixable else ""
    ai = ""
    if ai_note:
        ai = (
            f'<div class="lx-ai"><div class="lx-ai-h">{badge("AI-generated", "info", "sparkles")}'
            f'<span>{esc(ai_label)} - advisory, not a scanner result</span></div>'
            f'<div class="lx-ai-b">{_br(ai_note)}</div></div>'
        )
    return (
        f'<div class="lx-find" style="--c:{color}">'
        f'<div class="lx-find-h">{sev_badge(f.severity)}<span class="t">{esc(f.title)}</span>{fix}</div>'
        f'<div class="lx-find-m"><span>{svg("file", 13)}{esc(f.path)}:{esc(f.line)}</span>'
        f'<span>{svg("terminal", 13)}{esc(f.rule_id)}</span><span>{svg("cpu", 13)}Deterministic rule</span></div>'
        f'<div class="lx-pre">{_one_line(f.evidence)}</div>'
        f'<details><summary>Why it matters and how to fix it</summary><div class="lx-grid3">'
        f'<div><b>Explanation</b><p>{esc(f.explanation)}</p></div><div><b>Impact</b><p>{esc(f.impact)}</p></div>'
        f'<div><b>Remediation</b><p>{esc(f.remediation)}</p></div></div>{ai}</details></div>'
    )


def queue_header(r, status: str) -> str:
    gate = badge("Human approval required", "warn", "lock") if r.needs_approval else badge("Auto-eligible, low risk", "ok", "check-circle")
    if r.rule_id == "AI-CANDIDATE":
        gate = badge("AI-proposed", "info", "sparkles") + gate
    return (
        f'<div class="lx-q">{sev_badge(r.severity)}{gate}{status_badge(status)}'
        f'<span class="loc">{esc(r.path)}:{esc(r.line)}</span></div>'
        f'<div class="lx-q-d">{esc(r.description)} Fix risk: <b>{esc(r.fix_risk)}</b>.</div>'
    )


def timeline(audit: list, limit: int = 60) -> str:
    if not audit:
        return '<div class="lx-q-d">No audit events recorded yet.</div>'
    rows = []
    for e in reversed(audit[-limit:]):
        tone = _tone(AUDIT_TONES.get(e.get("action", ""), "muted"))
        loc = f' - {esc(e["path"])}:{esc(e.get("line", ""))}' if e.get("path") else ""
        detail = f'<div class="m">{_one_line(e["detail"])}</div>' if e.get("detail") else ""
        rows.append(
            f'<div class="lx-tl-i" style="--tc:{TONES[tone]}"><div class="dot"></div>'
            f'<div class="h"><b>{esc(str(e.get("action", "")).replace("_", " "))}</b><span>{esc(e.get("ts", ""))}</span></div>'
            f'<div class="m">{esc(e.get("actor", ""))} - {esc(e.get("scope", ""))}{loc}</div>{detail}</div>'
        )
    return f'<div class="lx-tl">{"".join(rows)}</div>'


PLANNED_STEPS = [
    ("Policy gate", "computed"), ("Package corrected source", "computed"), ("Security scan of package", "computed"),
    ("Build container image", "simulated"), ("Release to an environment", "simulated"), ("Health check", "simulated"),
]


def stepper(steps=None) -> str:
    """steps: deployment record steps, or None to show the planned (not yet run) pipeline."""
    run = steps is not None
    items = steps if run else [{"step": n, "nature": k, "status": "pending", "detail": ""} for n, k in PLANNED_STEPS]
    cards = []
    for i, s in enumerate(items, start=1):
        tone = "ok" if s["nature"] == "computed" else "warn"
        label = "COMPUTED" if s["nature"] == "computed" else "SIMULATED"
        status = badge(str(s["status"]).upper(), "ok" if run and s["nature"] == "computed" else ("warn" if run else "muted"))
        detail = f'<div class="d">{esc(s["detail"])}</div>' if s.get("detail") else ""
        cards.append(
            f'<div class="lx-step"><div class="n">STEP {i:02d}</div><div class="t">{esc(s["step"])}</div>'
            f'<div>{badge(label, tone)} {status}</div>{detail}</div>'
        )
    return f'<div class="lx-flow">{"".join(cards)}</div>'

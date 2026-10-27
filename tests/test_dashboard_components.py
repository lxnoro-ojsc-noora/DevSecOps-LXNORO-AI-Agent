from devsecops_agent.models import Finding
from dashboard import components as C
from dashboard import icons, theme


def make_finding(**kw):
    base = dict(id="R:a.py:1", rule_id="R", title="T", severity="high", path="a.py", line=1,
                evidence="x", explanation="e", impact="i", remediation="r")
    base.update(kw)
    return Finding(**base)


def test_finding_card_escapes_untrusted_text():
    f = make_finding(title="<script>alert(1)</script>", path="<img src=x onerror=1>.py", evidence="</div><b>x")
    out = C.finding_card(f, ai_note="<script>bad()</script>", ai_label="<i>x</i>")
    assert "<script>" not in out and "<img" not in out and "</div><b>" not in out
    assert "&lt;script&gt;" in out and "AI-generated" in out and "advisory, not a scanner result" in out
    assert "\n" not in out


def test_timeline_escapes_and_orders_newest_first():
    audit = [
        {"ts": "t1", "actor": "human:<b>x</b>", "action": "approved", "scope": "s", "detail": "<script>1</script>"},
        {"ts": "t2", "actor": "system", "action": "auto_applied", "scope": "s"},
    ]
    out = C.timeline(audit)
    assert "<script>" not in out and "<b>x</b>" not in out
    assert out.index("auto applied") < out.index("approved")
    assert "No audit events" in C.timeline([])


def test_badges_and_kpis_reject_unknown_tones_and_colors():
    assert 'class="lx-badge muted"' in C.badge("x", "evil\" onload=\"1")
    assert "--accent:#22d3ee" in C.kpi("k", "v", accent="red;background:url(x)")
    assert 'class="lx-sev info"' in C.sev_badge("unknown")


def test_sev_bar_and_ring_and_stepper():
    assert "lx-sevbar" in C.sev_bar({"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0})
    assert "stroke-dasharray" in C.risk_ring(150, "Critical")
    planned = C.stepper(None)
    assert planned.count("SIMULATED") == 3 and planned.count("COMPUTED") == 3


def test_icons_cover_every_stage_and_fall_back():
    for _n, _name, icon_name in theme.STAGES:
        assert icon_name in icons.ICONS
    assert icons.svg("does-not-exist").startswith("<svg")
    assert icons.data_uri("shield", "#22d3ee").startswith("data:image/svg+xml;utf8,")


def test_nav_css_reflects_each_state():
    states = {1: "done", 2: "active", 3: "ready", 4: "locked", 5: "locked", 6: "locked", 7: "locked"}
    css = theme.nav_css(states)
    for n in range(1, 8):
        assert f".st-key-nav_{n} button::before" in css
    assert "02 \u00b7 ACTIVE" in css and "01 \u00b7 DONE" in css and "04 \u00b7 LOCKED" in css

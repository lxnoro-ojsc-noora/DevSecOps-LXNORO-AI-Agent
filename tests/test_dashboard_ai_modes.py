import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from devsecops_agent import intake, orchestrator
from devsecops_agent.ai import llm
from devsecops_agent.safe_zip import extract_zip

APP = str(Path(__file__).resolve().parents[1] / "app.py")
SHELL_APP = "import subprocess\n\n\ndef f(c):\n    subprocess.call(c, shell=" + "True)\n"
SECRET = "hunter2hunter2"
ENV_KEYS = ("AI_PROVIDER", "AI_API_KEY", "AI_MODEL", "AI_ENDPOINT", "GITHUB_TOKEN", "PUBLISH_KEY", "PUBLISH_REPO",
            "GITLAB_AI_TOKEN", "GITLAB_AI_PROJECT_ID")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


class FakeLive:
    """Stands in for the provider so the UI wiring is testable without network or credentials."""

    live = True
    label = "fake/model (live)"
    fail = False

    def __init__(self, cfg, post=None):
        self.cfg = cfg

    def run(self, task, payload, prompt):
        if FakeLive.fail:
            raise llm.AIError("timeout", "The provider did not answer in time.")
        if task == "triage":
            pri = [{"finding_id": f["id"], "rank": i, "rationale": "LIVE-FAKE rationale"}
                   for i, f in enumerate(payload["findings"], start=1)]
            return json.dumps({"priorities": pri, "summary": "LIVE-FAKE summary"})
        if task == "fixes":
            fixes = [{"finding_id": it["id"], "replacement_line": it["line"].replace("shell=" + "True", "shell=False"),
                      "rationale": "LIVE-FAKE fix"} for it in payload["items"]]
            return json.dumps({"fixes": fixes})
        return json.dumps({"summary": "LIVE-FAKE " + payload["kind"]})


@pytest.fixture
def live_ai(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    monkeypatch.setenv("AI_API_KEY", "SECRETKEY")
    monkeypatch.setenv("AI_MODEL", "m")
    monkeypatch.setattr(orchestrator, "LiveClient", FakeLive)
    monkeypatch.setattr(FakeLive, "fail", False)


def make_project(source):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app.py", source)
    return intake.load_zip("demo.zip", buf.getvalue())


def digest(finding_id):
    return hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:10]


def text_of(at):
    chunks = [m.value for m in at.markdown] + [c.value for c in at.code] + [t.value for t in at.text]
    chunks += [c.value for c in at.caption] + [e.value for e in at.error]
    return "\n".join(chunks)


def seeded(source, stage=2):
    at = AppTest.from_file(APP, default_timeout=30)
    at.session_state["project"] = make_project(source)
    at.session_state["stage"] = stage
    return at.run()


def approve_and_apply(at, finding_id, prefix="p2"):
    at.text_input(key=f"{prefix}_approver").input("Lead Reviewer").run()
    at.button(key=f"{prefix}_ok_{digest(finding_id)}").click().run()
    at.button(key=f"{prefix}_apply").click().run()


# ---- mode selector

def test_mode_selector_switches_resets_and_labels_everything():
    at = seeded(SHELL_APP, stage=1)
    assert at.session_state["mode"] == "live" and "Mode: LIVE" in text_of(at)
    at.radio(key="mode_choice").set_value("simulation").run()
    assert not at.exception and at.session_state["mode"] == "simulation"
    assert at.session_state["project"] is None and at.session_state["stage"] == 1
    text = text_of(at)
    assert "Mode: SIMULATION" in text and "AI: SIMULATED" in text and "SIMULATION MODE" in text
    assert "Dependencies: SIMULATED fixture" in text and at.button(key="btn_demo").label.startswith("Load SIMULATED")
    at.radio(key="mode_choice").set_value("live").run()
    assert at.session_state["mode"] == "live" and "Mode: LIVE" in text_of(at)


# ---- simulation mode end to end

def test_simulation_workflow_is_labelled_and_ai_candidates_stay_gated():
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.radio(key="mode_choice").set_value("simulation").run()
    at.button(key="btn_demo").click().run()
    assert at.session_state["project"].name == "simulated-demo" and at.session_state["stage"] == 2
    at.button(key="btn_scan").click().run()
    scan = at.session_state["scan"]
    assert {"DEP-VULN-SIM", "PY-SHELL", "PY-EVAL", "SEC-HARDCODED"} <= {f.rule_id for f in scan.findings}
    names = {c.name: c.status for c in scan.checks}
    assert names["Bandit (Python SAST)"] == "performed" and "Dependency advisories (SIMULATED fixture)" in names

    at.button(key="ai_triage").click().run()
    triage = at.session_state["ai_triage"]
    assert triage.live is False and "SIMULATED" in triage.label and "SIMULATED" in text_of(at)
    at.button(key="ai_fixes").click().run()
    cand = at.session_state["ai_fixes"].candidates[0]
    assert any(r.rule_id == "AI-CANDIDATE" for r in at.session_state["plan"])

    at.session_state["stage"] = 4
    at.run()
    at.button(key="p2_apply").click().run()
    assert at.session_state["apply_result"].statuses[cand.finding_id] == "pending_approval"
    approve_and_apply(at, cand.finding_id)
    assert at.session_state["apply_result"].statuses[cand.finding_id] == "applied"
    corrected = at.session_state["corrected"]["app.py"]
    assert "shell=False" in corrected and "ast.literal_eval" not in corrected  # high-risk eval fix not approved
    at.button(key="ai_validation").click().run()
    assert at.session_state["ai_validation"].text.startswith("SIMULATED")

    at.session_state["stage"] = 5
    assert "disabled in simulation mode" in text_of(at.run())
    for stage in (2, 3, 4, 6):
        at.session_state["stage"] = stage
        assert SECRET not in text_of(at.run())


# ---- live mode honesty

def test_live_mode_without_credentials_reports_unavailable_and_never_fakes():
    at = seeded(SHELL_APP)
    at.button(key="btn_scan").click().run()
    assert at.button(key="ai_triage").proto.disabled and at.button(key="ai_fixes").proto.disabled
    at.button(key="ai_test").click().run()
    assert at.session_state["ai_health"]["state"] == "unavailable"
    assert "Live AI is unavailable" in text_of(at)
    assert at.session_state["ai_triage"] is None and at.session_state["ai_fixes"] is None
    assert "SIMULATED" not in text_of(at).replace("Dependencies: SIMULATED", "")


def test_live_failure_is_reported_and_never_replaced_by_a_mock_answer(live_ai, monkeypatch):
    monkeypatch.setattr(FakeLive, "fail", True)
    at = seeded(SHELL_APP)
    at.button(key="btn_scan").click().run()
    at.button(key="ai_triage").click().run()
    assert at.session_state["ai_triage"] is None and "timeout" in at.session_state["ai_msg"]
    at.button(key="ai_fixes").click().run()
    assert at.session_state["ai_fixes"] is None and "timeout" in text_of(at)
    assert "LIVE-FAKE" not in text_of(at) and "SIMULATED AI" not in text_of(at)


def test_connection_test_reports_verified_and_failed_states(live_ai, monkeypatch):
    at = seeded(SHELL_APP)
    assert at.session_state["ai_health"] is None  # nothing is claimed before a real test
    monkeypatch.setattr(llm, "ping", lambda cfg, post=None: llm.HealthResult(True, "ok", "fake answered.", 12))
    at.button(key="ai_test").click().run()
    assert at.session_state["ai_health"]["state"] == "verified"
    monkeypatch.setattr(llm, "ping", lambda cfg, post=None: llm.HealthResult(False, "auth", "credentials rejected"))
    at.button(key="ai_test").click().run()
    health = at.session_state["ai_health"]
    assert health["state"] == "failed" and "auth" in health["detail"]
    assert "SECRETKEY" not in text_of(at)


# ---- live mode with a (fake) provider: full orchestration through the UI

def test_live_orchestration_candidate_fix_needs_approval_and_reaches_the_export(live_ai):
    at = seeded(SHELL_APP)
    at.button(key="btn_scan").click().run()
    names = {c.name: c.status for c in at.session_state["scan"].checks}
    assert names["Bandit (Python SAST)"] == "performed" and names["Dependency advisories (OSV.dev)"] == "skipped"
    assert not any(n.startswith(("Dependency vulnerability", "External SAST")) for n in names)

    at.button(key="ai_triage").click().run()
    triage = at.session_state["ai_triage"]
    assert triage.live and triage.priorities and "LIVE AI" in text_of(at)
    at.button(key="ai_fixes").click().run()
    fixes = at.session_state["ai_fixes"]
    assert len(fixes.candidates) == 1 and fixes.rejected  # the unchanged import suggestion was rejected
    cand = fixes.candidates[0]

    at.session_state["stage"] = 4
    at.run()
    assert "AI-proposed" in text_of(at)
    at.button(key="p2_apply").click().run()
    assert at.session_state["apply_result"].statuses[cand.finding_id] == "pending_approval"
    assert "shell=False" not in at.session_state["corrected"]["app.py"]
    approve_and_apply(at, cand.finding_id)
    assert at.session_state["apply_result"].statuses[cand.finding_id] == "applied"
    assert "shell=False" in extract_zip(at.session_state["zip_bytes"]).text_files["app.py"]
    actions = [e["action"] for e in at.session_state["audit"]]
    assert {"ai_triage", "ai_fixes_proposed", "approved", "applied_after_approval"} <= set(actions)

    at.session_state["stage"] = 3
    report_text = text_of(at.run())
    assert "AI analysis (advisory)" in report_text and "LIVE AI" in report_text
    assert "SECRETKEY" not in report_text and "SECRETKEY" not in str(at.session_state["audit"])


def test_live_rescan_interpretation_is_reachable_after_drift(live_ai):
    at = seeded("app.run(debug=True)\n")
    at.button(key="btn_scan").click().run()
    at.session_state["stage"] = 4
    at.run()
    at.button(key="p2_apply").click().run()
    at.session_state["stage"] = 6
    at.run()
    at.button(key="btn_deploy").click().run()
    at.session_state["stage"] = 7
    at.run()
    assert at.button(key="ai_rescan").proto.disabled  # nothing to interpret before a rescan
    at.button(key="btn_drift").click().run()
    at.button(key="ai_rescan").click().run()
    result = at.session_state["ai_rescan"]
    assert result.live and result.text == "LIVE-FAKE rescan" and "LIVE AI" in text_of(at)

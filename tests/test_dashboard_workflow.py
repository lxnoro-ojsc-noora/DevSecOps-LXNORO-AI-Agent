import hashlib
import io
import zipfile
from pathlib import Path

from streamlit.testing.v1 import AppTest

from devsecops_agent import intake

APP = str(Path(__file__).resolve().parents[1] / "app.py")


def make_project():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app.py", "app.run(debug=True)\nx = eval(s)\n")
    return intake.load_zip("demo.zip", buf.getvalue())


def seeded(stage: int) -> AppTest:
    at = AppTest.from_file(APP, default_timeout=30)
    at.session_state["project"] = make_project()
    at.session_state["stage"] = stage
    return at.run()


def test_navigation_click_moves_between_unlocked_stages():
    at = seeded(1)
    assert not at.exception
    assert not at.button(key="nav_2").proto.disabled
    at.button(key="nav_2").click().run()
    assert not at.exception and at.session_state["stage"] == 2
    assert "Security Analysis" in " ".join(m.value for m in at.markdown)


def test_analysis_runs_real_scanner_and_unlocks_later_stages():
    at = seeded(2)
    at.button(key="btn_scan").click().run()
    assert not at.exception
    rules = {f.rule_id for f in at.session_state["scan"].findings}
    assert {"PY-DEBUG", "PY-EVAL"} <= rules
    for n in (3, 4, 5):
        assert not at.button(key=f"nav_{n}").proto.disabled
    assert at.button(key="nav_6").proto.disabled and at.button(key="nav_7").proto.disabled


def test_full_seven_stage_flow_with_human_approval_gate():
    at = seeded(2)
    at.button(key="btn_scan").click().run()
    scan = at.session_state["scan"]

    at.session_state["stage"] = 3
    at.run()
    assert not at.exception and "Executive summary" in " ".join(m.value for m in at.markdown)

    at.session_state["stage"] = 4
    at.run()
    assert not at.exception
    at.button(key="p2_apply").click().run()
    result = at.session_state["apply_result"]
    assert "debug=False" in result.files["app.py"] and "eval(s)" in result.files["app.py"]
    assert "import ast" not in result.files["app.py"]

    eval_id = [f.id for f in scan.findings if f.rule_id == "PY-EVAL"][0]
    digest = hashlib.sha256(eval_id.encode("utf-8")).hexdigest()[:10]
    at.text_input(key="p2_approver").input("Lead Reviewer").run()
    at.button(key=f"p2_ok_{digest}").click().run()
    at.button(key="p2_apply").click().run()
    fixed = at.session_state["apply_result"].files["app.py"]
    assert "ast.literal_eval(s)" in fixed and "import ast" in fixed
    actions = [e["action"] for e in at.session_state["audit"]]
    assert "approved" in actions and "applied_after_approval" in actions and "auto_applied" in actions

    at.session_state["stage"] = 5
    at.run()
    assert not at.exception and at.session_state["zip_bytes"]
    assert "GitHub publishing: disabled" in " ".join(m.value for m in at.markdown)

    at.session_state["stage"] = 6
    at.run()
    at.button(key="btn_deploy").click().run()
    record = at.session_state["deployment"]
    assert record.kind == "simulation" and record.real_deployment is False and record.url == ""

    at.session_state["stage"] = 7
    at.run()
    at.button(key="btn_drift").click().run()
    assert not at.exception
    new_rules = {f.rule_id for f in at.session_state["rescan_new"]}
    assert {"PY-SHELL", "PY-EVAL"} <= new_rules
    at.button(key="p5_apply").click().run()
    pending = at.session_state["apply5"].statuses
    assert pending and all(v == "pending_approval" for v in pending.values())
    assert "import ast" not in at.session_state["live_files"]["lxnoro_simulated_drift.py"]

import hashlib
import io
import zipfile
from pathlib import Path

from streamlit.testing.v1 import AppTest

from devsecops_agent import export, intake
from devsecops_agent.safe_zip import extract_zip

APP = str(Path(__file__).resolve().parents[1] / "app.py")
SECRET = "hunter2hunter2"


def make_project(source: str):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app.py", source)
    return intake.load_zip("demo.zip", buf.getvalue())


def digest(finding_id: str) -> str:
    return hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:10]


def all_text(at) -> str:
    chunks = [m.value for m in at.markdown] + [c.value for c in at.code] + [t.value for t in at.text]
    chunks += [c.value for c in at.caption]
    return "\n".join(chunks)


def start(source: str, stage: int = 2) -> AppTest:
    at = AppTest.from_file(APP, default_timeout=30)
    at.session_state["project"] = make_project(source)
    at.session_state["stage"] = stage
    return at.run()


def deployed(source: str = "app.run(debug=True)\n") -> AppTest:
    at = start(source)
    at.button(key="btn_scan").click().run()
    at.session_state["stage"] = 4
    at.run()
    at.button(key="p2_apply").click().run()
    at.session_state["stage"] = 6
    at.run()
    at.button(key="btn_deploy").click().run()
    assert at.session_state["deployment"] is not None
    at.session_state["stage"] = 7
    return at.run()


def approve_and_apply_p5(at, finding_id: str) -> None:
    at.text_input(key="p5_approver").input("Lead Reviewer").run()
    at.button(key=f"p5_ok_{digest(finding_id)}").click().run()
    at.button(key="p5_apply").click().run()


# ---- finding 1: the secret value never reaches any rendered output

def test_secret_value_is_never_rendered_in_any_stage():
    at = start(f'PASSWORD = "{SECRET}"\nx = eval(s)\n')
    at.button(key="btn_scan").click().run()
    scan = at.session_state["scan"]
    seen = [all_text(at)]
    at.session_state["stage"] = 3
    seen.append(all_text(at.run()))
    at.session_state["stage"] = 4
    seen.append(all_text(at.run()))
    at.text_input(key="p2_approver").input("Lead Reviewer").run()
    for f in scan.findings:
        if f.rule_id in ("PY-EVAL", "SEC-HARDCODED"):
            at.button(key=f"p2_ok_{digest(f.id)}").click().run()
    at.button(key="p2_apply").click().run()
    seen.append(all_text(at))
    for stage in (5, 6):
        at.session_state["stage"] = stage
        seen.append(all_text(at.run()))
    assert all(SECRET not in text for text in seen)
    assert any("[REDACTED]" in text for text in seen)
    audit = str(at.session_state["audit"])
    assert SECRET not in audit


def test_unapproved_secret_is_redacted_in_the_corrected_code_viewer():
    at = start(f'PASSWORD = "{SECRET}"\n')
    at.button(key="btn_scan").click().run()
    at.session_state["stage"] = 4
    at.run()
    at.button(key="p2_apply").click().run()
    assert at.session_state["corrected"]["app.py"].count(SECRET) == 1  # user's own file is untouched
    at.session_state["stage"] = 6
    assert SECRET not in all_text(at.run())


# ---- finding 3: post-deployment fixes reach the canonical corrected project

def test_post_deployment_approved_fix_reaches_download_and_publish_source():
    at = deployed()
    live = dict(at.session_state["live_files"])
    live["app.py"] += "x = eval(s)\n"
    at.session_state["live_files"] = live
    at.button(key="btn_rescan").click().run()
    new = at.session_state["rescan_new"]
    eval_id = [f.id for f in new if f.rule_id == "PY-EVAL"][0]
    assert "ast.literal_eval" not in at.session_state["corrected"]["app.py"]

    approve_and_apply_p5(at, eval_id)

    assert at.session_state["apply5"].statuses[eval_id] == "applied"
    corrected = at.session_state["corrected"]
    assert "ast.literal_eval(s)" in corrected["app.py"]
    assert "ast.literal_eval(s)" in extract_zip(at.session_state["zip_bytes"]).text_files["app.py"]
    changed = export.changed_files(at.session_state["project"].text_files, corrected)
    assert "ast.literal_eval(s)" in changed["app.py"]
    assert "export_updated" in [e["action"] for e in at.session_state["audit"]]


def test_simulated_drift_fix_is_never_exported_or_reported_as_exported():
    at = deployed()
    at.button(key="btn_drift").click().run()
    eval_id = [f.id for f in at.session_state["rescan_new"] if f.rule_id == "PY-EVAL"][0]
    approve_and_apply_p5(at, eval_id)
    drift = "lxnoro_simulated_drift.py"
    assert at.session_state["apply5"].statuses[eval_id] == "applied_simulated"
    assert drift not in at.session_state["corrected"]
    assert drift not in extract_zip(at.session_state["zip_bytes"]).text_files
    assert drift in at.session_state["live_files"]
    assert "simulated_fix_not_exported" in [e["action"] for e in at.session_state["audit"]]


def test_unapproved_post_deployment_change_is_not_exported():
    at = deployed()
    live = dict(at.session_state["live_files"])
    live["app.py"] += "x = eval(s)\n"
    at.session_state["live_files"] = live
    at.button(key="btn_rescan").click().run()
    at.button(key="p5_apply").click().run()
    assert all(v == "pending_approval" for v in at.session_state["apply5"].statuses.values())
    assert "ast.literal_eval" not in at.session_state["corrected"]["app.py"]


def test_project_without_fixes_can_still_continue_to_export():
    at = start("x = 1\n")
    at.button(key="btn_scan").click().run()
    at.session_state["stage"] = 4
    at.run()
    at.button(key="p2_apply").click().run()
    assert not at.exception and at.session_state["corrected"] == {"app.py": "x = 1\n"}
    assert at.session_state["zip_bytes"]

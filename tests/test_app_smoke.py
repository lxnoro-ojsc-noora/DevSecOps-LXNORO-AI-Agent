from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parents[1] / "app.py")


def markdown_text(at) -> str:
    return " ".join(m.value for m in at.markdown)


def test_new_ui_renders_brand_status_and_intake_stage():
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    text = markdown_text(at)
    assert "DevSecOps LXNORO AI Agent" in text and "Security command center" in text
    assert "Project Intake" in text and "STAGE 01" in text
    assert "Deployment: SIMULATION only" in text and "Monitoring: on-demand rescan" in text


def test_seven_stage_navigation_is_locked_until_prerequisites_exist():
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    names = {n: at.button(key=f"nav_{n}") for n in range(1, 8)}
    assert [names[n].label for n in range(1, 8)] == [
        "Intake", "Analysis", "Report", "Remediation", "Export", "Deploy", "Rescan"]
    assert not names[1].proto.disabled
    assert all(names[n].proto.disabled for n in range(2, 8))


def test_publishing_and_ai_disabled_by_default(monkeypatch):
    for key in ("GITHUB_TOKEN", "PUBLISH_KEY", "PUBLISH_REPO", "AI_PROVIDER", "AI_API_KEY", "AI_MODEL",
                "GITLAB_AI_TOKEN", "GITLAB_AI_PROJECT_ID"):
        monkeypatch.delenv(key, raising=False)
    at = AppTest.from_file(APP, default_timeout=30).run()
    text = markdown_text(at)
    assert "GitHub publishing: disabled" in text
    assert "not configured (deterministic only)" in text

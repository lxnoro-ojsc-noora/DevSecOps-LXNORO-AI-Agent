from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parents[1] / "app.py")


def test_app_renders_all_panels_without_exception():
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    text = " ".join(m.value for m in at.markdown)
    assert "DevSecOps" in text and "LXNORO" in text
    for title in ("Project Intake", "AI Security Analysis", "Outputs and GitHub Publishing",
                  "Secure Deployment and Corrected Code", "Post-Deployment Monitoring"):
        assert title in text
    assert "SIMULATION only" in text


def test_publishing_and_ai_disabled_by_default(monkeypatch):
    for key in ("GITHUB_TOKEN", "PUBLISH_KEY", "PUBLISH_REPO", "AI_PROVIDER", "AI_API_KEY", "AI_MODEL"):
        monkeypatch.delenv(key, raising=False)
    at = AppTest.from_file(APP, default_timeout=30).run()
    text = " ".join(m.value for m in at.markdown)
    assert "GitHub publishing: disabled" in text
    assert "not configured" in text

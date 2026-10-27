import json
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from devsecops_agent import ai
from devsecops_agent.ai.gitlab_duo import UPLOAD_MARKER
from devsecops_agent.scanners import scan_project

BASE = {"GITLAB_AI_TOKEN": "GLTOKEN", "GITLAB_AI_PROJECT_ID": "123", "GITLAB_AI_CONSUMER_ID": "77"}
FLOW_ENV = {**BASE, "GITLAB_AI_UPLOAD_FLOW": "1"}
SESSION_URL = "https://gitlab.com/g/p/-/automate/agent-sessions/9"
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


class FakeResp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = {} if payload is None else payload
        self.text = ""

    def json(self):
        return self._payload


class FakeHTTP:
    def __init__(self, resp):
        self.resp = resp
        self.calls = []

    def request(self, method, url, headers=None, json=None, timeout=None):
        self.calls.append((method, url, json))
        return self.resp


def _scan():
    return scan_project({"app.py": f'KEY = "{FAKE_AWS}"\nx = eval(s)\n'})


def test_flag_is_parsed_and_off_by_default():
    assert ai.load_gitlab_config(BASE.get).upload_flow is False
    assert ai.load_gitlab_config(FLOW_ENV.get).upload_flow is True


def test_upload_flow_payload_targets_the_catalog_flow_and_carries_only_redacted_findings():
    cfg = ai.load_gitlab_config(FLOW_ENV.get)
    scan = _scan()
    http = FakeHTTP(FakeResp(201, {"id": 9, "web_url": SESSION_URL, "status": "created"}))
    session = ai.submit_upload_flow(cfg, scan.findings, http=http,
                                    context=ai.upload_context("p", "ZIP upload", 1, "live", scan))
    payload = http.calls[0][2]
    assert payload["ai_catalog_item_consumer_id"] == 77 and "workflow_definition" not in payload
    assert payload["start_workflow"] is True and payload["goal"].splitlines()[0] == UPLOAD_MARKER
    assert "UPLOADED project" in payload["goal"] and "PY-EVAL" in payload["goal"] and FAKE_AWS not in payload["goal"]
    assert session.id == 9 and session.started_at


def test_upload_flow_needs_a_consumer_and_an_upload_context():
    scan = _scan()
    no_consumer = ai.load_gitlab_config({"GITLAB_AI_TOKEN": "t", "GITLAB_AI_PROJECT_ID": "123"}.get)
    with pytest.raises(ai.GitLabAIError):
        ai.submit_upload_flow(no_consumer, scan.findings, http=FakeHTTP(FakeResp()), context={"project": "p"})
    with pytest.raises(ai.GitLabAIError):
        ai.submit_upload_flow(ai.load_gitlab_config(FLOW_ENV.get), scan.findings, http=FakeHTTP(FakeResp()))


def test_upload_flow_errors_never_leak_the_token():
    cfg = ai.load_gitlab_config(FLOW_ENV.get)
    http = FakeHTTP(FakeResp(403, {"message": "nope GLTOKEN"}))
    with pytest.raises(ai.GitLabAIError) as exc:
        ai.submit_upload_flow(cfg, _scan().findings, http=http, context={"project": "p"})
    assert "GLTOKEN" not in str(exc.value) and "403" in str(exc.value)


def test_flow_source_contains_the_marker_the_app_sends():
    path = Path(__file__).resolve().parent.parent / ".gitlab" / "duo" / "flows" / "devsecops-triage-remediate.yaml"
    assert UPLOAD_MARKER in path.read_text(encoding="utf-8")


def _wired_app():
    import streamlit as st

    from dashboard import state
    from dashboard.views_workflow import _gitlab_card
    from devsecops_agent import intake
    from devsecops_agent.scanners import scan_project

    state.init_state()
    S = st.session_state
    if S.project is None:
        S.project = intake.Project("demo", "ZIP upload", {"a.py": "x = eval(s)\n"}, {}, [])
        S.scan = scan_project(S.project.text_files)
    _gitlab_card()


def _route(monkeypatch, env, use_flow):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    made = ai.GitLabSession(9, SESSION_URL, "created", "2026-10-27T09:25:00+00:00")
    calls = []

    def flow(cfg, findings, http=None, context=None):
        calls.append("flow")
        return made

    def agent(cfg, findings, http=None, context=None):
        calls.append("agent")
        return made

    monkeypatch.setattr(ai, "submit_upload_flow", flow)
    monkeypatch.setattr(ai, "submit_triage", agent)
    at = AppTest.from_function(_wired_app, default_timeout=30).run()
    at.button(key="gl_submit").click().run()
    assert not at.exception
    return at, calls


def test_catalog_flow_is_used_only_with_consumer_and_flag(monkeypatch):
    at, calls = _route(monkeypatch, FLOW_ENV, True)
    assert calls == ["flow"] and at.session_state["duo_via"] == "catalog flow"
    assert "via GitLab Duo catalog flow" in " ".join(m.value for m in at.markdown)


def test_agent_is_used_when_the_flag_is_off(monkeypatch):
    at, calls = _route(monkeypatch, BASE, False)
    assert calls == ["agent"] and at.session_state["duo_via"] == "agent"


def _stale_app():
    import streamlit as st

    from dashboard import state
    from dashboard.views_workflow import _gitlab_card
    from devsecops_agent import ai

    state.init_state()
    S = st.session_state
    if S.duo_session is None:
        S.duo_session = ai.GitLabSession(9, "https://gitlab.com/g/p/-/automate/agent-sessions/9", "running",
                                         "2020-01-01T00:00:00+00:00")
        S.duo_scope = "demo, 1 finding(s)"
    _gitlab_card()


def test_refresh_stops_waiting_after_the_timeout_and_shows_no_answer(monkeypatch):
    for key, value in FLOW_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(
        ai, "get_session",
        lambda cfg, sid, http=None, started_at="": ai.GitLabSession(sid, SESSION_URL, "running", started_at))
    at = AppTest.from_function(_stale_app, default_timeout=30).run()
    at.button(key="gl_refresh").click().run()
    assert not at.exception
    assert "Stopped waiting" in at.session_state["duo_msg"] and at.session_state["duo_answer"] == ""
    assert any("Stopped waiting" in e.value for e in at.error)

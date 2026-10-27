import pytest
from streamlit.testing.v1 import AppTest

from devsecops_agent import ai

GL = {"GITLAB_AI_TOKEN": "GLTOKEN", "GITLAB_AI_PROJECT_ID": "123"}
SESSION_URL = "https://gitlab.com/g/p/-/automate/agent-sessions/9"
STATUS = ("GET", "/duo_workflows/workflows/9")
PRIVS = ("GET", "/duo_workflows/workflows/agent_privileges")


class FakeResp:
    def __init__(self, status=200, payload=None, text=""):
        self.status_code = status
        self._payload = {} if payload is None else payload
        self.text = text

    def json(self):
        return self._payload


class FakeHTTP:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def request(self, method, url, headers=None, json=None, timeout=None):
        self.calls.append((method, url))
        for (m, suffix), resp in self.routes.items():
            if m == method and url.endswith(suffix):
                return resp
        return FakeResp(404, {"message": "not found"})


def test_check_access_needs_no_project_read():
    cfg = ai.load_gitlab_config(GL.get)
    http = FakeHTTP({PRIVS: FakeResp(200, {"all_privileges": []})})
    ok, msg = ai.check_access(cfg, http=http)
    assert ok and "Flows API" in msg and "only proven when one starts" in msg
    assert all("/projects/" not in url for _, url in http.calls)


def test_error_carries_the_http_status_without_the_token():
    cfg = ai.load_gitlab_config(GL.get)
    http = FakeHTTP({STATUS: FakeResp(500, {"message": "boom GLTOKEN"})})
    with pytest.raises(ai.GitLabAIError) as exc:
        ai.get_session(cfg, 9, http=http)
    assert exc.value.status == 500 and "GLTOKEN" not in str(exc.value)


@pytest.mark.parametrize("code", [401, 403])
def test_unreadable_status_is_unknown_only_when_the_token_is_otherwise_valid(code):
    cfg = ai.load_gitlab_config(GL.get)
    valid = FakeHTTP({STATUS: FakeResp(code, {"message": "denied"}), PRIVS: FakeResp(200, {})})
    session = ai.get_session(cfg, 9, http=valid, started_at="2026-10-27T09:25:00+00:00")
    assert (session.id, session.status, session.started_at) == (9, "unknown", "2026-10-27T09:25:00+00:00")
    assert ai.describe_status("unknown")[0] == "warn"
    rejected = FakeHTTP({STATUS: FakeResp(code, {"message": "denied GLTOKEN"})})
    with pytest.raises(ai.GitLabAIError) as exc:
        ai.get_session(cfg, 9, http=rejected)
    assert exc.value.status == code and "GLTOKEN" not in str(exc.value)


def _app():
    import streamlit as st

    from dashboard import state
    from dashboard.views_workflow import _gitlab_card
    from devsecops_agent import ai
    from devsecops_agent.models import utc_now

    state.init_state()
    S = st.session_state
    if S.duo_session is None:
        S.duo_session = ai.GitLabSession(9, "https://gitlab.com/g/p/-/automate/agent-sessions/9", "created", utc_now())
        S.duo_scope = "demo, 1 finding(s)"
        S.duo_via = "agent"
    _gitlab_card()


def test_partial_message_is_labelled_and_replaced_by_the_final_answer(monkeypatch):
    for key, value in GL.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(ai, "get_session",
                        lambda cfg, sid, http=None, started_at="": ai.GitLabSession(sid, "", "unknown", started_at))
    monkeypatch.setattr(ai, "get_final_answer", lambda cfg, sid, http=None: "Partial analysis")
    at = AppTest.from_function(_app, default_timeout=30).run()
    at.button(key="gl_refresh").click().run()
    assert not at.exception
    S = at.session_state
    assert S["duo_partial"] is True and S["duo_answer"] == "Partial analysis"
    assert S["duo_session"].web_url == SESSION_URL and "completion cannot be confirmed" in S["duo_msg"]
    text = " ".join(m.value for m in at.markdown)
    assert "latest agent message (completion not confirmed)" in text
    assert "LIVE: answer from the GitLab Duo agent" not in text

    monkeypatch.setattr(ai, "get_session",
                        lambda cfg, sid, http=None, started_at="": ai.GitLabSession(sid, SESSION_URL, "finished", started_at))
    monkeypatch.setattr(ai, "get_final_answer", lambda cfg, sid, http=None: "Final analysis")
    at.button(key="gl_refresh").click().run()
    assert not at.exception
    assert S["duo_partial"] is False and S["duo_answer"] == "Final analysis" and S["duo_msg"] == ""
    assert "LIVE: answer from the GitLab Duo agent" in " ".join(m.value for m in at.markdown)


def test_unknown_status_with_no_trace_message_shows_no_answer(monkeypatch):
    for key, value in GL.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(ai, "get_session",
                        lambda cfg, sid, http=None, started_at="": ai.GitLabSession(sid, "", "unknown", started_at))
    monkeypatch.setattr(ai, "get_final_answer", lambda cfg, sid, http=None: "")
    at = AppTest.from_function(_app, default_timeout=30).run()
    at.button(key="gl_refresh").click().run()
    assert not at.exception
    assert at.session_state["duo_answer"] == "" and at.session_state["duo_partial"] is False

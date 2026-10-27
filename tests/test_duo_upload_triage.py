import json

from streamlit.testing.v1 import AppTest

from devsecops_agent import ai
from devsecops_agent.scanners import scan_project

GL = {"GITLAB_AI_TOKEN": "GLTOKEN", "GITLAB_AI_PROJECT_ID": "123"}
SESSION_URL = "https://gitlab.com/g/p/-/automate/agent-sessions/9"
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
TRACE = "/duo_workflows/workflows/9/trace.jsonl"


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
        self.calls.append((method, url, headers, json))
        for (m, suffix), resp in self.routes.items():
            if m == method and url.endswith(suffix):
                return resp
        return FakeResp(404, {"message": "not found"})


def sample_scan():
    return scan_project({"app.py": f'KEY = "{FAKE_AWS}"\nx = eval(s)\n', "cfg.py": "d = yaml.load(f)\n"})


def test_goal_is_scoped_to_the_uploaded_project_and_hides_secrets():
    scan = sample_scan()
    ctx = ai.upload_context("my proj/../x", "ZIP upload", 2, "live", scan)
    assert "/" not in ctx["project"] and ctx["counts"]["critical"] == 1 and ctx["files"] == 2
    assert any("External SAST" in n for n in ctx["not_run"])
    goal = ai.build_goal(scan.findings, context=ctx)
    assert "UPLOADED project" in goal and "NOT in this GitLab repository" in goal and "cannot read its files" in goal
    assert "Analysis of uploaded project" in goal and "my-proj" in goal
    assert FAKE_AWS not in goal and "PY-EVAL" in goal and "Read-only" in goal and "untrusted" in goal
    assert "UPLOADED" not in ai.build_goal(scan.findings)


def test_goal_says_how_many_findings_were_listed():
    scan = sample_scan()
    ctx = ai.upload_context("p", "ZIP upload", 2, "live", scan)
    assert "3 findings, all listed" in ai.build_goal(scan.findings, context=ctx)
    assert "first 1 listed" in ai.build_goal(scan.findings, limit=1, context=ctx)


def test_submit_triage_sends_the_findings_with_read_only_privileges():
    cfg = ai.load_gitlab_config(GL.get)
    http = FakeHTTP({("POST", "/ai/duo_workflows/workflows"): FakeResp(201, {"id": 9, "web_url": SESSION_URL, "status": "created"})})
    scan = sample_scan()
    session = ai.submit_triage(cfg, scan.findings, http=http, context=ai.upload_context("p", "ZIP upload", 2, "live", scan))
    payload = http.calls[0][3]
    assert payload["agent_privileges"] == [2] and payload["allow_agent_to_request_user"] is False
    assert "UPLOADED project" in payload["goal"] and "ai_catalog_item_consumer_id" not in payload
    assert session.id == 9 and session.started_at


def test_final_answer_is_the_last_non_empty_ai_message_of_the_trace():
    cfg = ai.load_gitlab_config(GL.get)
    lines = [
        json.dumps({"message_type": "human", "content": "goal text"}),
        json.dumps({"message_type": "ai", "content": "I will read the findings."}),
        json.dumps({"message_type": "tool", "content": "tool output"}),
        json.dumps({"message_type": "ai", "content": [{"type": "text", "text": "Analysis of uploaded project p"}]}),
        json.dumps({"message_type": "ai", "content": ""}),
        "not json",
    ]
    http = FakeHTTP({("GET", TRACE): FakeResp(200, text="\n".join(lines))})
    assert ai.get_final_answer(cfg, 9, http=http) == "Analysis of uploaded project p"
    none = FakeHTTP({("GET", TRACE): FakeResp(200, text=json.dumps({"message_type": "human", "content": "x"}))})
    assert ai.get_final_answer(cfg, 9, http=none) == ""


def _card_app():
    import streamlit as st

    from dashboard import state
    from dashboard.views_workflow import _gitlab_card
    from devsecops_agent import ai

    state.init_state()
    S = st.session_state
    S.duo_session = ai.GitLabSession(9, "https://gitlab.com/g/p/-/automate/agent-sessions/9", "finished",
                                     "2026-10-27T09:25:00+00:00")
    S.duo_scope = "demo, 3 finding(s)"
    S.duo_answer = "Analysis of uploaded project demo\n\nRotate the credential first."
    _gitlab_card()


def test_card_shows_real_status_and_the_answer_scoped_to_the_findings(monkeypatch):
    for key, value in GL.items():
        monkeypatch.setenv(key, value)
    at = AppTest.from_function(_card_app, default_timeout=30).run()
    assert not at.exception
    text = " ".join(m.value for m in at.markdown)
    assert "Finished" in text and "LIVE: answer from the GitLab Duo agent" in text
    assert "Rotate the credential first" in text and "could not read the code" in text
    assert at.button(key="gl_submit") and at.button(key="gl_refresh") and at.button(key="gl_test")


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


def test_buttons_send_the_findings_and_keep_the_answer_with_its_session(monkeypatch):
    for key, value in GL.items():
        monkeypatch.setenv(key, value)
    seen = {}

    def fake_submit(cfg, findings, http=None, context=None):
        seen["context"], seen["count"] = context, len(findings)
        return ai.GitLabSession(9, SESSION_URL, "created", "2026-10-27T09:25:00+00:00")

    monkeypatch.setattr(ai, "submit_triage", fake_submit)
    monkeypatch.setattr(ai, "get_session",
                        lambda cfg, sid, http=None, started_at="": ai.GitLabSession(sid, SESSION_URL, "finished", started_at))
    monkeypatch.setattr(ai, "get_final_answer", lambda cfg, sid, http=None: "Analysis of uploaded project demo\nadvice")
    at = AppTest.from_function(_wired_app, default_timeout=30).run()
    assert not at.exception
    at.button(key="gl_submit").click().run()
    assert at.session_state["duo_session"].id == 9 and at.session_state["duo_answer"] == ""
    assert seen["context"]["project"] == "demo" and seen["count"] == 1
    at.button(key="gl_refresh").click().run()
    assert at.session_state["duo_answer"].startswith("Analysis of uploaded project demo")
    assert "LIVE: answer from the GitLab Duo agent" in " ".join(m.value for m in at.markdown)
    assert [e["action"] for e in at.session_state["audit"]].count("gitlab_duo_answer") == 1

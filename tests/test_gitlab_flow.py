from datetime import datetime, timezone

import pytest
import requests
from streamlit.testing.v1 import AppTest

from devsecops_agent import ai

GL = {"GITLAB_AI_TOKEN": "GLTOKEN", "GITLAB_AI_PROJECT_ID": "123", "GITLAB_AI_CONSUMER_ID": "77", "GITLAB_AI_MR_IID": "2"}
SESSION_URL = "https://gitlab.com/g/p/-/automate/agent-sessions/9"
NOTES = "/api/v4/projects/123/merge_requests/2/notes?sort=desc&order_by=created_at&per_page=50"


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
                if isinstance(resp, Exception):
                    raise resp
                return resp
        return FakeResp(404, {"message": "not found"})


def note(note_id, author_id, created, body="triage text", system=False, name="Flow bot"):
    return {"id": note_id, "system": system, "body": body, "created_at": created,
            "author": {"id": author_id, "name": name, "username": "bot"}}


def test_flow_config_validation_and_status_text():
    cfg = ai.load_gitlab_config(GL.get)
    assert cfg.consumer_id == "77" and cfg.mr_iid == "2" and "GLTOKEN" not in repr(cfg)
    assert ai.load_gitlab_config({**GL, "GITLAB_AI_CONSUMER_ID": "abc"}.get) is None
    assert ai.load_gitlab_config({**GL, "GITLAB_AI_MR_IID": "x"}.get) is None
    assert "existing AI Catalog flow" in ai.gitlab_status(GL.get).detail
    bad = ai.gitlab_status({**GL, "GITLAB_AI_CONSUMER_ID": "abc"}.get)
    assert bad.state == "unconfigured" and any("CONSUMER_ID" in m for m in bad.missing)


def test_submit_flow_runs_the_catalog_flow_and_never_sends_an_agent_definition():
    cfg = ai.load_gitlab_config(GL.get)
    http = FakeHTTP({("POST", "/ai/duo_workflows/workflows"): FakeResp(201, {"id": 9, "web_url": SESSION_URL, "status": "created"})})
    session = ai.submit_flow(cfg, "!2", http=http)
    assert (session.id, session.status, session.web_url) == (9, "created", SESSION_URL) and session.started_at
    method, url, headers, payload = http.calls[0]
    assert method == "POST" and headers["PRIVATE-TOKEN"] == "GLTOKEN"
    assert payload == {"project_id": 123, "ai_catalog_item_consumer_id": 77, "goal": "2", "start_workflow": True}


def test_submit_flow_input_and_error_handling_never_leaks_the_token():
    cfg = ai.load_gitlab_config(GL.get)
    with pytest.raises(ai.GitLabAIError):
        ai.submit_flow(cfg, "not a number", http=FakeHTTP({}))
    no_flow = ai.load_gitlab_config({k: v for k, v in GL.items() if k != "GITLAB_AI_CONSUMER_ID"}.get)
    with pytest.raises(ai.GitLabAIError):
        ai.submit_flow(no_flow, "2", http=FakeHTTP({}))
    route = ("POST", "/ai/duo_workflows/workflows")
    for status, word in ((401, "rejected"), (403, "Developer"), (404, "not found"), (429, "rate")):
        http = FakeHTTP({route: FakeResp(status, {"message": "denied GLTOKEN"})})
        with pytest.raises(ai.GitLabAIError) as exc:
            ai.submit_flow(cfg, "2", http=http)
        assert word in str(exc.value) and str(status) in str(exc.value) and "GLTOKEN" not in str(exc.value)
    slow = FakeHTTP({route: requests.exceptions.Timeout()})
    with pytest.raises(ai.GitLabAIError) as exc:
        ai.submit_flow(cfg, "2", http=slow)
    assert "did not answer" in str(exc.value)
    odd = FakeHTTP({route: FakeResp(201, {"status": "created"})})
    with pytest.raises(ai.GitLabAIError):
        ai.submit_flow(cfg, "2", http=odd)


def test_fetch_flow_result_matches_by_time_and_author_only():
    cfg = ai.load_gitlab_config(GL.get)
    session = ai.GitLabSession(9, SESSION_URL, "finished", "2026-10-27T09:25:00+00:00")
    notes = [
        note(6, 1, "2026-10-27T09:27:00.000Z", body="my own comment", name="Me"),
        note(5, 50, "2026-10-27T09:26:10.417Z", body="## Security triage"),
        note(4, 50, "2026-10-27T09:26:00.000Z", body="system", system=True),
        note(3, 50, "2026-10-27T09:00:00.000Z", body="an older run"),
    ]
    http = FakeHTTP({("GET", "/api/v4/user"): FakeResp(200, {"id": 1}), ("GET", NOTES): FakeResp(200, notes)})
    result = ai.fetch_flow_result(cfg, session, "2", http=http)
    assert result.body == "## Security triage" and result.author == "Flow bot"
    assert result.note_url == "https://gitlab.com/g/p/-/merge_requests/2#note_5"
    only_old = FakeHTTP({("GET", "/api/v4/user"): FakeResp(200, {"id": 1}), ("GET", NOTES): FakeResp(200, notes[:1] + notes[2:])})
    assert ai.fetch_flow_result(cfg, session, "2", http=only_old) is None
    with pytest.raises(ai.GitLabAIError):
        ai.fetch_flow_result(cfg, ai.GitLabSession(9, SESSION_URL, "finished", ""), "2", http=http)


def test_status_labels_and_slow_session_age():
    assert ai.describe_status("finished") == ("ok", "Finished")
    assert ai.describe_status("failed")[0] == "bad" and ai.describe_status("weird") == ("muted", "weird")
    running = ai.GitLabSession(1, "", "running", "2026-10-27T09:00:00+00:00")
    now = datetime(2026, 10, 27, 9, 30, tzinfo=timezone.utc)
    assert ai.session_age_minutes(running, now=now) == 30
    assert ai.session_age_minutes(ai.GitLabSession(1, "", "running"), now=now) == 0


def _card_app():
    import streamlit as st

    from dashboard import state
    from dashboard.views_workflow import _gitlab_flow_card
    from devsecops_agent import ai

    state.init_state()
    S = st.session_state
    S.gitlab_session = ai.GitLabSession(9, "https://gitlab.com/g/p/-/automate/agent-sessions/9", "finished",
                                        "2026-10-27T09:25:00+00:00")
    S.gitlab_kind, S.gitlab_mr = "flow", "2"
    S.gitlab_result = ai.FlowResult("## Triage result\n\nNo findings.", "Flow bot", "2026-10-27T09:26:10Z",
                                    "https://gitlab.com/g/p/-/merge_requests/2#note_5")
    _gitlab_flow_card()


def test_flow_card_shows_real_status_result_and_controls(monkeypatch):
    for key, value in GL.items():
        monkeypatch.setenv(key, value)
    at = AppTest.from_function(_card_app, default_timeout=30).run()
    assert not at.exception
    text = " ".join(m.value for m in at.markdown)
    assert "Finished" in text and "LIVE: comment posted by the GitLab Duo flow" in text and "Triage result" in text
    assert at.button(key="gl_run") and at.button(key="gl_refresh_flow") and at.button(key="gl_test")
    assert at.text_input(key="gl_mr").value == "2"

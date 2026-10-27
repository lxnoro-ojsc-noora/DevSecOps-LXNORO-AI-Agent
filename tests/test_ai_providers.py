import json

import pytest

from devsecops_agent import ai
from devsecops_agent.scanners import scan_project

FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


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


def test_openai_compatible_defaults_and_https_enforced():
    base = {"AI_PROVIDER": "openai", "AI_API_KEY": "k", "AI_MODEL": "m"}
    cfg = ai.load_config(base.get)
    assert cfg.endpoint == "https://api.openai.com/v1"
    assert ai.load_config({**base, "AI_ENDPOINT": "http://insecure.example/v1"}.get) is None
    assert ai.load_config({**base, "AI_ENDPOINT": "https://user:pw@evil.example/v1"}.get) is None
    custom = ai.load_config({**base, "AI_PROVIDER": "openai-compatible", "AI_ENDPOINT": "https://llm.example/v1/"}.get)
    assert custom.endpoint == "https://llm.example/v1"


def test_openai_request_shape_and_secret_hidden():
    cfg = ai.AIConfig("openai", "gpt-x", "SECRETKEY", "https://llm.example/v1")
    findings = scan_project({"c.py": f'K = "{FAKE_AWS}"\n'}).findings
    seen = {}

    def post(url, headers, payload, timeout):
        seen.update(url=url, headers=headers, payload=payload)
        return {"choices": [{"message": {"content": "Because X."}}]}

    res = ai.explain_findings(cfg, findings, post=post)
    assert res.ok and seen["url"] == "https://llm.example/v1/chat/completions"
    assert seen["headers"]["Authorization"] == "Bearer SECRETKEY"
    assert FAKE_AWS not in json.dumps(seen["payload"]) and "SECRETKEY" not in repr(cfg)


def test_external_status_reports_missing_settings():
    st = ai.external_status({}.get)
    assert st.state == "unconfigured" and set(st.missing) >= {"AI_PROVIDER", "AI_API_KEY", "AI_MODEL"}
    ready = ai.external_status({"AI_PROVIDER": "gemini", "AI_API_KEY": "k", "AI_MODEL": "m"}.get)
    assert ready.state == "ready" and "Not verified" in ready.detail


GL = {"GITLAB_AI_TOKEN": "GLTOKEN", "GITLAB_AI_PROJECT_ID": "123"}


def test_gitlab_config_validation():
    cfg = ai.load_gitlab_config(GL.get)
    assert cfg and cfg.base_url == "https://gitlab.com" and cfg.workflow_definition == "security_analyst_agent/v1"
    assert "GLTOKEN" not in repr(cfg)
    assert ai.load_gitlab_config({**GL, "GITLAB_AI_PROJECT_ID": "group/project"}.get) is None
    assert ai.load_gitlab_config({**GL, "GITLAB_URL": "http://gitlab.example"}.get) is None
    assert ai.load_gitlab_config({**GL, "GITLAB_AI_WORKFLOW_DEFINITION": "bad value"}.get) is None
    assert ai.load_gitlab_config({}.get) is None


def test_gitlab_goal_is_read_only_and_has_no_raw_secret():
    findings = scan_project({"c.py": f'K = "{FAKE_AWS}"\nx = eval(s)\n'}).findings
    goal = ai.build_goal(findings)
    assert FAKE_AWS not in goal and "Read-only" in goal and "untrusted" in goal
    assert "Do not modify code" in goal


def test_submit_triage_requests_read_only_privileges():
    cfg = ai.load_gitlab_config(GL.get)
    http = FakeHTTP({("POST", "/ai/duo_workflows/workflows"): FakeResp(
        201, {"id": 9, "web_url": "https://gitlab.com/g/p/-/automate/agent-sessions/9", "status": "running"})})
    findings = scan_project({"a.py": "x = eval(s)\n"}).findings
    session = ai.submit_triage(cfg, findings, http=http)
    assert (session.id, session.status) == (9, "running") and session.web_url.startswith("https://gitlab.com/")
    method, url, headers, payload = http.calls[0]
    assert method == "POST" and url == "https://gitlab.com/api/v4/ai/duo_workflows/workflows"
    assert payload["agent_privileges"] == [2] and payload["start_workflow"] is True
    assert payload["project_id"] == 123 and headers["PRIVATE-TOKEN"] == "GLTOKEN"


def test_submit_triage_rejects_foreign_web_url_and_scrubs_errors():
    cfg = ai.load_gitlab_config(GL.get)
    findings = scan_project({"a.py": "x = eval(s)\n"}).findings
    http = FakeHTTP({("POST", "/ai/duo_workflows/workflows"): FakeResp(201, {"id": 1, "web_url": "https://evil.example/x"})})
    assert ai.submit_triage(cfg, findings, http=http).web_url == ""
    bad = FakeHTTP({("POST", "/ai/duo_workflows/workflows"): FakeResp(403, {"message": "denied GLTOKEN"})})
    with pytest.raises(ai.GitLabAIError) as exc:
        ai.submit_triage(cfg, findings, http=bad)
    assert "GLTOKEN" not in str(exc.value) and "403" in str(exc.value)


def test_check_access_get_session_and_output():
    cfg = ai.load_gitlab_config(GL.get)
    http = FakeHTTP({
        ("GET", "/api/v4/projects/123"): FakeResp(200, {"path_with_namespace": "g/p"}),
        ("GET", "/duo_workflows/workflows/9"): FakeResp(200, {"id": 9, "status": "finished", "web_url": "https://gitlab.com/g/p/-/x"}),
        ("GET", "/duo_workflows/workflows/9/trace.jsonl"): FakeResp(200, text='{"content": "first"}\nnot json\n{"content": "second"}\n'),
    })
    ok, msg = ai.check_access(cfg, http=http)
    assert ok and "g/p" in msg
    assert ai.get_session(cfg, 9, http=http).status == "finished"
    assert ai.get_output(cfg, 9, http=http) == ["first", "second"]
    ok, msg = ai.check_access(cfg, http=FakeHTTP({}))
    assert not ok and "404" in msg


def test_registry_lists_all_options_with_truthful_states():
    statuses = {s.id: s for s in ai.provider_statuses({}.get)}
    assert statuses["none"].state == "ready"
    assert statuses["external"].state == "unconfigured" and statuses["gitlab"].state == "unconfigured"
    assert statuses["gitlab-chat"].state == "unsupported"
    full = {**GL, "AI_PROVIDER": "anthropic", "AI_API_KEY": "k", "AI_MODEL": "m"}
    both = {s.id: s for s in ai.provider_statuses(full.get)}
    assert both["external"].state == "ready" and both["gitlab"].state == "ready"

from devsecops_agent import ai

GL = {"GITLAB_AI_TOKEN": "GLTOKEN", "GITLAB_AI_PROJECT_ID": "123"}
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


def test_access_test_uses_flows_api_only_and_reports_every_exact_error():
    cfg = ai.load_gitlab_config(GL.get)
    http = FakeHTTP({PRIVS: FakeResp(403, {"message": "insufficient_scope GLTOKEN"})})
    ok, msg = ai.check_access(cfg, http=http)
    assert not ok and "HTTP 403" in msg and "HTTP 404" in msg and "GLTOKEN" not in msg
    assert all("/ai/duo_workflows/" in u or "/api/v4/projects/" in u for _, u in http.calls)
    assert not any("chat" in u for _, u in http.calls)


def test_flows_read_failure_is_still_reported_when_project_read_works():
    cfg = ai.load_gitlab_config(GL.get)
    http = FakeHTTP({PRIVS: FakeResp(403, {"message": "denied"}),
                     ("GET", "/api/v4/projects/123"): FakeResp(200, {"path_with_namespace": "g/p"})})
    ok, msg = ai.check_access(cfg, http=http)
    assert ok and "g/p" in msg and "HTTP 403" in msg and "unverified" in msg


def test_no_unsupported_chat_provider_is_offered():
    assert "gitlab-chat" not in {s.id for s in ai.provider_statuses({}.get)}
    assert not hasattr(ai, "chat_api_status")

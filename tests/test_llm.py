import pytest
import requests

from devsecops_agent.ai import AIConfig
from devsecops_agent.ai import llm

ANTHROPIC = AIConfig("anthropic", "m", "SECRETKEY")
OPENAI = AIConfig("openai", "m", "SECRETKEY", "https://llm.example/v1")
GEMINI = AIConfig("gemini", "g", "SECRETKEY")


def http_error(status):
    resp = requests.Response()
    resp.status_code = status
    return requests.exceptions.HTTPError(response=resp)


def test_complete_builds_each_providers_official_request():
    seen = {}

    def post(url, headers, payload, timeout):
        seen.update(url=url, headers=headers, payload=payload, timeout=timeout)
        return {"content": [{"type": "text", "text": "hi"}]}

    assert llm.complete(ANTHROPIC, "sys", "p", post=post) == "hi"
    assert seen["url"] == "https://api.anthropic.com/v1/messages" and seen["headers"]["x-api-key"] == "SECRETKEY"
    assert seen["payload"]["system"] == "sys" and seen["timeout"] == llm.TIMEOUT

    def post2(url, headers, payload, timeout):
        seen.update(url=url, headers=headers, payload=payload)
        return {"choices": [{"message": {"content": "ok"}}]}

    assert llm.complete(OPENAI, "sys", "p", post=post2) == "ok"
    assert seen["url"] == "https://llm.example/v1/chat/completions"
    assert seen["headers"]["Authorization"] == "Bearer SECRETKEY"

    def post3(url, headers, payload, timeout):
        seen.update(url=url, headers=headers, payload=payload)
        return {"candidates": [{"content": {"parts": [{"text": "g"}]}}]}

    assert llm.complete(GEMINI, "sys", "p", post=post3) == "g"
    assert "g:generateContent" in seen["url"] and "x-goog-api-key" in seen["headers"]


def test_timeout_is_retried_once_then_reported_without_fabricating_an_answer():
    calls = []

    def post(url, headers, payload, timeout):
        calls.append(1)
        raise requests.exceptions.Timeout("slow SECRETKEY")

    sleeps = []
    with pytest.raises(llm.AIError) as exc:
        llm.complete(ANTHROPIC, "s", "p", post=post, sleep=sleeps.append)
    assert exc.value.kind == "timeout" and len(calls) == 2 and len(sleeps) == 1
    assert "SECRETKEY" not in str(exc.value)


def test_transient_failure_recovers_on_retry():
    state = {"n": 0}

    def post(url, headers, payload, timeout):
        state["n"] += 1
        if state["n"] == 1:
            raise http_error(503)
        return {"content": [{"type": "text", "text": "recovered"}]}

    assert llm.complete(ANTHROPIC, "s", "p", post=post, sleep=lambda s: None) == "recovered"


@pytest.mark.parametrize("status,kind", [(401, "auth"), (403, "auth"), (404, "not_found"), (400, "http")])
def test_non_transient_http_errors_are_not_retried(status, kind):
    calls = []

    def post(url, headers, payload, timeout):
        calls.append(1)
        raise http_error(status)

    with pytest.raises(llm.AIError) as exc:
        llm.complete(ANTHROPIC, "s", "p", post=post, sleep=lambda s: None)
    assert exc.value.kind == kind and len(calls) == 1


def test_rate_limit_and_connection_errors_are_classified():
    def limited(url, headers, payload, timeout):
        raise http_error(429)

    def down(url, headers, payload, timeout):
        raise requests.exceptions.ConnectionError("x")

    with pytest.raises(llm.AIError) as a:
        llm.complete(ANTHROPIC, "s", "p", post=limited, retries=0)
    with pytest.raises(llm.AIError) as b:
        llm.complete(ANTHROPIC, "s", "p", post=down, retries=0)
    assert (a.value.kind, b.value.kind) == ("rate_limit", "network")


def test_malformed_or_empty_responses_are_bad_response():
    with pytest.raises(llm.AIError) as a:
        llm.complete(ANTHROPIC, "s", "p", post=lambda *args: {"unexpected": 1}, retries=0)
    with pytest.raises(llm.AIError) as b:
        llm.complete(ANTHROPIC, "s", "p", post=lambda *args: {"content": [{"type": "text", "text": "  "}]}, retries=0)
    assert a.value.kind == "bad_response" and b.value.kind == "bad_response"


def test_ping_reports_success_and_failure_truthfully():
    ok = llm.ping(ANTHROPIC, post=lambda *args: {"content": [{"type": "text", "text": "OK"}]})
    assert ok.ok and ok.kind == "ok" and "answered" in ok.message

    def bad(url, headers, payload, timeout):
        raise http_error(401)

    failed = llm.ping(ANTHROPIC, post=bad)
    assert not failed.ok and failed.kind == "auth" and "SECRETKEY" not in failed.message

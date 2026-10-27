"""Unified, provider-neutral LLM completion over each provider's official HTTP API.

Timeouts are explicit, one retry is made for transient failures, and every failure becomes an
AIError with a machine-readable kind. Messages never echo request data, headers or keys, and a
failed live request is never silently replaced by a simulated answer.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import requests

from .external import AIConfig, _extract

TIMEOUT = (5, 45)  # connect and read seconds
TRANSIENT = ("timeout", "network", "rate_limit", "server")


class AIError(RuntimeError):
    """A live AI request failed. `kind` is machine-readable; the message is safe to display."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


def build_request(cfg: AIConfig, system: str, prompt: str, max_tokens: int):
    if cfg.provider == "anthropic":
        return (
            "https://api.anthropic.com/v1/messages",
            {"x-api-key": cfg.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            {"model": cfg.model, "max_tokens": max_tokens, "system": system,
             "messages": [{"role": "user", "content": prompt}]},
        )
    if cfg.provider == "openai":
        return (
            f"{cfg.endpoint}/chat/completions",
            {"Authorization": f"Bearer {cfg.api_key}", "content-type": "application/json"},
            {"model": cfg.model,
             "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]},
        )
    return (
        f"https://generativelanguage.googleapis.com/v1beta/models/{cfg.model}:generateContent",
        {"x-goog-api-key": cfg.api_key, "content-type": "application/json"},
        {"system_instruction": {"parts": [{"text": system}]},
         "contents": [{"role": "user", "parts": [{"text": prompt}]}],
         "generationConfig": {"maxOutputTokens": max_tokens}},
    )


def _default_post(url, headers, payload, timeout):
    resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _http_error(status: int) -> AIError:
    if status in (401, 403):
        return AIError("auth", "The provider rejected the credentials, or this model or plan is not permitted.")
    if status == 404:
        return AIError("not_found", "The model or endpoint was not found.")
    if status == 429:
        return AIError("rate_limit", "The provider rate-limited the request.")
    if status >= 500:
        return AIError("server", "The provider reported a server error.")
    return AIError("http", f"The provider returned HTTP {status}.")


def complete(cfg: AIConfig, system: str, prompt: str, max_tokens: int = 900, post=None,
             retries: int = 1, sleep=time.sleep) -> str:
    post = post or _default_post
    url, headers, payload = build_request(cfg, system, prompt, max_tokens)
    attempt = 0
    while True:
        try:
            text = _extract(cfg, post(url, headers, payload, TIMEOUT))
            if not str(text).strip():
                raise AIError("bad_response", "The provider returned an empty response.")
            return str(text)
        except AIError as exc:
            err = exc
        except requests.exceptions.Timeout:
            err = AIError("timeout", "The provider did not answer in time.")
        except requests.exceptions.ConnectionError:
            err = AIError("network", "Could not reach the provider.")
        except requests.exceptions.HTTPError as exc:
            err = _http_error(int(getattr(exc.response, "status_code", 0) or 0))
        except (KeyError, IndexError, TypeError, ValueError):
            err = AIError("bad_response", "The provider returned an unexpected response shape.")
        if err.kind in TRANSIENT and attempt < retries:
            attempt += 1
            sleep(2 * attempt)
            continue
        raise err


@dataclass(frozen=True)
class HealthResult:
    ok: bool
    kind: str
    message: str
    latency_ms: int = 0


def ping(cfg: AIConfig, post=None) -> HealthResult:
    """One tiny real request that proves credentials, model and network work together."""
    started = time.monotonic()
    try:
        complete(cfg, "You are a connectivity probe.", "Reply with the single word OK.", max_tokens=16,
                 post=post, retries=0)
    except AIError as exc:
        return HealthResult(False, exc.kind, str(exc))
    return HealthResult(True, "ok", f"{cfg.label} answered.", int((time.monotonic() - started) * 1000))

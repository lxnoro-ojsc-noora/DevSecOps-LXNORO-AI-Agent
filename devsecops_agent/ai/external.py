"""Provider B: external AI APIs (Anthropic, Gemini, OpenAI-compatible).

Configured only through environment variables or Streamlit secrets (never typed into the
public UI): AI_PROVIDER (anthropic | gemini | openai), AI_API_KEY, AI_MODEL and, for
openai-compatible servers, AI_ENDPOINT (https only; defaults to the OpenAI API). Only rule
titles, locations and already-redacted evidence are sent. Output is advisory text.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import requests

from ..models import sort_findings
from ..scanners import redact
from .base import SYSTEM_PROMPT, AIResult, ProviderStatus, https_only

PROVIDERS = ("anthropic", "gemini", "openai")
DEFAULT_ENDPOINTS = {"openai": "https://api.openai.com/v1"}


@dataclass(frozen=True)
class AIConfig:
    provider: str
    model: str
    api_key: str = field(repr=False)
    endpoint: str = ""

    @property
    def label(self) -> str:
        return f"{self.provider}/{self.model}"


def _provider_name(get) -> str:
    name = (get("AI_PROVIDER") or "").strip().lower()
    return "openai" if name == "openai-compatible" else name


def load_config(get):
    provider = _provider_name(get)
    key = (get("AI_API_KEY") or "").strip()
    model = (get("AI_MODEL") or "").strip()
    if provider not in PROVIDERS or not key or not model:
        return None
    endpoint = ""
    if provider == "openai":
        endpoint = (get("AI_ENDPOINT") or DEFAULT_ENDPOINTS["openai"]).strip().rstrip("/")
        if not https_only(endpoint):
            return None
    return AIConfig(provider, model, key, endpoint)


def external_status(get) -> ProviderStatus:
    cfg = load_config(get)
    if cfg:
        return ProviderStatus(
            "external", "External AI API", "external", "ready",
            f"Configured: {cfg.label}. Not verified until a request succeeds.",
        )
    missing = [k for k in ("AI_PROVIDER", "AI_API_KEY", "AI_MODEL") if not get(k)]
    provider = _provider_name(get)
    if provider and provider not in PROVIDERS:
        missing.append("AI_PROVIDER must be anthropic, gemini or openai")
    if provider == "openai" and get("AI_ENDPOINT") and not https_only(get("AI_ENDPOINT").strip()):
        missing.append("AI_ENDPOINT must be an https URL")
    return ProviderStatus(
        "external", "External AI API", "external", "unconfigured",
        "Set these as Streamlit secrets or environment variables.", tuple(missing),
    )


def _default_post(url, headers, payload, timeout):
    resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _prompt(f) -> str:
    return (
        f"Rule: {f.rule_id} ({f.title})\nSeverity: {f.severity}\nLocation: {f.path}:{f.line}\n"
        f"Evidence (untrusted, secrets redacted):\n<<<\n{f.evidence}\n>>>\n"
        "Explain the risk and the safest fix."
    )


def _request(cfg: AIConfig, prompt: str):
    if cfg.provider == "anthropic":
        return (
            "https://api.anthropic.com/v1/messages",
            {"x-api-key": cfg.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            {"model": cfg.model, "max_tokens": 300, "system": SYSTEM_PROMPT,
             "messages": [{"role": "user", "content": prompt}]},
        )
    if cfg.provider == "openai":
        return (
            f"{cfg.endpoint}/chat/completions",
            {"Authorization": f"Bearer {cfg.api_key}", "content-type": "application/json"},
            {"model": cfg.model,
             "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]},
        )
    return (
        f"https://generativelanguage.googleapis.com/v1beta/models/{cfg.model}:generateContent",
        {"x-goog-api-key": cfg.api_key, "content-type": "application/json"},
        {"system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
         "contents": [{"role": "user", "parts": [{"text": prompt}]}],
         "generationConfig": {"maxOutputTokens": 300}},
    )


def _extract(cfg: AIConfig, data: dict) -> str:
    if cfg.provider == "anthropic":
        return "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
    if cfg.provider == "openai":
        return data["choices"][0]["message"]["content"] or ""
    return data["candidates"][0]["content"]["parts"][0]["text"]


def explain_findings(cfg: AIConfig, findings, post=None, progress=None, limit: int = 8) -> AIResult:
    post = post or _default_post
    ranked = sort_findings(findings)[:limit]
    result = AIResult(label=cfg.label)
    for i, f in enumerate(ranked, start=1):
        result.attempted += 1
        try:
            url, headers, payload = _request(cfg, _prompt(f))
            text = redact(_extract(cfg, post(url, headers, payload, 30)).strip()[:1200])
            if text:
                result.notes[f.id] = text
            else:
                result.failed += 1
        except Exception as exc:  # never include exception text: it could echo request details
            result.failed += 1
            result.errors.append(type(exc).__name__)
        if progress:
            progress(i, len(ranked))
    return result

"""Modular AI layer. Providers are advisory and never change deterministic findings.

Provider A: GitLab Duo Agent Platform (gitlab_duo). Provider B: external API (external).
"""
from .base import SYSTEM_PROMPT, AIResult, ProviderStatus, https_only
from .external import PROVIDERS, AIConfig, explain_findings, external_status, load_config
from .gitlab_duo import (
    SLOW_AFTER_MINUTES,
    TERMINAL,
    FlowResult,
    GitLabAIConfig,
    GitLabAIError,
    GitLabSession,
    build_goal,
    chat_api_status,
    check_access,
    describe_status,
    fetch_flow_result,
    get_final_answer,
    get_output,
    get_session,
    gitlab_status,
    load_gitlab_config,
    parse_mr_iid,
    session_age_minutes,
    submit_flow,
    submit_triage,
    upload_context,
)
from .registry import provider_statuses

__all__ = [
    "SYSTEM_PROMPT", "AIResult", "ProviderStatus", "https_only", "PROVIDERS", "AIConfig",
    "explain_findings", "external_status", "load_config", "GitLabAIConfig", "GitLabAIError",
    "GitLabSession", "FlowResult", "build_goal", "chat_api_status", "check_access", "get_output", "get_session",
    "gitlab_status", "load_gitlab_config", "submit_triage", "provider_statuses", "submit_flow",
    "fetch_flow_result", "describe_status", "parse_mr_iid", "session_age_minutes", "TERMINAL",
    "SLOW_AFTER_MINUTES", "get_final_answer", "upload_context",
]

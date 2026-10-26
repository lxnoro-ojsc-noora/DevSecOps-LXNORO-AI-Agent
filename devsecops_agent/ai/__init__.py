"""Modular AI layer. Providers are advisory and never change deterministic findings.

Provider A: GitLab Duo Agent Platform (gitlab_duo). Provider B: external API (external).
"""
from .base import SYSTEM_PROMPT, AIResult, ProviderStatus, https_only
from .external import PROVIDERS, AIConfig, explain_findings, external_status, load_config
from .gitlab_duo import (
    GitLabAIConfig,
    GitLabAIError,
    GitLabSession,
    build_goal,
    chat_api_status,
    check_access,
    get_output,
    get_session,
    gitlab_status,
    load_gitlab_config,
    submit_triage,
)
from .registry import provider_statuses

__all__ = [
    "SYSTEM_PROMPT", "AIResult", "ProviderStatus", "https_only", "PROVIDERS", "AIConfig",
    "explain_findings", "external_status", "load_config", "GitLabAIConfig", "GitLabAIError",
    "GitLabSession", "build_goal", "chat_api_status", "check_access", "get_output", "get_session",
    "gitlab_status", "load_gitlab_config", "submit_triage", "provider_statuses",
]

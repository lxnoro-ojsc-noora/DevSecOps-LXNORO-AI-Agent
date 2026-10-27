"""Provider registry: one place that reports which AI options exist and their real status."""
from __future__ import annotations

from .base import ProviderStatus
from .external import external_status
from .gitlab_duo import gitlab_status


def provider_statuses(get) -> list[ProviderStatus]:
    return [
        ProviderStatus("none", "Deterministic only", "builtin", "ready", "No AI. Always available."),
        external_status(get),
        gitlab_status(get),
    ]

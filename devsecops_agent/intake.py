"""Stage 1: turn an uploaded ZIP or a public GitHub repository into a validated Project."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .github_io import RepoRef, download_repo_zip, parse_repo_url
from .safe_zip import UnsafeArchiveError, extract_zip


@dataclass
class Project:
    name: str
    source: str
    text_files: dict
    binary_files: dict
    skipped: list
    repo: Optional[RepoRef] = None


def _clean_name(raw: str) -> str:
    base = re.split(r"[\\/]", raw or "")[-1]
    base = re.sub(r"\.zip$", "", base, flags=re.I)
    return re.sub(r"[^A-Za-z0-9._-]+", "-", base).strip("-.")[:80] or "project"


def _build(name, source, data, repo=None) -> Project:
    extracted = extract_zip(data)
    if not extracted.text_files:
        raise UnsafeArchiveError("No analyzable text files were found in the archive.")
    return Project(name, source, extracted.text_files, extracted.binary_files, extracted.skipped, repo)


def load_zip(filename: str, data: bytes) -> Project:
    return _build(_clean_name(filename), "ZIP upload", data)


def load_github(url: str, http=None) -> Project:
    ref = parse_repo_url(url)
    data = download_repo_zip(ref, http=http)
    return _build(ref.full_name, "GitHub import (public archive)", data, ref)

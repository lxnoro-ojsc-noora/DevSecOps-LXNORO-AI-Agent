"""GitHub import (Stage 1) and authorized publishing (Stage 5).

Import is unauthenticated and public-repository only; the repository is fetched
as an archive, never cloned or executed. Publishing uses the GitHub Git Data API
to create a NEW branch and a pull request. It never force-pushes and refuses the
default branch. Tokens are never logged, rendered or included in error text.
"""
from __future__ import annotations

import hmac
import re
from dataclasses import dataclass, field
from urllib.parse import quote

import requests

API = "https://api.github.com"
MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_REF = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
_URL = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/([^/\s]+)/([^/\s#?]+?)(?:\.git)?(?:/tree/([^\s?#]+))?/?(?:[?#].*)?$"
)
_SHORT = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$")


class GitHubError(RuntimeError):
    """A GitHub operation failed. The message never contains credentials."""


@dataclass(frozen=True)
class RepoRef:
    owner: str
    repo: str
    ref: str = ""

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"


def parse_repo_url(url: str) -> RepoRef:
    text = (url or "").strip()
    m = _URL.match(text) or _SHORT.match(text)
    if not m:
        raise GitHubError(
            "Enter a github.com repository URL such as https://github.com/owner/repository."
        )
    owner, repo = m.group(1), m.group(2)
    ref = (m.group(3) if m.re.groups >= 3 else "") or ""
    for part in (owner, repo):
        if not _NAME.match(part) or part in (".", ".."):
            raise GitHubError("The owner or repository name contains unsupported characters.")
    if ref and (not _REF.match(ref) or ".." in ref):
        raise GitHubError("The branch or tag name contains unsupported characters.")
    return RepoRef(owner, repo, ref)


def _headers(token):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "lxnoro-devsecops-agent",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _scrub(text: str, token) -> str:
    return text.replace(token, "[token]") if token else text


def download_repo_zip(ref: RepoRef, http=None, max_bytes: int = MAX_ARCHIVE_BYTES, timeout: int = 30) -> bytes:
    http = http or requests
    url = f"{API}/repos/{ref.owner}/{ref.repo}/zipball"
    if ref.ref:
        url += "/" + quote(ref.ref, safe="/")
    try:
        resp = http.get(url, headers=_headers(None), stream=True, timeout=timeout)
    except Exception as exc:
        raise GitHubError(f"Could not reach GitHub ({type(exc).__name__}).") from None
    if resp.status_code == 404:
        raise GitHubError("Repository or ref not found, or it is private. Only public repositories can be imported.")
    if resp.status_code in (401, 403):
        raise GitHubError("GitHub refused the request (rate limit or access denied). Try later or use ZIP upload.")
    if resp.status_code >= 400:
        raise GitHubError(f"GitHub returned HTTP {resp.status_code}.")
    buf = bytearray()
    for chunk in resp.iter_content(65536):
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise GitHubError("Repository archive exceeds the size limit.")
    return bytes(buf)


def _api(http, token, method, path, json=None):
    http = http or requests
    try:
        resp = http.request(method, API + path, headers=_headers(token), json=json, timeout=30)
    except Exception as exc:
        raise GitHubError(_scrub(f"Network error calling GitHub ({type(exc).__name__}).", token)) from None
    if resp.status_code >= 400:
        try:
            message = str(resp.json().get("message", ""))
        except Exception:
            message = ""
        raise GitHubError(_scrub(f"GitHub API returned {resp.status_code}: {message}", token))
    return resp.json()


@dataclass(frozen=True)
class AccessInfo:
    ok: bool
    can_push: bool
    default_branch: str
    message: str


def verify_access(token: str, repo_full_name: str, http=None) -> AccessInfo:
    try:
        data = _api(http, token, "GET", f"/repos/{repo_full_name}")
    except GitHubError as exc:
        return AccessInfo(False, False, "", str(exc))
    can_push = bool((data.get("permissions") or {}).get("push"))
    msg = "Token can push." if can_push else "Token is valid but cannot push to this repository."
    return AccessInfo(True, can_push, data.get("default_branch", ""), msg)


@dataclass(frozen=True)
class PublishResult:
    repo: str
    branch: str
    commit_sha: str
    pr_url: str
    pr_number: object = None


def publish_changes(token: str, repo_full_name: str, base_branch: str, new_branch: str,
                    changes: dict, commit_message: str, pr_title: str, pr_body: str,
                    http=None) -> PublishResult:
    if not changes:
        raise GitHubError("There are no changed files to publish.")
    if not _REF.match(new_branch or "") or ".." in new_branch:
        raise GitHubError("Invalid branch name.")
    info = _api(http, token, "GET", f"/repos/{repo_full_name}")
    default = info.get("default_branch", "")
    if new_branch in (base_branch, default, "main", "master"):
        raise GitHubError("Refusing to publish to the default or base branch. Use a new feature branch.")
    if not (info.get("permissions") or {}).get("push"):
        raise GitHubError("The configured token cannot push to this repository.")
    base = quote(base_branch, safe="/")
    ref = _api(http, token, "GET", f"/repos/{repo_full_name}/git/ref/heads/{base}")
    base_sha = ref["object"]["sha"]
    commit = _api(http, token, "GET", f"/repos/{repo_full_name}/git/commits/{base_sha}")
    tree_sha = commit["tree"]["sha"]
    tree = _api(http, token, "GET", f"/repos/{repo_full_name}/git/trees/{tree_sha}?recursive=1")
    modes = {e["path"]: e.get("mode", "100644") for e in tree.get("tree", []) if e.get("type") == "blob"}
    entries = []
    for path, content in sorted(changes.items()):
        blob = _api(http, token, "POST", f"/repos/{repo_full_name}/git/blobs",
                    {"content": content, "encoding": "utf-8"})
        entries.append({"path": path, "mode": modes.get(path, "100644"), "type": "blob", "sha": blob["sha"]})
    new_tree = _api(http, token, "POST", f"/repos/{repo_full_name}/git/trees",
                    {"base_tree": tree_sha, "tree": entries})
    new_commit = _api(http, token, "POST", f"/repos/{repo_full_name}/git/commits",
                      {"message": commit_message, "tree": new_tree["sha"], "parents": [base_sha]})
    _api(http, token, "POST", f"/repos/{repo_full_name}/git/refs",
         {"ref": f"refs/heads/{new_branch}", "sha": new_commit["sha"]})
    pr = _api(http, token, "POST", f"/repos/{repo_full_name}/pulls",
              {"title": pr_title, "head": new_branch, "base": base_branch, "body": pr_body})
    url = pr.get("html_url", "")
    if not url.startswith("https://github.com/"):
        url = ""
    return PublishResult(repo_full_name, new_branch, new_commit["sha"], url, pr.get("number"))


@dataclass(frozen=True)
class PublishConfig:
    token: str = field(repr=False)
    publish_key: str = field(repr=False)
    repo: str


_REPO_FULL = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def publish_blockers(get) -> list[str]:
    """Names of settings still missing. Publishing stays disabled until this is empty."""
    missing = [k for k in ("GITHUB_TOKEN", "PUBLISH_KEY", "PUBLISH_REPO") if not get(k)]
    repo = get("PUBLISH_REPO")
    if repo and not _REPO_FULL.match(repo.strip()):
        missing.append("PUBLISH_REPO (must look like owner/repository)")
    return missing


def load_publish_config(get):
    if publish_blockers(get):
        return None
    return PublishConfig(get("GITHUB_TOKEN").strip(), get("PUBLISH_KEY"), get("PUBLISH_REPO").strip())


def key_matches(cfg: PublishConfig, entered: str) -> bool:
    if not entered:
        return False
    return hmac.compare_digest(entered.encode(), cfg.publish_key.encode())

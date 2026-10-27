"""Real scanner adapters: Bandit (static Python SAST) and OSV.dev dependency advisories.

Bandit parses files with Python's ast module and never imports or runs them. It is started as a
subprocess without a shell, with a minimal environment, a timeout and a private temporary
directory. OSV.dev is queried through its public batch API. A missing tool or a failed request
produces an explicit 'unavailable' check, never fabricated results.
"""
from __future__ import annotations

import functools
import json
import os
import posixpath
import re
import subprocess  # nosec B404
import sys
import tempfile

import requests

from .models import Check, Finding
from .scanners import redact

BANDIT_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
BANDIT_MAX_FILES = 500
BANDIT_TIMEOUT = 90
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
MAX_DEPS = 200
_ADV_ID = re.compile(r"^[A-Za-z0-9._-]{1,60}$")
_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)")


@functools.lru_cache(maxsize=1)
def bandit_available() -> bool:
    try:
        proc = subprocess.run(  # nosec B603
            [sys.executable, "-m", "bandit", "--version"], capture_output=True, text=True, timeout=30, shell=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _bandit_env() -> dict:
    keep = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "HOME", "LANG")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _inside(root: str, dest: str) -> bool:
    try:
        return os.path.commonpath([root, dest]) == root
    except ValueError:
        return False


def bandit_scan(text_files: dict, occupied=frozenset()):
    """Run Bandit over the Python files. `occupied` holds (path, line) pairs already reported."""
    name = "Bandit (Python SAST)"
    py = {p: c for p, c in text_files.items() if p.endswith(".py")}
    if not py:
        return [], Check(name, "skipped", "No Python files in project.")
    if not bandit_available():
        return [], Check(name, "unavailable",
                         "Bandit is not installed in this environment (pip install bandit); its checks were NOT run.")
    py = dict(list(py.items())[:BANDIT_MAX_FILES])
    with tempfile.TemporaryDirectory(prefix="lxnoro-") as tmp:
        root = os.path.realpath(tmp)
        for path, content in py.items():
            dest = os.path.realpath(os.path.join(root, *path.split("/")))
            if not _inside(root, dest):
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8", newline="") as fh:
                fh.write(content)
        try:
            proc = subprocess.run(  # nosec B603
                [sys.executable, "-m", "bandit", "-r", root, "-f", "json", "-q"],
                capture_output=True, text=True, timeout=BANDIT_TIMEOUT, cwd=root, env=_bandit_env(), shell=False)
        except subprocess.TimeoutExpired:
            return [], Check(name, "unavailable", f"Bandit timed out after {BANDIT_TIMEOUT} s; its results were NOT used.")
        except (OSError, subprocess.SubprocessError) as exc:
            return [], Check(name, "unavailable", f"Bandit could not be started ({type(exc).__name__}).")
        try:
            results = json.loads(proc.stdout).get("results", [])
        except (ValueError, AttributeError):
            return [], Check(name, "unavailable", "Bandit produced unexpected output; its results were NOT used.")
        findings, merged = [], 0
        for item in results:
            try:
                rel = os.path.relpath(os.path.realpath(item["filename"]), root).replace(os.sep, "/")
                line = int(item["line_number"])
                test_id = str(item["test_id"])
                severity = BANDIT_SEVERITY.get(str(item.get("issue_severity", "")).upper(), "low")
            except (KeyError, ValueError, TypeError):
                continue
            if not re.fullmatch(r"B\d{3}", test_id) or rel not in py:
                continue
            if (rel, line) in occupied:
                merged += 1
                continue
            lines = py[rel].split("\n")
            evidence = redact(lines[line - 1].strip())[:200] if 0 < line <= len(lines) else ""
            more = str(item.get("more_info", ""))
            guide = f" See {more}" if more.startswith("https://bandit.readthedocs.io/") else ""
            findings.append(Finding(
                id=f"BANDIT-{test_id}:{rel}:{line}", rule_id=f"BANDIT-{test_id}",
                title=f"Bandit {test_id}: {str(item.get('test_name', ''))[:80]}", severity=severity,
                path=rel, line=line, evidence=evidence, explanation=str(item.get("issue_text", ""))[:300],
                impact="Reported by Bandit, a static analysis tool for Python. Review the context before acting.",
                remediation="Review and fix according to the Bandit guidance." + guide, source="bandit",
            ))
    return findings, Check(name, "performed",
                           f"{len(findings)} finding(s) from Bandit; {merged} overlapping built-in finding(s) merged.")


def pinned_requirements(text_files: dict) -> list:
    out = []
    for path, content in text_files.items():
        if not re.fullmatch(r"requirements[\w.-]*\.txt", posixpath.basename(path).lower()):
            continue
        for n, line in enumerate(content.split("\n"), start=1):
            if line.lstrip().startswith(("#", "-")):
                continue
            m = _REQ.match(line)
            if m:
                out.append((path, n, m.group(1), m.group(2)))
    return out


def _osv_post(url, payload, timeout):
    resp = requests.post(url, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def osv_scan(text_files: dict, post=None):
    """Check pinned PyPI requirements against OSV.dev. The batch API returns advisory ids only."""
    name = "Dependency advisories (OSV.dev)"
    reqs = pinned_requirements(text_files)[:MAX_DEPS]
    if not reqs:
        return [], Check(name, "skipped", "No pinned PyPI requirements (name==version) found.")
    payload = {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for _p, _l, n, v in reqs]}
    try:
        data = (post or _osv_post)(OSV_BATCH, payload, (5, 30))
    except Exception as exc:
        return [], Check(name, "unavailable",
                         f"OSV.dev request failed ({type(exc).__name__}); dependency advisories were NOT checked.")
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list) or len(results) != len(reqs):
        return [], Check(name, "unavailable", "OSV.dev returned an unexpected response; advisories were NOT checked.")
    findings = []
    for (path, line, pkg, ver), res in zip(reqs, results):
        vulns = res.get("vulns", []) if isinstance(res, dict) else []
        ids = [v.get("id") for v in vulns if isinstance(v, dict)]
        ids = [i for i in ids if isinstance(i, str) and _ADV_ID.match(i)]
        if not ids:
            continue
        findings.append(Finding(
            id=f"DEP-VULN:{path}:{line}:{pkg}", rule_id="DEP-VULN",
            title=f"Known advisories for {pkg}=={ver}", severity="medium", path=path, line=line,
            evidence=f"{pkg}=={ver}: {', '.join(ids[:5])}",
            explanation="OSV.dev lists published advisories for this exact version. The batch endpoint does not "
                        "return severity, so this rating is a default and the advisory must be reviewed.",
            impact="Depending on the advisory, the dependency may expose the application to known attacks.",
            remediation=f"Upgrade {pkg} to a version without these advisories. Details: https://osv.dev/vulnerability/{ids[0]}",
            source="osv",
        ))
    return findings, Check(name, "performed",
                           f"{len(reqs)} pinned requirement(s) checked; {len(findings)} with advisories. "
                           "Unpinned requirements are not checked.")


SIM_ADVISORIES = {"pyyaml==5.3": "SIMULATED-ADV-0001", "flask==0.12": "SIMULATED-ADV-0002"}


def simulated_dependency_scan(text_files: dict):
    """Offline demo fixture for SIMULATION mode. These are NOT real advisories."""
    name = "Dependency advisories (SIMULATED fixture)"
    findings = []
    for path, line, pkg, ver in pinned_requirements(text_files):
        adv = SIM_ADVISORIES.get(f"{pkg.lower()}=={ver}")
        if adv:
            findings.append(Finding(
                id=f"DEP-VULN-SIM:{path}:{line}:{pkg}", rule_id="DEP-VULN-SIM",
                title=f"SIMULATED advisory for {pkg}=={ver}", severity="medium", path=path, line=line,
                evidence=f"{pkg}=={ver}: {adv}",
                explanation="This advisory comes from a built-in demo fixture, not from a real vulnerability database.",
                impact="None: simulated data used to demonstrate the workflow.",
                remediation="In live mode this check queries OSV.dev instead.", source="simulation",
            ))
    return findings, Check(name, "performed", "Offline demo fixture; these are NOT real advisories.")

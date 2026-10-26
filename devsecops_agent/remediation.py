"""Stage 4: remediation policy, safe fixers, human approval and audit log.

Policy: a change may be applied automatically only when the finding severity
is below high AND the fixer is classed low-risk. Everything else (high or
critical severity, or any non-low-risk fix) stays pending until a named human
records an approval. Original files are never mutated; fixes produce copies.
"""
from __future__ import annotations

import difflib
import hashlib
import re
from dataclasses import dataclass
from typing import Callable, Optional

from .models import Finding, utc_now
from .scanners import redact

AUTO_RISK = "low"
APPROVAL_SEVERITIES = ("high", "critical")


def needs_approval(severity: str, fix_risk: str) -> bool:
    return severity in APPROVAL_SEVERITIES or fix_risk != AUTO_RISK


@dataclass(frozen=True)
class FixSpec:
    risk: str
    description: str
    fn: Callable[[str], Optional[str]]
    import_module: Optional[str] = None


def _sub_once(pattern: str, repl: str, line: str) -> Optional[str]:
    new = re.sub(pattern, repl, line, count=1)
    return new if new != line else None


def _fix_yaml(line: str) -> Optional[str]:
    return _sub_once(r"\byaml\.load\(", "yaml.safe_load(", line)


def _fix_debug(line: str) -> Optional[str]:
    return _sub_once(r"(\b(?:debug|DEBUG)\s*=\s*)True\b", r"\1False", line)


def _fix_tls(line: str) -> Optional[str]:
    return _sub_once(r"(\bverify\s*=\s*)False\b", r"\1True", line)


def _fix_eval(line: str) -> Optional[str]:
    return _sub_once(r"(?<![\w.])eval\s*\(", "ast.literal_eval(", line)


_ASSIGN = re.compile(r"""^(\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)(["'])[^"'\r\n]+\4(\s*(?:#.*)?)$""")


def _fix_hardcoded(line: str) -> Optional[str]:
    m = _ASSIGN.match(line)
    if not m:
        return None
    name = m.group(2)
    return f'{m.group(1)}{name}{m.group(3)}os.environ["{name.upper()}"]{m.group(5)}'


_SECRET_SPEC = FixSpec(
    "high",
    "Replace the hard-coded value with an os.environ lookup. The exposed credential must still be rotated.",
    _fix_hardcoded,
    "os",
)

FIXERS: dict[str, FixSpec] = {
    "PY-YAML-LOAD": FixSpec("low", "Use yaml.safe_load instead of yaml.load", _fix_yaml),
    "PY-DEBUG": FixSpec("low", "Disable debug mode", _fix_debug),
    "PY-TLS-VERIFY": FixSpec(
        "medium",
        "Enable TLS certificate verification (can break use of self-signed certificates)",
        _fix_tls,
    ),
    "PY-EVAL": FixSpec(
        "high",
        "Replace the eval call with ast.literal_eval (parses literals only; behaviour may change)",
        _fix_eval,
        "ast",
    ),
    "SEC-HARDCODED": _SECRET_SPEC,
    "SEC-AWS-KEY": _SECRET_SPEC,
    "SEC-GITHUB-TOKEN": _SECRET_SPEC,
    "SEC-SLACK-TOKEN": _SECRET_SPEC,
}


def _import_position(lines: list[str]) -> int:
    i = 0
    while i < len(lines) and (lines[i].startswith("#") or not lines[i].strip()):
        i += 1  # shebang, coding line, licence header and blank lines stay first
    if i < len(lines):
        s = lines[i].lstrip()
        for q in ('"""', "'''"):
            if s.startswith(q):
                if s.count(q) >= 2:
                    i += 1
                else:
                    j = i + 1
                    while j < len(lines) and q not in lines[j]:
                        j += 1
                    i = min(j + 1, len(lines))
                break
    while i < len(lines) and lines[i].startswith("from __future__"):
        i += 1
    return i


def _ensure_import(lines: list[str], module: str) -> list[str]:
    pat = re.compile(rf"^\s*(import\s+{module}\b|from\s+{module}\s+import\b)")
    if any(pat.match(ln) for ln in lines):
        return lines
    pos = _import_position(lines)
    return lines[:pos] + [f"import {module}"] + lines[pos:]


@dataclass(frozen=True)
class Remediation:
    finding_id: str
    rule_id: str
    path: str
    line: int
    severity: str
    fix_risk: str
    description: str
    old_line_digest: str  # sha256 of the original line; the raw line is never stored or shown
    diff: str
    needs_approval: bool


@dataclass(frozen=True)
class Decision:
    decision: str  # approved | rejected
    approver: str
    ts: str


@dataclass
class ApplyResult:
    files: dict
    statuses: dict  # finding_id -> applied | pending_approval | rejected | skipped


def plan_remediations(files: dict[str, str], findings: list[Finding]) -> list[Remediation]:
    plan: list[Remediation] = []
    for f in findings:
        spec = FIXERS.get(f.rule_id)
        content = files.get(f.path)
        if spec is None or content is None:
            continue
        lines = content.split("\n")
        idx = f.line - 1
        if not 0 <= idx < len(lines):
            continue
        new_line = spec.fn(lines[idx])
        if new_line is None:
            continue
        new_lines = list(lines)
        new_lines[idx] = new_line
        if spec.import_module:
            new_lines = _ensure_import(new_lines, spec.import_module)
        diff = redact("\n".join(
            difflib.unified_diff(lines, new_lines, f"a/{f.path}", f"b/{f.path}", lineterm="", n=1)
        ))
        plan.append(Remediation(
            finding_id=f.id, rule_id=f.rule_id, path=f.path, line=f.line,
            severity=f.severity, fix_risk=spec.risk, description=spec.description,
            old_line_digest=_digest(lines[idx]), diff=diff,
            needs_approval=needs_approval(f.severity, spec.risk),
        ))
    return plan


def _digest(line: str) -> str:
    return hashlib.sha256(line.strip().encode("utf-8")).hexdigest()


def _compiles(source: str) -> bool:
    """Static syntax check via compile(); the code is never executed."""
    try:
        compile(source, "<candidate>", "exec", dont_inherit=True)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    return True


def apply_remediations(files: dict[str, str], plan: list[Remediation], decisions: dict) -> ApplyResult:
    """Apply low-risk fixes and explicitly approved changes. Never mutates `files`."""
    out = dict(files)
    statuses: dict[str, str] = {}
    imports: dict[str, set] = {}
    for r in plan:
        d = decisions.get(r.finding_id)
        if r.needs_approval:
            if d is not None and d.decision == "rejected":
                statuses[r.finding_id] = "rejected"
                continue
            if d is None or d.decision != "approved" or not d.approver.strip():
                statuses[r.finding_id] = "pending_approval"
                continue
        spec = FIXERS.get(r.rule_id)
        content = out.get(r.path)
        if spec is None or content is None:
            statuses[r.finding_id] = "skipped"
            continue
        lines = content.split("\n")
        idx = r.line - 1
        if not 0 <= idx < len(lines) or _digest(lines[idx]) != r.old_line_digest:
            statuses[r.finding_id] = "skipped"
            continue
        new_line = spec.fn(lines[idx])
        if new_line is None:
            statuses[r.finding_id] = "skipped"
            continue
        lines[idx] = new_line
        out[r.path] = "\n".join(lines)
        if spec.import_module:
            imports.setdefault(r.path, set()).add(spec.import_module)
        statuses[r.finding_id] = "applied"
    for path, modules in imports.items():
        lines = out[path].split("\n")
        for module in sorted(modules):
            lines = _ensure_import(lines, module)
        out[path] = "\n".join(lines)
    touched = {r.path for r in plan if statuses.get(r.finding_id) == "applied" and r.path.endswith(".py")}
    for path in touched:
        if _compiles(files[path]) and not _compiles(out[path]):
            out[path] = files[path]
            for r in plan:
                if r.path == path and statuses.get(r.finding_id) == "applied":
                    statuses[r.finding_id] = "skipped"
    return ApplyResult(files=out, statuses=statuses)


def audit_event(audit: list, actor: str, action: str, scope: str = "", **fields) -> None:
    entry = {"ts": utc_now(), "actor": actor, "action": action, "scope": scope}
    entry.update({k: v for k, v in fields.items() if v not in (None, "")})
    audit.append(entry)


def record_decision(decisions: dict, audit: list, item: Remediation, decision: str,
                    approver: str, scope: str = "") -> Decision:
    if decision not in ("approved", "rejected"):
        raise ValueError("Decision must be 'approved' or 'rejected'.")
    name = re.sub(r"[^\w .@'-]", "", approver or "").strip()[:80]
    if not name:
        raise ValueError("Enter the approver's name before approving or rejecting.")
    d = Decision(decision, name, utc_now())
    decisions[item.finding_id] = d
    audit_event(audit, f"human:{name}", decision, scope, finding_id=item.finding_id,
                rule_id=item.rule_id, path=item.path, line=item.line,
                detail=f"severity={item.severity}; fix risk={item.fix_risk}")
    return d


def apply_and_audit(files: dict, plan: list[Remediation], decisions: dict, audit: list,
                    logged: set, scope: str = "") -> ApplyResult:
    result = apply_remediations(files, plan, decisions)
    for r in plan:
        status = result.statuses.get(r.finding_id)
        key = (r.finding_id, status)
        if status not in ("applied", "skipped") or key in logged:
            continue
        logged.add(key)
        if status == "applied" and r.needs_approval:
            actor, action = f"human:{decisions[r.finding_id].approver}", "applied_after_approval"
        elif status == "applied":
            actor, action = "system:auto", "auto_applied"
        else:
            actor, action = "system", "skipped"
        audit_event(audit, actor, action, scope, finding_id=r.finding_id, rule_id=r.rule_id,
                    path=r.path, line=r.line, detail=r.description)
    return result

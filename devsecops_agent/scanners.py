"""Stage 2: deterministic, non-executing security checks.

All checks are line-based pattern rules over text files that were already
validated by safe_zip. Nothing is imported, executed or evaluated. Evidence
strings are redacted before they are stored, so secrets never reach reports,
the UI or any AI provider.
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

from .models import Check, Finding, Hygiene, ScanResult, sort_findings, utc_now

MAX_LINE_LENGTH = 2000
PY_EXT = (".py",)
JS_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

_SPECIFIC_SECRETS = (
    ("SEC-AWS-KEY", "AWS access key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("SEC-GITHUB-TOKEN", "GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    (
        "SEC-PRIVATE-KEY",
        "Private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ),
    ("SEC-SLACK-TOKEN", "Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
)
_GENERIC_SECRET = re.compile(
    r"""(?i)\b([A-Za-z0-9_.-]*(?:api[_-]?key|secret|passw(?:or)?d|token|auth)[A-Za-z0-9_.-]*)\s*[:=]\s*(["'])([^"'\s]{8,})\2"""
)
_PLACEHOLDER = re.compile(
    r"(?i)(change.?me|your[_-]|example|placeholder|dummy|x{4,}|<[^>]*>|\$\{|%\(|\*{3,}|\[redacted\])"
)

_SECRET_EXPL = "A credential-like value is stored directly in source code."
_SECRET_IMPACT = (
    "Anyone with repository access (including history and forks) can reuse it. "
    "Deleting it from the file does not remove it from Git history."
)
_SECRET_FIX = (
    "Revoke and rotate the credential now, then load it from an environment "
    "variable or a secret manager and add secret scanning to CI."
)


def redact(text: str) -> str:
    """Replace secret-looking values with [REDACTED]."""
    for _rule_id, _label, rx in _SPECIFIC_SECRETS:
        text = rx.sub("[REDACTED]", text)
    return _GENERIC_SECRET.sub(
        lambda m: m.group(0).replace(m.group(3), "[REDACTED]"), text
    )


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    exts: tuple
    comment: str
    pattern: re.Pattern
    explanation: str
    impact: str
    remediation: str
    fixer: bool = False


RULES = (
    Rule(
        "PY-EVAL", "Dynamic code evaluation with eval()", "high", PY_EXT, "#",
        re.compile(r"(?<![\w.])eval\s*\("),
        "eval() executes arbitrary Python expressions.",
        "If any input reaches it, an attacker can run code in the application.",
        "Use ast.literal_eval() for literals or an explicit parser. Do not evaluate untrusted input.",
        True,
    ),
    Rule(
        "PY-EXEC", "Dynamic code execution with exec()", "high", PY_EXT, "#",
        re.compile(r"(?<![\w.])exec\s*\("),
        "exec() runs arbitrary Python statements.",
        "Remote code execution if any input reaches it.",
        "Remove dynamic execution or replace it with a fixed dispatch table.",
    ),
    Rule(
        "PY-SHELL", "Subprocess call with shell=True", "high", PY_EXT, "#",
        re.compile(r"subprocess\.\w+\(.*shell\s*=\s*True"),
        "The command is interpreted by a shell, enabling injection through metacharacters.",
        "Command injection and arbitrary command execution.",
        "Pass an argument list and omit shell=True; validate any user-controlled values.",
    ),
    Rule(
        "PY-YAML-LOAD", "yaml.load() without a safe loader", "medium", PY_EXT, "#",
        re.compile(r"\byaml\.load\((?!.*Loader)"),
        "yaml.load() can construct arbitrary Python objects from YAML.",
        "Code execution when parsing untrusted YAML.",
        "Use yaml.safe_load().",
        True,
    ),
    Rule(
        "PY-PICKLE", "Unsafe deserialization with pickle", "high", PY_EXT, "#",
        re.compile(r"\bpickle\.loads?\("),
        "Unpickling untrusted data can execute arbitrary code.",
        "Remote code execution through crafted payloads.",
        "Use a data-only format such as JSON, or authenticate and sign the data.",
    ),
    Rule(
        "PY-WEAK-HASH", "Weak hash algorithm (MD5/SHA-1)", "medium", PY_EXT, "#",
        re.compile(r"\bhashlib\.(md5|sha1)\("),
        "MD5 and SHA-1 are collision-prone and unsuitable for security purposes.",
        "Forged signatures or weak password storage if used for security.",
        "Use SHA-256 or stronger; use a password hashing function (argon2, bcrypt, scrypt) for passwords.",
    ),
    Rule(
        "PY-DEBUG", "Debug mode enabled", "medium", PY_EXT, "#",
        re.compile(r"(\.run\(.*\bdebug\s*=\s*True|^\s*DEBUG\s*=\s*True\b)"),
        "Debug mode can expose stack traces, source and interactive consoles.",
        "Information disclosure and, for some frameworks, remote code execution.",
        "Disable debug mode outside local development; drive it from configuration.",
        True,
    ),
    Rule(
        "PY-TLS-VERIFY", "TLS certificate verification disabled", "medium", PY_EXT, "#",
        re.compile(r"\bverify\s*=\s*False\b"),
        "Disabling certificate verification removes protection against interception.",
        "Man-in-the-middle attacks on outbound HTTPS requests.",
        "Keep verification on; trust a private CA bundle instead of disabling checks.",
        True,
    ),
    Rule(
        "PY-SQLI", "Possible SQL injection (string-built query)", "high", PY_EXT, "#",
        re.compile(r"\.execute\(\s*(f[\"']|[\"'][^\"']*[\"']\s*(%|\+|\.format))"),
        "A query appears to be assembled with string formatting instead of parameters.",
        "Data theft or modification through injected SQL.",
        "Use parameterized queries (placeholders) and never format user input into SQL.",
    ),
    Rule(
        "JS-EVAL", "Dynamic code evaluation with eval()", "high", JS_EXT, "//",
        re.compile(r"(?<![\w.])eval\s*\("),
        "eval() executes arbitrary JavaScript.",
        "Script injection if any input reaches it.",
        "Remove eval(); use JSON.parse or explicit logic.",
    ),
    Rule(
        "JS-INNERHTML", "innerHTML assignment (XSS risk)", "medium", JS_EXT, "//",
        re.compile(r"\.innerHTML\s*="),
        "Assigning HTML strings can inject attacker-controlled markup.",
        "Cross-site scripting.",
        "Use textContent or a sanitizer such as DOMPurify.",
    ),
    Rule(
        "JS-DOCWRITE", "document.write usage", "medium", JS_EXT, "//",
        re.compile(r"\bdocument\.write\("),
        "document.write can inject unsanitized content into the page.",
        "Cross-site scripting.",
        "Build DOM nodes with safe APIs instead.",
    ),
)


def _ext(path: str) -> str:
    return posixpath.splitext(path)[1].lower()


def _finding(rule_id, title, severity, path, line, evidence, explanation, impact,
             remediation, fixable=False) -> Finding:
    return Finding(
        id=f"{rule_id}:{path}:{line}",
        rule_id=rule_id,
        title=title,
        severity=severity,
        path=path,
        line=line,
        evidence=redact(evidence.strip())[:200],
        explanation=explanation,
        impact=impact,
        remediation=remediation,
        fixable=fixable,
    )


def _secret_finding(path: str, n: int, line: str, ext: str):
    for rule_id, label, rx in _SPECIFIC_SECRETS:
        if rx.search(line):
            return _finding(
                rule_id, f"Hard-coded secret: {label}", "critical", path, n, line,
                _SECRET_EXPL, _SECRET_IMPACT, _SECRET_FIX,
                fixable=(ext in PY_EXT and rule_id != "SEC-PRIVATE-KEY"),
            )
    m = _GENERIC_SECRET.search(line)
    if m and not _PLACEHOLDER.search(m.group(3)):
        return _finding(
            "SEC-HARDCODED", "Hard-coded credential", "high", path, n, line,
            _SECRET_EXPL, _SECRET_IMPACT, _SECRET_FIX, fixable=ext in PY_EXT,
        )
    return None


def _scan_file(path: str, content: str) -> list[Finding]:
    out: list[Finding] = []
    ext = _ext(path)
    for n, raw in enumerate(content.split("\n"), start=1):
        if len(raw) > MAX_LINE_LENGTH:
            continue
        line = raw.rstrip("\r")
        secret = _secret_finding(path, n, line, ext)
        if secret:
            out.append(secret)
        stripped = line.lstrip()
        for rule in RULES:
            if ext not in rule.exts or stripped.startswith(rule.comment):
                continue
            if rule.pattern.search(line):
                out.append(
                    _finding(rule.id, rule.title, rule.severity, path, n, line,
                             rule.explanation, rule.impact, rule.remediation, rule.fixer)
                )
    return out


def _config_findings(text_files: dict[str, str]) -> list[Finding]:
    out: list[Finding] = []
    for path, content in text_files.items():
        base = posixpath.basename(path)
        low = base.lower()
        if low == ".env" or (
            low.startswith(".env.")
            and not low.endswith((".example", ".sample", ".template"))
        ):
            out.append(_finding(
                "ENV-FILE", "Environment file committed", "high", path, 1,
                "[environment file present; contents not shown]",
                "Environment files commonly hold credentials.",
                "Secrets in the repository are exposed to everyone with access.",
                "Remove it from version control, rotate any secrets, and add it to .gitignore.",
            ))
        if low.startswith("dockerfile") or low.endswith(".dockerfile"):
            lines = content.split("\n")
            if not any(re.match(r"\s*USER\s+(?!root\b|0\b)\S+", ln, re.I) for ln in lines):
                out.append(_finding(
                    "DOCKER-ROOT", "Container runs as root", "medium", path, 1,
                    "No non-root USER instruction found",
                    "Without a USER instruction the container process runs as root.",
                    "A compromise of the app has root privileges inside the container.",
                    "Create an unprivileged user and add a USER instruction.",
                ))
            aliases = {
                m.group(1).lower()
                for ln in lines
                for m in [re.search(r"\bAS\s+(\S+)\s*$", ln, re.I)]
                if m
            }
            for n, ln in enumerate(lines, start=1):
                m = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", ln, re.I)
                if not m:
                    continue
                image = m.group(1)
                if image.lower() == "scratch" or image.startswith("$") or image.lower() in aliases:
                    continue
                tag_part = image.split("/")[-1]
                pinned = "@sha256:" in image or (":" in tag_part and not image.endswith(":latest"))
                if not pinned:
                    out.append(_finding(
                        "DOCKER-UNPINNED", "Base image not pinned", "low", path, n, ln,
                        "An untagged or :latest image changes without notice.",
                        "Builds are not reproducible and may pull in vulnerable versions.",
                        "Pin a specific version tag or digest.",
                    ))
        if re.fullmatch(r"requirements[\w.-]*\.txt", low):
            unpinned = [
                (n, ln) for n, ln in enumerate(content.split("\n"), start=1)
                if ln.strip()
                and not ln.strip().startswith(("#", "-"))
                and not re.search(r"(==|@)", ln)
            ]
            if unpinned:
                n, first = unpinned[0]
                out.append(_finding(
                    "DEP-UNPINNED", "Unpinned dependencies", "low", path, n,
                    f"{len(unpinned)} unpinned requirement(s), first: {first.strip()}",
                    "Unpinned dependencies can silently move to vulnerable or malicious versions.",
                    "Non-reproducible builds and supply-chain exposure.",
                    "Pin exact versions (==) and use a lock file with hashes where possible.",
                ))
    return out


def _hygiene(paths: list[str], findings: list[Finding]) -> list[Hygiene]:
    lower = [p.lower() for p in paths]
    bases = {posixpath.basename(p) for p in lower}
    has_tests = any(
        re.search(r"(^|/)(tests?|__tests__)/", p)
        or re.search(r"(^|/)(test_[^/]*\.py|[^/]*_test\.py|[^/]*\.(test|spec)\.[jt]sx?)$", p)
        for p in lower
    )
    has_ci = (
        ".gitlab-ci.yml" in bases
        or "jenkinsfile" in bases
        or any(p.startswith(".github/workflows/") for p in lower)
    )
    secrets_found = any(f.rule_id.startswith("SEC-") or f.rule_id == "ENV-FILE" for f in findings)
    items = [
        ("README present", any(b.startswith("readme") for b in bases)),
        ("License file present", any(b.startswith(("license", "copying")) for b in bases)),
        (".gitignore present", ".gitignore" in bases),
        ("Automated tests present", has_tests),
        ("CI configuration present", has_ci),
        ("No hard-coded secrets detected", not secrets_found),
    ]
    return [Hygiene(name, ok, "Found" if ok else "Not found / not satisfied") for name, ok in items]


def scan_project(text_files: dict[str, str], other_paths=()) -> ScanResult:
    findings: list[Finding] = []
    for path, content in text_files.items():
        findings.extend(_scan_file(path, content))
    findings.extend(_config_findings(text_files))
    findings = sort_findings(list({f.id: f for f in findings}.values()))

    paths = list(text_files) + list(other_paths)
    has_py = any(_ext(p) in PY_EXT for p in text_files)
    has_js = any(_ext(p) in JS_EXT for p in text_files)
    n = len(text_files)
    checks = [
        Check("Secret pattern detection", "performed", f"{n} text file(s) scanned"),
        Check("Python risky-API rules", "performed" if has_py else "skipped",
              "" if has_py else "No Python files in project"),
        Check("JavaScript/TypeScript risky-API rules", "performed" if has_js else "skipped",
              "" if has_js else "No JS/TS files in project"),
        Check("Config checks (.env, Dockerfile, dependency pinning)", "performed"),
        Check("Project hygiene checks", "performed"),
        Check("Dependency vulnerability (CVE) database lookup", "unavailable",
              "Not implemented in this MVP."),
        Check("External SAST engines (Semgrep, Bandit)", "unavailable",
              "Not run inside this app. GitLab CI runs Semgrep SAST on this tool's own repository only."),
    ]
    return ScanResult(
        findings=findings,
        checks=checks,
        hygiene=_hygiene(paths, findings),
        files_scanned=n,
        scanned_at=utc_now(),
    )

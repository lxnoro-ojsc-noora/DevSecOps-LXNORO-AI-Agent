import ast

from devsecops_agent import export, remediation
from devsecops_agent.remediation import apply_remediations, plan_remediations, record_decision
from devsecops_agent.scanners import scan_project

HEADER_SRC = '# Licence header\n"""Doc."""\nfrom __future__ import annotations\nx = eval(s)\n'


# ---- finding 1: secret leakage

def test_plan_diff_never_contains_raw_secret():
    files = {"c.py": 'PASSWORD = "hunter2hunter2"\n'}
    plan = plan_remediations(files, scan_project(files).findings)
    assert plan and all("hunter2hunter2" not in r.diff for r in plan)
    assert "[REDACTED]" in plan[0].diff


def test_remediation_object_never_holds_or_prints_the_raw_line():
    files = {"c.py": 'PASSWORD = "hunter2hunter2"\n'}
    r = plan_remediations(files, scan_project(files).findings)[0]
    assert not hasattr(r, "old_line")
    assert "hunter2hunter2" not in repr(r) and "hunter2hunter2" not in str(r.__dict__)
    assert len(r.old_line_digest) == 64


def test_staleness_check_still_works_with_digest():
    files = {"a.py": "d = yaml.load(f)\n"}
    plan = plan_remediations(files, scan_project(files).findings)
    changed = {"a.py": "d = yaml.load(g)\n"}
    result = apply_remediations(changed, plan, {})
    assert result.files == changed and result.statuses[plan[0].finding_id] == "skipped"


def test_export_diff_summary_redacts_secrets():
    old = {"c.py": 'PASSWORD = "hunter2hunter2"\n'}
    new = {"c.py": 'PASSWORD = os.environ["PASSWORD"]\n'}
    _path, diff = export.diff_summary(old, new)[0]
    assert "hunter2hunter2" not in diff and "[REDACTED]" in diff


# ---- finding 2: invalid Python after remediation

def test_licence_header_docstring_and_future_import_yield_a_valid_fix():
    files = {"a.py": HEADER_SRC}
    plan = plan_remediations(files, scan_project(files).findings)
    assert len(plan) == 1
    decisions = {}
    record_decision(decisions, [], plan[0], "approved", "Lead")
    result = apply_remediations(files, plan, decisions)
    lines = result.files["a.py"].split("\n")
    assert lines[:4] == ["# Licence header", '"""Doc."""', "from __future__ import annotations", "import ast"]
    assert result.statuses[plan[0].finding_id] == "applied"
    ast.parse(result.files["a.py"])  # static parse, nothing executed
    compile(result.files["a.py"], "<check>", "exec")  # also validates __future__ placement


def test_rewrite_that_does_not_compile_is_rejected_and_file_unchanged(monkeypatch):
    def bad_import(lines, module):
        return [f"import {module}"] + lines  # puts a normal import before __future__

    monkeypatch.setattr(remediation, "_ensure_import", bad_import)
    files = {"a.py": HEADER_SRC}
    plan = plan_remediations(files, scan_project(files).findings)
    decisions = {}
    record_decision(decisions, [], plan[0], "approved", "Lead")
    result = apply_remediations(files, plan, decisions)
    assert result.files["a.py"] == HEADER_SRC
    assert result.statuses[plan[0].finding_id] == "skipped"

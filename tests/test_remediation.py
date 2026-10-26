import pytest

from devsecops_agent.remediation import (
    apply_and_audit,
    apply_remediations,
    plan_remediations,
    record_decision,
)
from devsecops_agent.scanners import scan_project


def make(files):
    scan = scan_project(files)
    return plan_remediations(files, scan.findings)


def item(plan, rule_id):
    return [r for r in plan if r.rule_id == rule_id][0]


def test_low_risk_fixes_auto_applied():
    files = {"a.py": "import yaml\nd = yaml.load(f)\napp.run(debug=True)\n"}
    plan = make(files)
    assert plan and all(not r.needs_approval for r in plan)
    res = apply_remediations(files, plan, {})
    assert "yaml.safe_load(" in res.files["a.py"]
    assert "debug=False" in res.files["a.py"]
    assert set(res.statuses.values()) == {"applied"}


def test_original_not_mutated():
    files = {"a.py": "d = yaml.load(f)\n"}
    apply_remediations(files, make(files), {})
    assert files["a.py"] == "d = yaml.load(f)\n"


def test_high_risk_not_applied_without_approval():
    files = {"a.py": "x = eval(s)\n"}
    plan = make(files)
    assert item(plan, "PY-EVAL").needs_approval
    res = apply_remediations(files, plan, {})
    assert res.files == files
    assert res.statuses[item(plan, "PY-EVAL").finding_id] == "pending_approval"


def test_high_risk_applied_after_named_approval():
    files = {"a.py": "x = eval(s)\n"}
    plan = make(files)
    decisions, audit = {}, []
    record_decision(decisions, audit, item(plan, "PY-EVAL"), "approved", "Dr. Noora")
    res = apply_remediations(files, plan, decisions)
    assert res.files["a.py"] == "import ast\nx = ast.literal_eval(s)\n"
    assert audit[0]["actor"] == "human:Dr. Noora" and audit[0]["action"] == "approved"


def test_rejected_change_not_applied():
    files = {"a.py": "x = eval(s)\n"}
    plan = make(files)
    decisions = {}
    record_decision(decisions, [], item(plan, "PY-EVAL"), "rejected", "Reviewer")
    res = apply_remediations(files, plan, decisions)
    assert res.files == files
    assert res.statuses[item(plan, "PY-EVAL").finding_id] == "rejected"


def test_blank_approver_rejected():
    plan = make({"a.py": "x = eval(s)\n"})
    with pytest.raises(ValueError):
        record_decision({}, [], plan[0], "approved", "   ")


def test_medium_severity_but_non_low_fix_needs_approval():
    plan = make({"a.py": "requests.get(u, verify=False)\n"})
    r = item(plan, "PY-TLS-VERIFY")
    assert r.severity == "medium" and r.needs_approval


def test_hardcoded_secret_fix_needs_approval_and_removes_literal():
    files = {"c.py": 'PASSWORD = "hunter2hunter2"\n'}
    plan = make(files)
    r = item(plan, "SEC-HARDCODED")
    assert r.needs_approval
    assert apply_remediations(files, plan, {}).files == files
    decisions = {}
    record_decision(decisions, [], r, "approved", "Lead")
    out = apply_remediations(files, plan, decisions).files["c.py"]
    assert 'os.environ["PASSWORD"]' in out and "import os" in out
    assert "hunter2hunter2" not in out


def test_mixed_fixes_single_import_and_no_line_shift_problem():
    files = {"a.py": "import yaml\nx = eval(a)\nd = yaml.load(f)\n"}
    plan = make(files)
    decisions = {}
    record_decision(decisions, [], item(plan, "PY-EVAL"), "approved", "Lead")
    out = apply_remediations(files, plan, decisions).files["a.py"]
    assert "ast.literal_eval(" in out and "yaml.safe_load(" in out
    assert out.count("import ast") == 1


def test_import_goes_after_docstring_and_future():
    files = {"a.py": '"""Doc."""\nfrom __future__ import annotations\nx = eval(s)\n'}
    plan = make(files)
    decisions = {}
    record_decision(decisions, [], plan[0], "approved", "Lead")
    out = apply_remediations(files, plan, decisions).files["a.py"].split("\n")
    assert out[:3] == ['"""Doc."""', "from __future__ import annotations", "import ast"]


def test_audit_logged_once():
    files = {"a.py": "d = yaml.load(f)\n"}
    plan = make(files)
    audit, logged = [], set()
    apply_and_audit(files, plan, {}, audit, logged, "t")
    apply_and_audit(files, plan, {}, audit, logged, "t")
    assert [e["action"] for e in audit] == ["auto_applied"]
    assert audit[0]["actor"] == "system:auto"

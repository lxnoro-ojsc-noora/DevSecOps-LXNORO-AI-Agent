from devsecops_agent import export
from devsecops_agent.remediation import apply_remediations, plan_remediations, record_decision
from devsecops_agent.scanners import scan_project


def test_plan_diff_never_contains_raw_secret():
    files = {"c.py": 'PASSWORD = "hunter2hunter2"\n'}
    plan = plan_remediations(files, scan_project(files).findings)
    assert plan and all("hunter2hunter2" not in r.diff for r in plan)
    assert "[REDACTED]" in plan[0].diff


def test_export_diff_summary_redacts_secrets():
    old = {"c.py": 'PASSWORD = "hunter2hunter2"\n'}
    new = {"c.py": 'PASSWORD = os.environ["PASSWORD"]\n'}
    _path, diff = export.diff_summary(old, new)[0]
    assert "hunter2hunter2" not in diff and "[REDACTED]" in diff


def test_rewrite_that_no_longer_compiles_is_skipped_and_file_unchanged():
    src = '# header\n"""Doc."""\nfrom __future__ import annotations\nx = eval(s)\n'
    files = {"a.py": src}
    plan = plan_remediations(files, scan_project(files).findings)
    assert len(plan) == 1
    decisions = {}
    record_decision(decisions, [], plan[0], "approved", "Lead")
    result = apply_remediations(files, plan, decisions)
    assert result.files["a.py"] == src
    assert result.statuses[plan[0].finding_id] == "skipped"

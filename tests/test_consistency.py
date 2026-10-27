from devsecops_agent import pipeline, remediation, report
from devsecops_agent.scanners import SIMPLE_ASSIGN, scan_project

SECRET = "hunter2" + "hunter2"


def test_limitations_come_from_the_scan_not_from_a_fixed_sentence():
    scan = pipeline.run_scans({"a.py": "x = 1\n"}, mode="live", osv_post=lambda *a, **k: {"results": []})
    text = " ".join(report.build_report("demo", scan)["limitations"])
    assert "were not run by this app" not in text
    assert "Semgrep: not run" in text
    status = {c.name: c.status for c in scan.checks}
    if status["Bandit (Python SAST)"] == "performed":
        assert "Bandit (Python SAST): not run" not in text


def test_limitations_name_checks_that_really_did_not_run():
    text = " ".join(report.build_report("demo", scan_project({"a.py": "x = 1\n"}))["limitations"])
    assert "External SAST engines (Semgrep, Bandit): not run" in text


def test_fix_available_only_when_a_fixer_can_rewrite_the_line():
    src = "\n".join([f'PASSWORD = "{SECRET}"', f'requests.get(u, password="{SECRET}")', f'cfg = dict(password="{SECRET}")', ""])
    files = {"a.py": src}
    scan = scan_project(files)
    by_line = {f.line: f for f in scan.findings if f.rule_id == "SEC-HARDCODED"}
    assert set(by_line) == {1, 2, 3}
    assert by_line[1].fixable and not by_line[2].fixable and not by_line[3].fixable
    planned = {r.line for r in remediation.plan_remediations(files, scan.findings)}
    assert planned == {line for line, f in by_line.items() if f.fixable}


def test_scanner_and_fixer_agree_on_what_a_simple_assignment_is():
    samples = ['A = "abcdefgh"', '    A = "abcdefgh"  # note', 'A: str = "abcdefgh"', 'f(A="abcdefgh")',
               'A = "a" + "b"', "A = 'abcdefgh'"]
    for line in samples:
        assert bool(SIMPLE_ASSIGN.match(line)) == (remediation._fix_hardcoded(line) is not None), line

import json

from devsecops_agent import export, report
from devsecops_agent.safe_zip import extract_zip
from devsecops_agent.scanners import scan_project

FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


def test_report_counts_levels_and_no_secret_leak():
    scan = scan_project({"c.py": 'PASSWORD = "hunter2hunter2"\nx = eval(s)\n'})
    rep = report.build_report("demo", scan)
    assert rep["summary"]["counts"]["high"] == 2
    assert rep["summary"]["risk_level"] == "High"
    blob = json.dumps(rep) + report.report_markdown(rep) + report.duo_handoff(rep)
    assert "hunter2hunter2" not in blob
    assert "No AI analysis" in blob


def test_critical_level_and_plan_order():
    scan = scan_project({"c.py": f'K = "{FAKE_AWS}"\nx = eval(s)\n'})
    rep = report.build_report("demo", scan)
    assert rep["summary"]["risk_level"] == "Critical"
    assert rep["remediation_plan"][0]["severity"] == "critical"
    assert FAKE_AWS not in json.dumps(rep)


def test_ai_notes_are_labelled():
    scan = scan_project({"a.py": "x = eval(s)\n"})
    fid = scan.findings[0].id
    rep = report.build_report("demo", scan, {fid: "note"}, "anthropic/x")
    md = report.report_markdown(rep)
    assert "AI-generated note (not a scanner result)" in md and "anthropic/x" in md


def test_none_detected_level():
    rep = report.build_report("demo", scan_project({"a.py": "x = 1\n"}))
    assert rep["summary"]["risk_level"] == "None detected"


def test_zip_roundtrip_keeps_binaries_and_text():
    data = export.build_zip({"a.py": "x = 1\n"}, {"b.bin": b"\x00\x01"})
    project = extract_zip(data)
    assert project.text_files == {"a.py": "x = 1\n"}
    assert project.binary_files == {"b.bin": b"\x00\x01"}


def test_changed_files_and_diff():
    old = {"a.py": "x = 1\n", "b.py": "y\n"}
    new = {"a.py": "x = 2\n", "b.py": "y\n"}
    assert list(export.changed_files(old, new)) == ["a.py"]
    path, diff = export.diff_summary(old, new)[0]
    assert path == "a.py" and "+x = 2" in diff and "-x = 1" in diff

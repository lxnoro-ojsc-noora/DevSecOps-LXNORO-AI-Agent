import os
import tempfile

import pytest

from devsecops_agent import engines, pipeline
from devsecops_agent.demo import demo_project

SHELL_SRC = "import subprocess\n\n\ndef f(c):\n    subprocess.call(c, shell=" + "True)\n"


def rules(findings):
    return {f.rule_id for f in findings}


# ---- Bandit: real tool, real input

def test_bandit_really_runs_and_reports_shell_injection():
    findings, check = engines.bandit_scan({"a.py": SHELL_SRC})
    assert check.status == "performed", check.detail
    hit = [f for f in findings if f.rule_id == "BANDIT-B602"]
    assert hit and hit[0].severity == "high" and hit[0].line == 5 and hit[0].source == "bandit"
    assert "subprocess.call" in hit[0].evidence


def test_bandit_findings_overlapping_builtin_ones_are_merged():
    findings, check = engines.bandit_scan({"a.py": SHELL_SRC}, occupied={("a.py", 5)})
    assert check.status == "performed" and "BANDIT-B602" not in rules(findings)
    assert "1 overlapping" in check.detail or "overlapping" in check.detail


def test_bandit_analysis_never_executes_uploaded_code(tmp_path):
    marker = tmp_path / "pwned"
    code = f"import os\nos.makedirs(r'{marker}')\n"
    _findings, check = engines.bandit_scan({"evil.py": code})
    assert check.status == "performed", check.detail  # the tool really ran...
    assert not marker.exists()  # ...and the uploaded code did not


def test_bandit_ignores_paths_that_escape_the_private_directory():
    escaped = os.path.join(tempfile.gettempdir(), "lxnoro_escape_test.py")
    if os.path.exists(escaped):
        os.remove(escaped)
    _f, check = engines.bandit_scan({"../lxnoro_escape_test.py": "x = 1\n", "ok.py": "y = 2\n"})
    assert check.status == "performed" and not os.path.exists(escaped)


def test_bandit_skips_without_python_and_reports_unavailable_when_missing(monkeypatch):
    assert engines.bandit_scan({"a.js": "x"})[1].status == "skipped"
    monkeypatch.setattr(engines, "bandit_available", lambda: False)
    findings, check = engines.bandit_scan({"a.py": SHELL_SRC})
    assert findings == [] and check.status == "unavailable" and "NOT run" in check.detail


# ---- OSV.dev adapter (mocked transport here; the real call is in the live-integration job)

def fake_post(results):
    calls = []

    def post(url, payload, timeout):
        calls.append((url, payload))
        return {"results": results}

    post.calls = calls
    return post


def test_osv_flags_only_pinned_vulnerable_requirements():
    post = fake_post([{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}, {"id": "PYSEC-1"}]}, {}])
    files = {"requirements.txt": "# c\npyyaml==5.3\nflask==3.0.0\nrequests\n-r other.txt\n"}
    findings, check = engines.osv_scan(files, post)
    assert check.status == "performed" and "2 pinned" in check.detail and "Unpinned" in check.detail
    assert len(findings) == 1 and findings[0].rule_id == "DEP-VULN" and findings[0].line == 2
    assert "GHSA-aaaa-bbbb-cccc" in findings[0].evidence and "does not return severity" in findings[0].explanation
    url, payload = post.calls[0]
    assert url == engines.OSV_BATCH
    assert payload["queries"][0] == {"package": {"name": "pyyaml", "ecosystem": "PyPI"}, "version": "5.3"}


def test_osv_failures_are_explicit_never_fabricated():
    def boom(url, payload, timeout):
        raise TimeoutError("x")

    findings, check = engines.osv_scan({"requirements.txt": "pyyaml==5.3\n"}, boom)
    assert findings == [] and check.status == "unavailable" and "NOT checked" in check.detail
    bad = engines.osv_scan({"requirements.txt": "pyyaml==5.3\n"}, lambda *a: {"results": []})[1]
    assert bad.status == "unavailable"
    assert engines.osv_scan({"requirements.txt": "flask\n"}, fake_post([]))[1].status == "skipped"


def test_osv_discards_malformed_advisory_ids():
    post = fake_post([{"vulns": [{"id": "<script>x</script>"}, {"id": "GHSA-ok"}]}])
    findings, _c = engines.osv_scan({"requirements.txt": "a==1\n"}, post)
    assert "<script>" not in findings[0].evidence and "GHSA-ok" in findings[0].evidence


def test_simulated_dependency_scan_is_labelled_and_offline():
    findings, check = engines.simulated_dependency_scan({"requirements.txt": "PyYAML==5.3\nflask\n"})
    assert findings and findings[0].rule_id == "DEP-VULN-SIM" and findings[0].source == "simulation"
    assert "SIMULATED" in check.name and "NOT real" in check.detail


# ---- combined pipeline

def test_live_pipeline_combines_builtin_bandit_and_osv_and_drops_placeholder_checks():
    files = {"app.py": "x = eval(s)\n", "requirements.txt": "pyyaml==5.3\n"}
    scan = pipeline.run_scans(files, mode="live", osv_post=fake_post([{"vulns": [{"id": "GHSA-x"}]}]))
    assert {"PY-EVAL", "DEP-VULN"} <= rules(scan.findings)
    assert "BANDIT-B307" not in rules(scan.findings)  # same line as PY-EVAL, merged
    by_name = {c.name: c.status for c in scan.checks}
    assert by_name["Bandit (Python SAST)"] == "performed" and by_name["Dependency advisories (OSV.dev)"] == "performed"
    assert by_name["Semgrep"] == "unavailable"
    assert not any(n.startswith(("Dependency vulnerability", "External SAST")) for n in by_name)


def test_simulation_pipeline_never_touches_the_network():
    def forbidden(*args):
        raise AssertionError("network used in simulation mode")

    project = demo_project()
    scan = pipeline.run_scans(project.text_files, mode="simulation", osv_post=forbidden)
    assert "DEP-VULN-SIM" in rules(scan.findings)
    assert any("SIMULATED" in c.name for c in scan.checks)


def test_demo_project_is_deterministic_and_insecure_by_design():
    a, b = demo_project(), demo_project()
    assert a.text_files == b.text_files and a.source.startswith("SIMULATED")
    scan = pipeline.run_scans(a.text_files, mode="simulation")
    found = rules(scan.findings)
    assert {"PY-EVAL", "PY-SHELL", "PY-YAML-LOAD", "PY-DEBUG", "SEC-HARDCODED", "DOCKER-ROOT"} <= found

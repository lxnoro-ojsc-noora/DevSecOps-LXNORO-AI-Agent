import io
import json
import zipfile

import pytest

from devsecops_agent import ai, cli, deploy, intake, monitor
from devsecops_agent.safe_zip import UnsafeArchiveError
from devsecops_agent.scanners import scan_project

FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in entries:
            z.writestr(name, content)
    return buf.getvalue()


# ---- intake

def test_load_zip_cleans_name_and_requires_text():
    p = intake.load_zip("my proj.zip", make_zip([("a.py", "x = 1\n")]))
    assert p.name == "my-proj" and p.source == "ZIP upload" and "a.py" in p.text_files
    with pytest.raises(UnsafeArchiveError):
        intake.load_zip("x.zip", make_zip([("b.bin", b"\x00\x01")]))


def test_load_github_uses_archive_download():
    class Resp:
        status_code = 200

        def iter_content(self, n):
            yield make_zip([("o-r-abc/app.py", "x = 1\n")])

    class Http:
        def get(self, *a, **k):
            return Resp()

    p = intake.load_github("https://github.com/o/r", http=Http())
    assert p.name == "o/r" and p.text_files == {"app.py": "x = 1\n"} and p.repo.full_name == "o/r"


# ---- ai

def test_ai_config_requires_all_settings_and_hides_key():
    full = {"AI_PROVIDER": "anthropic", "AI_API_KEY": "SECRETKEY", "AI_MODEL": "m"}
    cfg = ai.load_config(full.get)
    assert cfg and "SECRETKEY" not in repr(cfg)
    assert ai.load_config({**full, "AI_MODEL": ""}.get) is None
    assert ai.load_config({**full, "AI_PROVIDER": "other"}.get) is None
    assert ai.load_config({}.get) is None


def test_ai_explanations_labelled_and_payload_has_no_raw_secret():
    findings = scan_project({"c.py": f'K = "{FAKE_AWS}"\n'}).findings
    calls = []

    def fake_post(url, headers, payload, timeout):
        calls.append(payload)
        return {"content": [{"type": "text", "text": "Because of X."}]}

    res = ai.explain_findings(ai.AIConfig("anthropic", "m", "k"), findings, post=fake_post)
    assert res.ok and res.label == "anthropic/m" and res.failed == 0
    blob = json.dumps(calls)
    assert FAKE_AWS not in blob and "untrusted" in blob


def test_ai_gemini_request_shape_and_failure_handling():
    findings = scan_project({"a.py": "x = eval(s)\n"}).findings
    seen = {}

    def ok_post(url, headers, payload, timeout):
        seen.update(url=url, headers=headers)
        return {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}

    res = ai.explain_findings(ai.AIConfig("gemini", "gem-x", "k"), findings, post=ok_post)
    assert res.ok and "gem-x" in seen["url"] and "x-goog-api-key" in seen["headers"]

    def bad_post(url, headers, payload, timeout):
        raise RuntimeError("boom k")

    res = ai.explain_findings(ai.AIConfig("gemini", "gem-x", "k"), findings, post=bad_post)
    assert not res.ok and res.failed == 1 and res.errors == ["RuntimeError"]


# ---- deploy (simulation)

def test_deploy_gate_blocks_pending_and_unacknowledged_risk():
    assert deploy.gate(2, 0, False)
    assert deploy.gate(0, 1, False)
    assert not deploy.gate(0, 1, True)
    assert not deploy.gate(0, 0, False)


def test_deploy_simulation_is_labelled_and_never_real():
    residual = scan_project({"a.py": "x = eval(s)\n"}).findings
    with pytest.raises(ValueError):
        deploy.simulate_deployment("p", {"a.py": "x"}, {}, residual)
    with pytest.raises(ValueError):
        deploy.simulate_deployment("p", {"a.py": "x"}, {}, [], pending=1)
    rec = deploy.simulate_deployment("p", {"a.py": "x"}, {"b": b"1"}, residual, accepted_residual_risk=True)
    assert rec.kind == "simulation" and rec.real_deployment is False and rec.url == ""
    natures = {s["nature"] for s in rec.steps}
    assert natures == {"computed", "simulated"}
    again = deploy.package_digest({"a.py": "x"}, {"b": b"1"})
    assert rec.digest == again


# ---- monitor

def test_rescan_detects_simulated_drift_as_new_and_high_risk_needs_approval():
    files = {"a.py": "x = 1\n"}
    history = []
    base = scan_project(files)
    monitor.record_scan(history, "baseline", base, None)
    baseline = {monitor.fingerprint(f) for f in base.findings}
    drifted = monitor.simulate_drift(files)
    new, resolved = monitor.record_scan(history, "rescan", scan_project(drifted), baseline)
    assert {f.rule_id for f in new} >= {"PY-SHELL", "PY-EVAL"}
    assert all(f.severity == "high" for f in new)
    assert history[0].status == "baseline recorded" and history[1].new == len(new)
    from devsecops_agent.remediation import plan_remediations
    plan = plan_remediations(drifted, new)
    assert plan and all(r.needs_approval for r in plan)


def test_fingerprint_is_stable_when_lines_shift():
    a = scan_project({"a.py": "x = eval(s)\n"}).findings[0]
    b = scan_project({"a.py": "import os\nx = eval(s)\n"}).findings[0]
    assert a.id != b.id and monitor.fingerprint(a) == monitor.fingerprint(b)


# ---- cli

def test_cli_scans_directory_with_excludes_and_exit_codes(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = eval(s)\n", encoding="utf-8")
    (tmp_path / "skip").mkdir()
    (tmp_path / "skip" / "b.py").write_text("y = eval(t)\n", encoding="utf-8")
    out = tmp_path / "r.json"
    assert cli.main([str(tmp_path), "--exclude", "skip", "--out", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["counts"]["high"] == 1 and data["findings"][0]["location"] == "src/a.py:1"
    assert cli.main([str(tmp_path), "--exclude", "skip", "--fail-on-high"]) == 1

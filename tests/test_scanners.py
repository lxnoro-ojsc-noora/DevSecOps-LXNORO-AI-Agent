from devsecops_agent.scanners import redact, scan_project

FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"


def rules(files):
    return {f.rule_id for f in scan_project(files).findings}


def test_eval_flagged_high_and_fixable():
    scan = scan_project({"a.py": "x = eval(user)\n"})
    f = [f for f in scan.findings if f.rule_id == "PY-EVAL"][0]
    assert f.severity == "high" and f.line == 1 and f.fixable


def test_method_eval_and_comments_not_flagged():
    assert "PY-EVAL" not in rules({"a.py": "model.eval()\n# eval(x)\n"})


def test_aws_key_flagged_and_redacted():
    scan = scan_project({"cfg.py": f'KEY = "{FAKE_AWS}"\n'})
    f = [f for f in scan.findings if f.rule_id == "SEC-AWS-KEY"][0]
    assert f.severity == "critical"
    assert FAKE_AWS not in f.evidence and "[REDACTED]" in f.evidence


def test_generic_password_flagged_and_redacted():
    scan = scan_project({"c.py": 'PASSWORD = "hunter2hunter2"\n'})
    f = [f for f in scan.findings if f.rule_id == "SEC-HARDCODED"][0]
    assert f.severity == "high" and f.fixable
    assert "hunter2hunter2" not in f.evidence


def test_placeholder_secret_not_flagged():
    assert not any(r.startswith("SEC-") for r in rules({"c.py": 'API_KEY = "your-api-key-here"\n'}))


def test_yaml_rules():
    assert "PY-YAML-LOAD" in rules({"a.py": "d = yaml.load(f)\n"})
    assert "PY-YAML-LOAD" not in rules({"a.py": "d = yaml.load(f, Loader=yaml.SafeLoader)\n"})
    assert "PY-YAML-LOAD" not in rules({"a.py": "d = yaml.safe_load(f)\n"})


def test_debug_and_tls_flagged():
    r = rules({"a.py": "app.run(debug=True)\nrequests.get(u, verify=False)\n"})
    assert {"PY-DEBUG", "PY-TLS-VERIFY"} <= r


def test_dockerfile_checks():
    assert "DOCKER-ROOT" in rules({"Dockerfile": "FROM python:3.12\nRUN echo hi\n"})
    assert "DOCKER-ROOT" not in rules({"Dockerfile": "FROM python:3.12\nUSER app\n"})
    assert "DOCKER-UNPINNED" in rules({"Dockerfile": "FROM python\nUSER app\n"})
    assert "DOCKER-UNPINNED" not in rules({"Dockerfile": "FROM python:3.12 AS b\nFROM b\nUSER app\n"})


def test_requirements_unpinned():
    assert "DEP-UNPINNED" in rules({"requirements.txt": "flask\nrequests==2.0\n"})
    assert "DEP-UNPINNED" not in rules({"requirements.txt": "flask==3.0.0\n"})


def test_env_file_flagged_but_example_not():
    assert "ENV-FILE" in rules({".env": "A=1\n"})
    assert "ENV-FILE" not in rules({".env.example": "A=1\n"})


def test_js_rules():
    assert {"JS-INNERHTML", "JS-EVAL"} <= rules({"a.js": "el.innerHTML = x;\neval(y);\n"})


def test_hygiene_and_checks():
    scan = scan_project({"README.md": "hi", "LICENSE": "MIT", "tests/test_a.py": "x = 1\n"})
    h = {x.name: x.passed for x in scan.hygiene}
    assert h["README present"] and h["License file present"] and h["Automated tests present"]
    assert not h[".gitignore present"]
    assert any(c.status == "unavailable" for c in scan.checks)


def test_redact_function():
    assert FAKE_AWS not in redact(f"k={FAKE_AWS}")

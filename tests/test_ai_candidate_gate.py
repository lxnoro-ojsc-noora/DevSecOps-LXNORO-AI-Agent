from dataclasses import replace

from devsecops_agent.remediation import AI_CANDIDATE, Remediation, _digest, apply_remediations, record_decision

SRC = "import subprocess\n\n\ndef f(c):\n    subprocess.call(c, shell=" + "True)\n"
GOOD = "    subprocess.call(c, shell=False)"


def candidate(source=SRC, new_line=GOOD):
    lines = source.split("\n")
    return Remediation("F:1", AI_CANDIDATE, "a.py", 5, "high", "high", "AI-proposed change (advisory): x",
                       _digest(lines[4]), "diff", True, new_line)


def approved(r):
    decisions = {}
    record_decision(decisions, [], r, "approved", "Lead Reviewer")
    return decisions


def test_ai_candidate_is_never_applied_without_approval():
    r = candidate()
    result = apply_remediations({"a.py": SRC}, [r], {})
    assert result.files["a.py"] == SRC and result.statuses["F:1"] == "pending_approval"


def test_backend_enforces_approval_even_if_the_flag_is_cleared():
    r = replace(candidate(), needs_approval=False)
    result = apply_remediations({"a.py": SRC}, [r], {})
    assert result.files["a.py"] == SRC and result.statuses["F:1"] == "pending_approval"


def test_ai_candidate_is_applied_after_named_approval():
    r = candidate()
    result = apply_remediations({"a.py": SRC}, [r], approved(r))
    assert result.statuses["F:1"] == "applied"
    assert result.files["a.py"].split("\n")[4] == GOOD


def test_rejected_ai_candidate_is_not_applied():
    r = candidate()
    decisions = {}
    record_decision(decisions, [], r, "rejected", "Lead Reviewer")
    result = apply_remediations({"a.py": SRC}, [r], decisions)
    assert result.files["a.py"] == SRC and result.statuses["F:1"] == "rejected"


def test_stale_file_is_skipped_via_digest_check():
    r = candidate()
    changed = SRC.replace("(c,", "(d,")
    result = apply_remediations({"a.py": changed}, [r], approved(r))
    assert result.files["a.py"] == changed and result.statuses["F:1"] == "skipped"


def test_replacement_that_breaks_syntax_is_rejected_even_when_approved():
    r = candidate(new_line="    subprocess.call(c, shell=False")
    result = apply_remediations({"a.py": SRC}, [r], approved(r))
    assert result.files["a.py"] == SRC and result.statuses["F:1"] == "skipped"


def test_crlf_line_endings_are_preserved():
    crlf = SRC.replace("\n", "\r\n")
    r = candidate(source=crlf)
    result = apply_remediations({"a.py": crlf}, [r], approved(r))
    assert result.statuses["F:1"] == "applied"
    assert result.files["a.py"].split("\n")[4] == GOOD + "\r"

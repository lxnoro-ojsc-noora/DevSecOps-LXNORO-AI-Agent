import json
from dataclasses import replace

import pytest
import requests

from devsecops_agent import orchestrator as orch
from devsecops_agent.ai import AIConfig, llm
from devsecops_agent.remediation import AI_CANDIDATE, apply_remediations, record_decision
from devsecops_agent.scanners import scan_project

SRC = "import subprocess\n\n\ndef f(c):\n    subprocess.call(c, shell=" + "True)\n"
GOOD = "    subprocess.call(c, shell=False)"
SECRET = "hunter2hunter2"


class FakeClient:
    live = True
    label = "fake (live)"

    def __init__(self, reply):
        self.reply = reply
        self.prompts = []

    def run(self, task, payload, prompt):
        self.prompts.append(prompt)
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply if isinstance(self.reply, str) else json.dumps(self.reply)


def shell_finding(files=None):
    files = files or {"a.py": SRC}
    return files, [f for f in scan_project(files).findings if f.rule_id == "PY-SHELL"][0]


# ---- triage

def test_triage_keeps_valid_entries_orders_by_rank_and_discards_the_rest():
    files, f = shell_finding()
    reply = {"priorities": [{"finding_id": f.id, "rank": 2, "rationale": "r"}, {"finding_id": "nope", "rank": 1},
                            {"finding_id": f.id, "rank": 3}, "junk", {"finding_id": f.id, "rank": True}],
             "summary": "s"}
    result = orch.triage(FakeClient(reply), scan_project(files).findings)
    assert [p.finding_id for p in result.priorities] == [f.id] and result.discarded == 4
    assert result.summary == "s" and result.live is True and result.label == "fake (live)"


def test_triage_tolerates_code_fences_and_rejects_non_json():
    files, f = shell_finding()
    fenced = "```json\n" + json.dumps({"priorities": [], "summary": "ok"}) + "\n```"
    assert orch.triage(FakeClient(fenced), scan_project(files).findings).summary == "ok"
    with pytest.raises(llm.AIError) as exc:
        orch.triage(FakeClient("I think the code is fine"), scan_project(files).findings)
    assert exc.value.kind == "bad_response"


def test_a_failed_live_request_raises_and_is_never_replaced_by_a_mock_answer():
    resp = requests.Response()
    resp.status_code = 401

    def post(url, headers, payload, timeout):
        raise requests.exceptions.HTTPError(response=resp)

    client = orch.LiveClient(AIConfig("anthropic", "m", "SECRETKEY"), post=post)
    files, _f = shell_finding()
    with pytest.raises(llm.AIError) as exc:
        orch.triage(client, scan_project(files).findings)
    assert exc.value.kind == "auth" and "SECRETKEY" not in str(exc.value)


# ---- candidate fixes

def propose(replacement, files=None, rationale="why"):
    files, f = shell_finding(files)
    client = FakeClient({"fixes": [{"finding_id": f.id, "replacement_line": replacement, "rationale": rationale}]})
    return files, f, orch.propose_fixes(client, files, scan_project(files).findings), client


def test_valid_candidate_is_built_and_always_needs_approval():
    files, f, result, _c = propose(GOOD)
    assert len(result.candidates) == 1 and not result.rejected
    cand = result.candidates[0]
    assert cand.rule_id == AI_CANDIDATE and cand.needs_approval and cand.fix_risk == "high"
    assert cand.new_line == GOOD and "-    subprocess.call" in cand.diff and "AI-proposed change (advisory)" in cand.description
    assert apply_remediations(files, [cand], {}).files == files  # not applied without approval
    decisions = {}
    record_decision(decisions, [], cand, "approved", "Lead Reviewer")
    applied = apply_remediations(files, [cand], decisions)
    assert applied.statuses[cand.finding_id] == "applied" and applied.files["a.py"].split("\n")[4] == GOOD


@pytest.mark.parametrize("replacement,reason", [
    ("a\nb", "exactly one line"),
    ("    subprocess.call(c, shell=False", "would not compile"),
    ("    subprocess.call(c, shell=" + "True)  # looks safe", "still flagged"),
    ('    subprocess.call(c, shell=False)  # password = "' + SECRET + '"', "secret-like"),
    ("x" * 400, "too long"),
    ("   ", "empty"),
    ("    subprocess.call(c, shell=" + "True)", "does not change"),
    (123, "not text"),
])
def test_unsafe_or_invalid_candidates_are_rejected_without_touching_the_project(replacement, reason):
    files, _f, result, _c = propose(replacement)
    assert result.candidates == [] and len(result.rejected) == 1 and reason in result.rejected[0][1]
    assert files == {"a.py": SRC}


def test_unknown_finding_ids_are_rejected():
    files, _f = shell_finding()
    client = FakeClient({"fixes": [{"finding_id": "made-up", "replacement_line": GOOD}]})
    result = orch.propose_fixes(client, files, scan_project(files).findings)
    assert result.candidates == [] and result.rejected[0][1] == "unknown finding id"


def test_secret_bearing_lines_are_never_sent_to_the_model():
    src = 'import subprocess\n\n\ndef f(c):\n    subprocess.call(c, shell=' + 'True)  # password = "' + SECRET + '"\n'
    files = {"a.py": src}
    client = FakeClient({"fixes": []})
    result = orch.propose_fixes(client, files, scan_project(files).findings)
    assert client.prompts == [] and any("not sent to the model" in r for _i, r in result.rejected)


def test_only_python_findings_without_a_deterministic_fixer_are_proposed():
    files = {"a.js": "eval(x)\n", "b.py": "d = yaml.load(f)\n"}
    client = FakeClient({"fixes": []})
    result = orch.propose_fixes(client, files, scan_project(files).findings)
    assert client.prompts == [] and result.attempted == 0


def test_prompts_never_contain_the_api_key_or_raw_secrets():
    files, _f, _r, client = propose(GOOD)
    assert all("SECRETKEY" not in p and SECRET not in p for p in client.prompts)
    assert "untrusted" in client.prompts[0]


def test_backend_still_requires_approval_if_a_candidate_flag_is_cleared():
    files, _f, result, _c = propose(GOOD)
    cand = replace(result.candidates[0], needs_approval=False)
    assert apply_remediations(files, [cand], {}).statuses[cand.finding_id] == "pending_approval"


# ---- summaries and facts

def test_summaries_are_parsed_and_empty_ones_rejected():
    assert orch.summarize(FakeClient({"summary": "All good."}), "validation", {"a": 1}).text == "All good."
    with pytest.raises(llm.AIError):
        orch.summarize(FakeClient({"summary": "  "}), "validation", {})


def test_fact_builders_contain_counts_and_locations_only():
    files, f = shell_finding()
    cand = propose(GOOD)[2].candidates[0]
    facts = orch.validation_facts([cand], {cand.finding_id: "skipped"})
    assert facts["ai_candidates"] == 1 and facts["status_skipped"] == 1 and facts["skipped_locations"] == ["a.py:5"]
    rf = orch.rescan_facts("rescan", 3, [f], [f], 1)
    assert rf["new"] == [{"rule": "PY-SHELL", "severity": "high", "location": "a.py:5"}]
    assert "evidence" not in json.dumps(rf)


# ---- simulated client goes through the SAME validation and gates

def test_simulated_client_is_labelled_and_its_fixes_are_still_gated():
    files, f = shell_finding()
    client = orch.SimulatedClient()
    tri = orch.triage(client, scan_project(files).findings)
    assert tri.live is False and "SIMULATED" in tri.label and tri.priorities[0].finding_id == f.id
    fixes = orch.propose_fixes(client, files, scan_project(files).findings)
    assert fixes.live is False and len(fixes.candidates) == 1 and fixes.candidates[0].needs_approval
    assert "SIMULATED" in fixes.candidates[0].description
    assert apply_remediations(files, fixes.candidates, {}).files == files
    assert orch.summarize(client, "rescan", {"new_findings": 2}).text.startswith("SIMULATED")

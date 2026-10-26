"""Live integration tests. Excluded from the normal run (see pytest.ini); executed by the
live-integration CI job. They call real external services and are skipped, with a reason, when the
network or credentials are unavailable. Mocked tests live in the other test files."""
import os

import pytest

from devsecops_agent import ai, engines, orchestrator
from devsecops_agent.ai import llm
from devsecops_agent.scanners import scan_project

pytestmark = pytest.mark.live
CFG = ai.load_config(os.environ.get)
NO_AI = "live AI NOT verified: set AI_PROVIDER, AI_API_KEY and AI_MODEL as masked CI/CD variables"


def test_real_osv_query_returns_known_advisories_for_an_old_pyyaml():
    findings, check = engines.osv_scan({"requirements.txt": "pyyaml==5.3\n"})
    if check.status == "unavailable":
        pytest.skip(f"OSV.dev not reachable from this runner (unverified): {check.detail}")
    assert check.status == "performed", check.detail
    assert any(f.rule_id == "DEP-VULN" and "pyyaml" in f.evidence.lower() for f in findings), \
        "OSV.dev returned no advisories for pyyaml==5.3"


@pytest.mark.skipif(CFG is None, reason=NO_AI)
def test_real_ai_provider_answers_a_connectivity_ping():
    result = llm.ping(CFG)
    assert result.ok, f"{result.kind}: {result.message}"


@pytest.mark.skipif(CFG is None, reason=NO_AI)
def test_real_ai_orchestrator_returns_a_valid_triage_structure():
    findings = scan_project({"a.py": "x = eval(s)\n"}).findings
    result = orchestrator.triage(orchestrator.LiveClient(CFG), findings)
    assert result.live and (result.summary or result.priorities)
    assert all(p.finding_id in {f.id for f in findings} for p in result.priorities)


@pytest.mark.skip(reason="GitHub publishing NOT verified: needs a dedicated test repository and a fine-grained token")
def test_github_publishing_against_a_real_test_repository():
    raise AssertionError("not implemented without a safe test target")


@pytest.mark.skip(reason="GitLab Duo Flows API NOT verified: needs Duo Agent Platform access and a token")
def test_gitlab_duo_flows_api_session_against_a_real_project():
    raise AssertionError("not implemented without access")

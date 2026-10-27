# DevSecOps LXNORO AI Agent

A Streamlit security command center (GitLab Transcend hackathon). It scans a source ZIP or a public GitHub repository with real engines, lets an optional AI orchestrator prioritise findings and propose fixes, applies **only low-risk fixes automatically**, and **requires a named human approval for every high-risk or AI-proposed change**. Uploaded code is never executed.

MIT License. Copyright (c) 2026 NOORA AL-MAOLAI, Research Center: LXNORO OJSC.

## Run

```
pip install -r requirements.txt
streamlit run app.py          # http://localhost:8501
python -m pytest -q           # mocked and unit tests (live tests are excluded)
```

## Live and Simulation mode (selector at the top of the page)

| | LIVE | SIMULATION |
|---|---|---|
| Scanners | built-in rules, **Bandit**, **OSV.dev** (network) | built-in rules, Bandit, labelled offline advisory fixture |
| AI | your configured provider only; no key means "unavailable" | deterministic templates, labelled SIMULATED, not a model |
| Intake | ZIP upload, public GitHub import | the above plus a built-in demo project |
| GitHub publishing / GitLab AI | available when configured | disabled: no external changes |
| Deployment | **simulation only** (no deployment provider exists) | simulation |

Both modes share the same approval, validation and audit rules. Live mode never falls back to simulation after an error; switching mode resets the workflow.

## The seven stages

1. **Intake**: hardened in-memory ZIP handling; public GitHub archive import.
2. **Analysis**: built-in rules, Bandit (run as a subprocess, no shell, private temp dir, timeout; it parses code, never runs it), OSV.dev for pinned PyPI requirements. Missing tools or failed requests show as *unavailable*.
3. **Report**: risk level, strengths, weaknesses, plan; JSON/Markdown with a separately labelled AI section; manual GitLab Duo hand-off brief.
4. **Remediation**: diffs, approval queue, audit trail. Auto-apply only when severity is below high and the fixer is low risk. AI candidates always need approval (enforced in `remediation.apply_remediations`).
5. **Export**: corrected ZIP; GitHub publishing (new branch and pull request only) when configured. Stage-7 fixes update this canonical project; simulated drift files are never exported.
6. **Deploy**: simulation only; gate, package digest and scan are computed, the rest is simulated.
7. **Rescan**: on-demand comparison with the deployment baseline (new, resolved, remaining) and an optional AI interpretation. Not continuous monitoring.

## AI orchestration

`devsecops_agent/orchestrator.py` asks the model for triage, candidate fixes and summaries, and treats every answer as untrusted: strict JSON parsing, ids checked against real findings, secrets redacted, and each candidate fix must be one line, free of secret-like text, compile (never executed), no longer be flagged by the deterministic scanner, and pass named human approval. Secret-bearing lines are never sent to the model.

**Primary provider: external API** (`devsecops_agent/ai/`), configured with Streamlit secrets or environment variables, never in the UI:

- `AI_PROVIDER`: `anthropic`, `gemini`, or `openai` (any OpenAI-compatible server)
- `AI_API_KEY`, `AI_MODEL`, and for `openai` an optional https `AI_ENDPOINT`

**Optional: GitLab Duo Agent Platform** uses the documented, experimental Flows API to submit a read-only, asynchronous triage session (live mode only): `GITLAB_AI_TOKEN`, `GITLAB_AI_PROJECT_ID`, optional `GITLAB_URL`, `GITLAB_AI_WORKFLOW_DEFINITION`. The Duo Chat completions API is internal-only on GitLab.com and is not used.

**GitHub publishing** needs `GITHUB_TOKEN` (fine-grained, one repository), `PUBLISH_REPO` (`owner/repo`) and `PUBLISH_KEY`; it refuses the default branch and never force-pushes.

## Verified versus unverified

| Capability | Evidence |
|---|---|
| Scanner, remediation gates, export, secret redaction, approvals, audit, stage-7 export consistency | unit and headless UI tests in CI |
| Whole seven-stage UI flow, both modes, AI orchestration wiring | headless `AppTest` with a stand-in provider (wiring only) |
| Bandit | really executed in CI tests |
| OSV.dev | mocked in unit tests; **real query only in the `live-integration` CI job**, skipped with a reason if the network is unreachable |
| External AI provider | mocked in unit tests; **real call only if** the AI variables are set in CI; **otherwise unverified** |
| GitLab Flows API, GitHub publishing | fake transports only: **unverified** |
| Real deployment, continuous monitoring, Semgrep in the app | not implemented |
| Browser look and feel, Streamlit Community Cloud | not verified |

To verify live AI in CI, add masked CI/CD variables `AI_PROVIDER`, `AI_API_KEY`, `AI_MODEL`, then read the `live-integration` job log.

## Repository

`.gitlab-ci.yml` runs pytest, SAST, Secret Detection, `self-scan` and `live-integration`. `.gitlab/duo/mr-review-instructions.yaml` and `AGENTS.md` configure GitLab Duo for this repository.

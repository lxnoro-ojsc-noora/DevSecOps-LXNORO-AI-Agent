# DevSecOps LXNORO AI Agent

A Streamlit security command center (GitLab Transcend hackathon). It scans a source ZIP or a public GitHub repository with real engines, lets an optional AI orchestrator prioritise findings and propose fixes, applies **only low-risk fixes automatically**, and **requires a named human approval for every high-risk or AI-proposed change**. Uploaded code is never executed.

MIT License. Copyright (c) 2026 NOORA AL-MAOLAI, Research Center: LXNORO OJSC.

## Run

```
pip install -r requirements.txt
streamlit run app.py          # http://localhost:8501
python -m pytest -q           # mocked and unit tests (live tests are excluded)
```

Simulation mode, the built-in rules, Bandit and OSV.dev need no credentials.

## Configuration (Live mode)

Settings are read from Streamlit secrets (`.streamlit/secrets.toml`, which is git-ignored, or the secrets panel of your host) or from environment variables. Never type secrets into the UI and never commit them.

| Setting | Needed for | Notes |
|---|---|---|
| `AI_PROVIDER` | AI explanations, triage, candidate fixes | `anthropic`, `gemini`, `openai` or `openai-compatible` |
| `AI_API_KEY` | same | your provider key |
| `AI_MODEL` | same | model id from your provider |
| `AI_ENDPOINT` | optional, OpenAI-compatible servers | https URL; default `https://api.openai.com/v1` |
| `GITHUB_TOKEN` | Publish to GitHub | fine-grained token with contents and pull-request write access to one repository |
| `PUBLISH_KEY` | Publish to GitHub | shared key a user must type before publishing |
| `PUBLISH_REPO` | Publish to GitHub | `owner/repository`, the fixed target |
| `GITLAB_AI_TOKEN` | GitLab Duo triage session | token allowed to create Duo sessions in the project |
| `GITLAB_AI_PROJECT_ID` | GitLab Duo triage session | numeric project id |
| `GITLAB_URL` | optional | https; default `https://gitlab.com` |
| `GITLAB_AI_WORKFLOW_DEFINITION` | optional | default `security_analyst_agent/v1` |

Example `.streamlit/secrets.toml` (placeholders only):

```toml
AI_PROVIDER = "anthropic"
AI_API_KEY = "<your-api-key>"
AI_MODEL = "<model-id>"
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
2. **Analysis**: built-in rules, Bandit (run as a subprocess, no shell, private temp dir, timeout; it parses code, never runs it), OSV.dev for pinned PyPI requirements. Missing tools or failed requests show as *unavailable*, and the report lists every check that did not run.
3. **Report**: risk level, strengths, weaknesses, plan; JSON/Markdown with a separately labelled AI section; manual GitLab Duo hand-off brief.
4. **Remediation**: diffs, approval queue, audit trail. Auto-apply only when severity is below high and the fixer is low risk. AI candidates always need approval (enforced in `remediation.apply_remediations`). A finding is marked "Fix available" only when a deterministic fixer can really rewrite its line.
5. **Export**: corrected ZIP; GitHub publishing (new branch and pull request only) when configured. Stage-7 fixes update this canonical project; simulated drift files are never exported.
6. **Deploy**: simulation only; gate, package digest and scan are computed, the rest is simulated.
7. **Rescan**: on-demand comparison with the deployment baseline (new, resolved, remaining) and an optional AI interpretation. Not continuous monitoring.

## AI orchestration

`devsecops_agent/orchestrator.py` asks the model for triage, candidate fixes and summaries, and treats every answer as untrusted: strict JSON parsing, ids checked against real findings, secrets redacted, and each candidate fix must be one line, free of secret-like text, compile (never executed), no longer be flagged by the deterministic scanner, and pass named human approval. Secret-bearing lines are never sent to the model.

**External API provider** (`devsecops_agent/ai/`): set `AI_PROVIDER`, `AI_API_KEY` and `AI_MODEL` as described above. The UI offers a connection test that makes one real request.

**GitLab Duo Agent Platform provider**: submits a read-only triage session through the Flows API (asynchronous; the output lives in GitLab).

## GitLab Duo flow and skill

- `skills/devsecops-triage-remediate/SKILL.md` is the agent skill: triage order, the fixer table and the approval policy.
- `.gitlab/duo/flows/devsecops-triage-remediate.yaml` is the custom flow source. GitLab does not load it automatically: create the flow in the AI Catalog (paste the YAML), enable it in the project, then mention its service account in a merge request comment.
- The flow reads the `self-scan` CI artifact of the merge request pipeline and posts one comment of proposals. It cannot commit, merge or approve.
- `.gitlab/duo/mr-review-instructions.yaml` and `AGENTS.md` configure GitLab Duo code review for this repository.

## Verified versus unverified

| Capability | Evidence |
|---|---|
| Scanner, remediation gates, export, secret redaction, approvals, audit, stage-7 export consistency | unit and headless UI tests in CI |
| Whole seven-stage UI flow, both modes, AI orchestration wiring | headless `AppTest` with a stand-in provider (wiring only) |
| Bandit | really executed in CI tests |
| OSV.dev | mocked in unit tests; **real query in the `live-integration` CI job**, skipped with a reason if the network is unreachable |
| GitLab Duo flow and code review on merge request !1 | real sessions that posted comments (see the merge request) |
| External AI provider | mocked in unit tests; **real call only if** `AI_PROVIDER`, `AI_API_KEY` and `AI_MODEL` are set as masked CI/CD variables; **otherwise unverified** |
| App-to-GitLab Flows API request, GitHub import and publishing | fake transports only: **unverified** |
| Real deployment, continuous monitoring, Semgrep inside the app | not implemented |
| Browser look and feel, hosted deployment | not verified |

To verify live AI in CI, add masked CI/CD variables `AI_PROVIDER`, `AI_API_KEY`, `AI_MODEL`, then read the `live-integration` job log.

## Known limitation: deployment

This tool analyses and repairs code; it does not host it. Stage 6 computes a policy gate, a package digest and a scan, and labels build, release and health check as simulated. A real deployment step would need a target platform and its credentials.

## Repository

`.gitlab-ci.yml` runs pytest, SAST, Secret Detection, `self-scan` and `live-integration`. Dependencies are pinned in `requirements.txt` to the versions CI uses.

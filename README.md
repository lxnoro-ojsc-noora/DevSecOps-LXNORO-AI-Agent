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
| `GITLAB_AI_WORKFLOW_DEFINITION` | optional | default `security_analyst_agent/v1`; ignored when `GITLAB_AI_CONSUMER_ID` is set |
| `GITLAB_AI_CONSUMER_ID` | run the existing GitLab flow | numeric AI Catalog item consumer id of the flow enabled in the project (GraphQL `aiCatalogConfiguredItems`); no external model key is needed |
| `GITLAB_AI_MR_IID` | optional | default merge request number the flow triages |
| `GITLAB_AI_UPLOAD_FLOW` | optional, `1` | send an uploaded project's findings to the catalog flow instead of the agent; set only after the catalog copy of the flow contains the `UPLOADED-PROJECT-FINDINGS` mode check from `.gitlab/duo/flows/` |

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

**GitLab Duo Agent Platform provider** (asynchronous, the output lives in GitLab, no external model key). Choose "GitLab Duo Agent Platform" in the Analysis stage; two separate cards can appear:

- **GitLab Duo triage of the uploaded project**: sends the current analysis' redacted findings (rule, severity, file and line, redacted evidence, summary counts; never code) to a read-only foundational agent session. The agent is told it cannot read the uploaded files and must not describe this repository, so the answer is advice on the findings, not a code review. The card shows the real session status and the agent's final answer read from the session trace, and ties both to the current analysis: a new analysis, project or mode switch clears them.
- **Repository merge-request flow (not your upload)**: shown only when `GITLAB_AI_CONSUMER_ID` is set. It starts the AI Catalog flow already enabled in the project, which triages the CI security findings (`self-scan` report) of a merge request of the configured GitLab project, and displays the comment that flow posts. It does not analyse the project uploaded to the app. The catalog flow cannot take findings: its prompt, stored in the AI Catalog, treats the goal as a merge-request reference.

**Uploaded project through the catalog flow (opt-in):** with `GITLAB_AI_CONSUMER_ID` and `GITLAB_AI_UPLOAD_FLOW=1`, the first card starts the catalog flow instead of the agent. The redacted findings travel in the `goal`, behind the first line `UPLOADED-PROJECT-FINDINGS`; the flow answers in its final answer, with no tools and no comment, and the app reads that answer from the session's own trace. This works only after you paste the updated `.gitlab/duo/flows/devsecops-triage-remediate.yaml` into the AI Catalog flow (the app cannot edit it). Without the flag the read-only agent is used. A session that is not finished after 30 minutes is reported as stopped waiting; the app never shows a comment from another merge request.

Candidate fixes and per-finding explanations still use the external provider, because a Duo session is not a synchronous completion API.

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
| GitLab Duo triage of an uploaded project's findings | a real agent session (10115413) answered from a goal written in the app's format, using only the findings; the app's own HTTP client and trace parsing are verified with stand-in transports only |
| Existing catalog flow on a repository merge request | real session (10114123) posted a triage comment; the app's own client is verified with stand-in transports only |
| Uploaded findings through the catalog flow (`GITLAB_AI_UPLOAD_FLOW`) | stand-in transports only; **unverified** against GitLab until the catalog flow is updated and a real session is run |
| Fine-grained token (`create_duo_workflow` + `read_duo_workflow`) | per GitLab's docs, `GET /ai/duo_workflows/workflows/:id` is unavailable to fine-grained tokens, so the app shows the session status as "unknown" and reads only the trace; a partial message is labelled as such. Whether a session can be created and read with exactly these two permissions is **unverified** until a live session is run |
| GitHub import and publishing | fake transports only: **unverified** |
| Real deployment, continuous monitoring, Semgrep inside the app | not implemented |
| Browser look and feel, hosted deployment | not verified |

To verify live AI in CI, add masked CI/CD variables `AI_PROVIDER`, `AI_API_KEY`, `AI_MODEL`, then read the `live-integration` job log.

## Known limitation: deployment

This tool analyses and repairs code; it does not host it. Stage 6 computes a policy gate, a package digest and a scan, and labels build, release and health check as simulated. A real deployment step would need a target platform and its credentials.

## Repository

`.gitlab-ci.yml` runs pytest, SAST, Secret Detection, `self-scan` and `live-integration`. Dependencies are pinned in `requirements.txt` to the versions CI uses.

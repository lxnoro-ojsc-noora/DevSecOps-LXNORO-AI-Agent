# DevSecOps LXNORO AI Agent

**Secure code. Controlled remediation. Human-approved decisions.**

A Streamlit security command center built for the GitLab Transcend hackathon. It scans a source ZIP or a public GitHub repository with real static engines, optionally uses AI to explain and prioritise the findings, applies **only low-risk fixes automatically** and **requires a named human approval for every high or critical change and every AI-proposed change**. Uploaded code is never executed.

- Repository: https://gitlab.com/gitlab-ai-hackathon/transcend-october-2026/43725688/showcase
- License: [MIT](https://gitlab.com/gitlab-ai-hackathon/transcend-october-2026/43725688/showcase/-/blob/main/LICENSE)
- Hosted demo: **not available / not verified** (no demo URL is configured in this repository)

## Overview

**Problem.** Scanners produce long finding lists. Teams must decide which findings are real, which matter most and which fixes are safe to apply. Automated fixers can change behaviour without review, and AI suggestions can be wrong or can leak secrets into prompts. Manual triage is slow, and nothing records who approved what.

**Solution.** The agent separates *finding* from *fixing*. Deterministic scanners are authoritative. AI is advisory and treated as untrusted until its output passes deterministic checks. Low-risk fixes may be applied automatically. Anything riskier waits for a named human, and every decision lands in an audit trail.

**Intended users.** Developers and security reviewers who want a quick, transparent first pass over a Python-centric project, and a controlled path from findings to a corrected copy of the code.

## Key features

- **Intake:** ZIP upload (up to 25 MB) or public GitHub repository import by URL.
- **Analysis:** built-in rules, Bandit (Python SAST) and OSV.dev advisories for pinned PyPI requirements. A check that could not run is shown as *unavailable* and is listed in the report.
- **Report:** risk level, strengths, weaknesses, severity, redacted evidence and a prioritised remediation plan, downloadable as JSON or Markdown, plus a manual GitLab Duo hand-off brief.
- **AI-assisted triage:** optional external model provider (explanations, triage, candidate fixes) and a GitLab Duo Agent Platform session that receives **redacted findings, never source code**.
- **Policy-gated remediation:** diffs, an approval queue and an audit trail. Auto-apply only when severity is below high **and** the fixer is classed low risk.
- **Re-scan comparison:** on-demand rescan against the deployment baseline (new, resolved, remaining).
- **Export:** corrected project ZIP, and GitHub publishing to a new branch plus pull request when configured.
- **Simulation mode:** the whole workflow runs with no credentials, with simulated parts labelled.

## The seven stages and how data moves

1. **Intake:** a ZIP or a GitHub archive is read in memory by `safe_zip`. Text files, binary files and skipped entries (with reasons) become the project.
2. **Analysis:** the text files go through the built-in rules, Bandit and OSV.dev (`pipeline.run_scans`). The result is a list of findings plus a list of checks, each marked performed, skipped or unavailable. An AI provider can add explanations or a Duo triage session.
3. **Report:** findings and checks become a structured report. AI text sits in a separately labelled section and never changes deterministic findings.
4. **Remediation:** each finding with a deterministic fixer becomes a planned change with a diff. Low-risk changes can be applied automatically. The rest wait for a named approver. AI candidate fixes join the same queue and always need approval.
5. **Export:** the corrected files are zipped for download. GitHub publishing creates a new branch and a pull request.
6. **Deploy (simulation only):** a policy gate, package digest and security scan are computed. Build, release and health check are simulated and labelled.
7. **Rescan:** a fresh scan is compared with the deployment baseline. New findings go through the same approval rules.

## What makes it distinctive

- **Transparent status:** simulated, unavailable and skipped are shown as such. Live mode never falls back to simulation after an error.
- **Human oversight:** approvals need a named approver and are enforced in `remediation.apply_remediations`, not only in the UI.
- **Secret redaction:** evidence is redacted before display, reporting, export or any AI request. Secret-bearing lines are never sent to a model.
- **Untrusted AI:** model output is parsed strictly, ids are checked against real findings, and a candidate fix must be one line, free of secret-like text, compile (never executed) and no longer be flagged by the scanner.

## Technology stack

Python, Streamlit, Bandit, OSV.dev (public batch API), `requests`, GitLab Duo Agent Platform (Flows API and AI Catalog flow), GitHub REST API, pytest and GitLab CI (SAST and Secret Detection templates). Pinned versions are in `requirements.txt` (`streamlit`, `requests`, `bandit`). pytest is installed by the CI job.

## Setup and usage

**Prerequisites.** Python 3 and `pip`. CI uses the `python:3.12-slim` image. Other Python versions were not tested here.

```
pip install -r requirements.txt
streamlit run app.py          # http://localhost:8501
python -m pytest -q           # unit and headless UI tests; tests marked live are excluded
```

These commands are the ones CI uses (`pip install` and `pytest`). Starting the app locally was not re-run for this README update.

Simulation mode, the built-in rules, Bandit and OSV.dev need no credentials. The app opens in Live mode by default. Switch the mode at the top of the page. Switching resets the workflow.

Command-line scan with the built-in rules only (static, nothing executed):

```
python -m devsecops_agent.cli <path> [--exclude <dir>] [--out report.json] [--fail-on-high]
```

### Configuration (Live mode)

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

## Live and Simulation mode

| | LIVE | SIMULATION |
|---|---|---|
| Scanners | built-in rules, **Bandit**, **OSV.dev** (network) | built-in rules, Bandit, labelled offline advisory fixture (not real advisories) |
| AI | your configured provider only; no key means "unavailable" | deterministic templates, labelled SIMULATED, not a model |
| Intake | ZIP upload, public GitHub import | the above plus a built-in demo project |
| GitHub publishing / GitLab AI | available when configured | disabled: no external changes |
| Deployment | **simulation only** | simulation |

Both modes share the same approval, validation and audit rules.

## Architecture

| Path | Role |
|---|---|
| `app.py` | Streamlit entry point for the seven stages. `.streamlit/config.toml` sets the dark theme. |
| `dashboard/` | Views, components, theme and session state (`state.py`). Security decisions are not made here. |
| `devsecops_agent/safe_zip.py`, `intake.py` | Safe in-memory archive handling; ZIP and GitHub intake. |
| `devsecops_agent/scanners.py`, `engines.py`, `pipeline.py` | Built-in rules, Bandit and OSV.dev adapters, combined scan. |
| `devsecops_agent/remediation.py` | Approval policy, fixers, decisions, audit log. |
| `devsecops_agent/orchestrator.py`, `ai/` | AI triage and candidate fixes; external provider and GitLab Duo clients. |
| `devsecops_agent/report.py`, `export.py` | Report building (JSON, Markdown, Duo brief); corrected ZIP and diffs. |
| `devsecops_agent/github_io.py` | GitHub archive import and branch plus pull request publishing. |
| `devsecops_agent/deploy.py`, `monitor.py` | Deployment simulation; rescan history and comparison. |
| `devsecops_agent/cli.py`, `demo.py` | Command-line scan; built-in demo project. |
| `tests/` | pytest suite. |
| `.gitlab/duo/`, `skills/` | Duo flow source, merge-request review instructions, agent skill. |

## Security and limitations

- **Safe ZIP handling:** archives are read in memory; nothing is extracted to disk. Absolute paths, `..` traversal and NUL bytes reject the archive. Limits: 25 MB archive, 3000 entries, 2 MB per file, 50 MB total, and a compression-ratio check against ZIP bombs. Symlinks, encrypted entries, duplicates, oversize files and VCS or dependency directories (`.git`, `node_modules`, `venv` and similar) are skipped, listed with reasons and left out of the exported ZIP.
- **No execution:** uploaded code is never run, imported or evaluated. Bandit parses files and is started without a shell, with a minimal environment, a timeout (90 s), a file cap (500) and a private temporary directory.
- **Secrets:** evidence is redacted. `.streamlit/secrets.toml` and `.env` are git-ignored. The GitLab and GitHub clients scrub tokens from error text.
- **Approval gates:** high or critical severity, any fixer not classed low risk and every AI candidate need a named approver. Simulated drift files are never exported.
- **GitHub publishing:** creates a new branch and a pull request, never force-pushes and refuses the default branch.
- **Scope:** static, pattern-based checks. No finding does not prove the code is secure.

## Current implementation status

| Area | Status |
|---|---|
| Intake, Analysis, Report, Remediation, Export (ZIP) | Implemented and covered by unit and headless UI tests |
| **Deploy** | **Simulation only.** Nothing is built, deployed or hosted. Build, release and health check are simulated and labelled. |
| **Rescan** | On-demand comparison with the deployment baseline. **Continuous monitoring is not implemented.** |
| Netlify (or any real deployment) adapter | **Not implemented** |
| Real post-deployment health checks | **Not implemented** |
| Rescan verification that targeted findings were fixed | **Not implemented** (rescan compares with the deployment baseline only) |
| Security report inside the exported ZIP | **Not implemented.** The report is a separate JSON or Markdown download. |
| Semgrep inside the app | Not implemented (Semgrep appears only as a CI job) |

The open merge request for a Netlify adapter was empty when this README was written. Do not read it as delivered.

### Verified versus unverified

| Capability | Evidence |
|---|---|
| Scanner, remediation gates, export, secret redaction, approvals, audit, stage-7 export consistency | unit and headless UI tests in CI |
| Whole seven-stage UI flow, both modes, AI orchestration wiring | headless `AppTest` with a stand-in provider (wiring only) |
| Bandit | really executed in CI tests |
| OSV.dev | mocked in unit tests; a real query is attempted in the `live-integration` CI job, which skips with a reason if the network is unreachable |
| GitLab Duo flow and code review on merge request !1 | real sessions that posted comments, as recorded in the merge request |
| External AI provider | mocked in unit tests; **unverified live** unless `AI_PROVIDER`, `AI_API_KEY` and `AI_MODEL` are set as masked CI/CD variables |
| GitLab Duo triage of an uploaded project's findings | a real agent session answered from a goal in the app's format; the app's own HTTP client and trace parsing are verified with stand-in transports only |
| Existing catalog flow on a repository merge request | a real session posted a triage comment; the app's own client is verified with stand-in transports only |
| Uploaded findings through the catalog flow (`GITLAB_AI_UPLOAD_FLOW`) | stand-in transports only; **unverified** until the catalog flow is updated and a real session is run |
| Fine-grained token (`create_duo_workflow` + `read_duo_workflow`) | GitLab documents the session-status endpoint as unavailable to fine-grained tokens, so the app shows status "unknown" and reads only the trace. Whether a session can be created and read with exactly these two permissions is **unverified** |
| GitHub import and publishing | fake transports only: **unverified live** |
| Hosted app, browser look and feel | **not verified** |

### GitLab Duo integration

- **Triage of the uploaded project:** in Live mode, choose "GitLab Duo Agent Platform" in the Analysis stage. The redacted findings (rule, severity, file and line, redacted evidence, counts) go to a read-only agent session. The agent cannot read the uploaded files, so the answer is advice on the findings, not a code review. The card shows the real session status and the answer read from the session trace.
- **Repository merge-request flow:** shown only when `GITLAB_AI_CONSUMER_ID` is set. It runs the AI Catalog flow already enabled in the project on a merge request of that project. It does not analyse your upload.
- **Opt-in upload flow:** with `GITLAB_AI_CONSUMER_ID` and `GITLAB_AI_UPLOAD_FLOW=1`, findings go to the catalog flow. This works only after you paste the updated `.gitlab/duo/flows/devsecops-triage-remediate.yaml` into the AI Catalog flow, which the app cannot do. Without the flag the read-only agent is used.
- Candidate fixes and per-finding explanations use the external provider, because a Duo session is asynchronous.
- A session unfinished after 30 minutes is reported as stopped waiting.

## Verification (CI)

`.gitlab-ci.yml` defines these jobs:

- `unit-tests` (required): the pytest suite with mocked or stand-in transports and headless UI tests.
- SAST and Secret Detection: GitLab templates, allowed to fail.
- `self-scan`: the built-in scanner over this repository only, allowed to fail.
- `live-integration` (allowed to fail): tests marked `live`. A green result does not show that a live integration works, because tests skip with a reason when credentials or network are missing. Read the job log to see what really ran.

A green pipeline therefore proves the unit and UI tests passed. It does not prove the live GitHub, external AI or Duo upload paths.

## License

MIT License. Copyright (c) 2026 NOORA AL-MAOLAI, Research Center: LXNORO OJSC. See [LICENSE](LICENSE).

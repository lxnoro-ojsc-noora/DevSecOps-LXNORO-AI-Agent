# DevSecOps LXNORO AI Agent

Streamlit security command center (GitLab Transcend hackathon). It statically analyzes a source ZIP or a public GitHub repository, reports evidence-based findings, applies **only low-risk fixes automatically**, and **requires a named human approval for every high or critical change**. Uploaded code is never executed.

MIT License. Copyright (c) 2026 NOORA AL-MAOLAI, Research Center: LXNORO OJSC.

## Run

```
pip install -r requirements.txt
streamlit run app.py      # http://localhost:8501
python -m pytest -q
```

No secrets are needed for the core workflow. AI and GitHub publishing stay disabled until configured.

## Seven stages (locked until prerequisites exist)

1. **Intake**: ZIP upload or public GitHub import (archive download, never a clone). In-memory validation against path traversal, symlinks, encrypted entries, size, entry-count and ZIP-bomb limits.
2. **Analysis**: deterministic static rules with redacted evidence; performed, skipped and unavailable checks are listed. Optional AI provider.
3. **Report**: risk level, strengths, weaknesses, prioritized plan, limitations; JSON, Markdown and a manual GitLab Duo hand-off brief.
4. **Remediation**: diffs per fix. Automatic only when severity is below high AND the fixer is low risk; everything else needs a named approver (enforced in `devsecops_agent/remediation.py`). Audit timeline.
5. **Export**: corrected ZIP (real). GitHub publishing: new branch and pull request only, gated.
6. **Deploy**: **simulation only**. Gate, package digest and scan are computed; build, release and health check are simulated and labelled. No URL.
7. **Rescan**: on-demand comparison with the deployment baseline (new, resolved, remaining). The drift button is a labelled simulation. Not continuous monitoring.

## AI providers (optional, advisory)

Findings never depend on AI. If a provider is missing or fails, the workflow continues and the failure is shown. AI text is labelled advisory.

- **External API** (`devsecops_agent/ai/external.py`): `AI_PROVIDER` (`anthropic`, `gemini` or `openai` for any OpenAI-compatible server), `AI_API_KEY`, `AI_MODEL`, and for `openai` an optional https `AI_ENDPOINT`. Only rule titles, locations and redacted evidence are sent. Settings come from secrets or environment variables, never from the UI.
- **GitLab Duo Agent Platform** (`devsecops_agent/ai/gitlab_duo.py`): uses the documented, experimental Flows API (`POST /api/v4/ai/duo_workflows/workflows`) to submit a read-only, asynchronous triage session to a GitLab project. It runs in GitLab CI, uses Duo quota, and its output appears in GitLab. Not a synchronous API. Settings: `GITLAB_AI_TOKEN`, `GITLAB_AI_PROJECT_ID` (numeric), optional `GITLAB_URL` (https) and `GITLAB_AI_WORKFLOW_DEFINITION`.
- The GitLab Duo Chat completions REST API is documented as internal-only on GitLab.com, so it is not used and the UI shows it as unsupported.

## GitHub publishing (optional)

Disabled unless `GITHUB_TOKEN` (fine-grained, one repository), `PUBLISH_REPO` (`owner/repository`) and `PUBLISH_KEY` are all set. The target repo is fixed, the default branch is refused, history is never rewritten, and the user must verify access, enter the key and confirm.

## Verification status

- **Verified in CI:** scanner, approval gate, export, and a headless run of the seven-stage UI flow (Streamlit `AppTest`). GitHub and AI code paths are verified only against fake transports.
- **Not verified:** live calls to GitHub, the GitLab Flows API or an external AI provider; the look of the UI in a real browser; Streamlit Community Cloud deployment.
- **Not implemented:** real deployment, continuous monitoring, CVE lookups, Semgrep/Bandit inside the app.

## GitLab Duo in this repository

`.gitlab/duo/mr-review-instructions.yaml` (Duo Code Review instructions) and `AGENTS.md` (project instructions for Duo Chat and flows). CI: `.gitlab-ci.yml` runs pytest, SAST, Secret Detection and an informational `self-scan`.

## Streamlit Community Cloud

Connect the GitHub repository, set the main file to `app.py`, and add secrets only for the optional features.

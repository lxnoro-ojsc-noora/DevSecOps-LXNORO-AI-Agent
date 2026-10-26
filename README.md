# DevSecOps LXNORO AI Agent

A Streamlit app for the GitLab Transcend hackathon. It statically analyzes a source-code ZIP or a public GitHub repository, reports evidence-based findings, applies **only low-risk fixes automatically**, and **requires a named human approval for every high or critical change**. Uploaded code is never executed.

License: MIT (see `LICENSE`). Copyright (c) 2026 NOORA AL-MAOLAI, Research Center: LXNORO OJSC.

## The seven stages: what is real and what is not

| # | Stage | Status |
|---|-------|--------|
| 1 | Intake: ZIP upload, public GitHub repo import | Real. Hardened in-memory ZIP handling (path traversal, symlinks, size/entry limits, ZIP-bomb ratio). GitHub import downloads an archive (public repos only); not exercised against live GitHub from CI. |
| 2 | Analysis | Real deterministic pattern rules (secrets, risky Python/JS APIs, Dockerfile, `.env`, dependency pinning). Optional AI explanations need `AI_PROVIDER`, `AI_API_KEY`, `AI_MODEL`; that code path is unit-tested with a fake transport only, not against a live provider. CVE lookups and Semgrep/Bandit are **not** run by the app. |
| 3 | Report | Real. JSON and Markdown, redacted evidence, strengths, weaknesses, prioritized plan, stated limitations. |
| 4 | Remediation | Real. Auto-apply only for low-severity-class, low-risk deterministic fixes. High/critical severity, or any non-low-risk fix, stays pending until a named approver approves it. Originals are never mutated; every decision and action goes to an audit trail. |
| 5 | Export / GitHub | ZIP export is real. GitHub publishing (new branch + pull request via the Git Data API, never the default branch, never force) is implemented and tested with a fake transport only. It stays disabled unless `GITHUB_TOKEN`, `PUBLISH_KEY` and `PUBLISH_REPO` are configured, and it has **not been verified against live GitHub**. |
| 6 | Deployment | **Simulation only.** Policy gate, package digest and scan are computed; build, release and health check are simulated and labelled. No URL is produced. |
| 7 | Rescan | On-demand rescan is real. The drift button is a labelled simulation. There is no continuous monitoring. A new high/critical finding still needs human approval. |

## Run locally

```
pip install -r requirements.txt
streamlit run app.py
python -m pytest -q
```

## Configuration (optional; never commit these)

Set as Streamlit secrets (Community Cloud: app settings, Secrets) or environment variables:

- `AI_PROVIDER` (`anthropic` or `gemini`), `AI_API_KEY`, `AI_MODEL`: enable AI explanations. The model name is deliberately not hard-coded.
- `GITHUB_TOKEN` (fine-grained, single repository, contents and pull requests write), `PUBLISH_REPO` (`owner/repository`), `PUBLISH_KEY` (a passphrase you choose): enable publishing. Visitors of a public app must know `PUBLISH_KEY`, and the target repository is fixed by `PUBLISH_REPO`.

## Security model

- No uploaded or imported code is executed, imported or evaluated; all checks are static.
- ZIPs are read in memory with limits; unsafe archives are rejected, unsuitable entries are skipped and listed.
- Secret-like evidence is redacted before it reaches the UI, reports, AI providers or logs.
- Tokens are never rendered or included in error messages.
- Limits: pattern rules produce false positives and negatives; absence of findings is not proof of security.

## GitLab Duo Agent Platform in this repository

Configured in the repo (these are the documented GitLab mechanisms used):

- `.gitlab/duo/mr-review-instructions.yaml`: custom review instructions that GitLab Duo Code Review appends to its standard criteria, focused on the approval policy and untrusted-input handling.
- `AGENTS.md`: project instructions read by GitLab Duo Chat and foundational/custom flows (not Code Review).
- Duo flows available in this project (Code Review, Developer, Fix CI/CD Pipeline, SAST flows) are started from GitLab; see the merge request for the sessions actually run.

The app itself does **not** call GitLab Duo. It can export a text hand-off brief for open high/critical findings that you paste into a Duo flow manually.

## CI

`.gitlab-ci.yml` runs pytest (including a Streamlit app smoke test), GitLab SAST, Secret Detection, and `self-scan`, which runs this tool's scanner over this repository only (informational).

## Deploy on Streamlit Community Cloud

Connect the GitHub repository, choose the branch, and set the main file to `app.py`. Add secrets only if you want AI explanations or publishing.

# AGENTS.md

DevSecOps LXNORO AI Agent: a Streamlit app that statically analyzes uploaded or imported source code, reports findings, applies only low-risk fixes automatically, and requires named human approval for high/critical changes.

## Layout
- `app.py`: Streamlit entry point (seven stages); views and session state live in `dashboard/`. `.streamlit/config.toml`: dark theme.
- `devsecops_agent/`: `safe_zip` (intake), `scanners` (built-in rules), `engines` (Bandit, OSV.dev), `pipeline` (combined scan), `remediation` (policy, fixers, approvals, audit), `orchestrator` (AI triage and candidate fixes), `report`, `export`, `github_io`, `intake`, `ai/` (optional providers), `deploy` (simulation), `monitor` (on-demand rescan), `cli`.
- `tests/`: pytest suite. Run `python -m pytest -q`.

## Rules for changes
- Never execute, import or evaluate uploaded or imported project code.
- Never auto-apply high or critical severity fixes, or any fix not classed low risk. Keep the policy in `remediation.needs_approval`.
- Never log, render or report secrets or tokens; evidence strings must stay redacted.
- Label simulated features as simulated. Do not claim a deployment, push or scan happened unless it did.
- GitHub publishing must create a new branch and a pull request; never force-push or touch the default branch.
- Add or update tests for every behaviour change and keep CI green.

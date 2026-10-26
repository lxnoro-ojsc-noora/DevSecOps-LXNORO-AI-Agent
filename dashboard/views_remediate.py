"""Stage views 4 and 5: Remediation and approvals, Export and publishing.

Approval gating is enforced in devsecops_agent.remediation; these views only collect decisions.
"""
from __future__ import annotations

import hashlib

import streamlit as st

from devsecops_agent import export, github_io, remediation

from . import components as C
from .state import S, SCOPES, apply_fixes, cfg_get, decide, goto, safe_name


def item_status(r, decisions: dict, statuses: dict) -> str:
    status = statuses.get(r.finding_id)
    if status:
        return status
    d = decisions.get(r.finding_id)
    if d:
        return d.decision
    return "awaiting_approval" if r.needs_approval else "ready"


def render_queue(prefix: str, plan: list) -> None:
    """Approval queue shared by stage 4 and the post-deployment rescan stage."""
    sc = SCOPES[prefix]
    decisions = S[sc["decisions"]]
    result = S[sc["apply"]]
    statuses = result.statuses if result else {}
    if not plan:
        C.empty_state("shield-check", "No deterministic fixes available",
                      "Remaining findings need manual remediation. See the prioritized plan in the report.")
        return
    if any(r.needs_approval for r in plan):
        with st.container(border=True):
            C.section("Approver identity",
                      "A named human must approve or reject every high-risk change. Decisions are written to the audit trail.", "user")
            st.text_input("Approver name", key=f"{prefix}_approver", max_chars=80,
                          placeholder="Full name of the approving person", label_visibility="collapsed")
            if S.get(f"{prefix}_err"):
                st.warning(S[f"{prefix}_err"])
    for r in plan:
        digest = hashlib.sha256(r.finding_id.encode("utf-8")).hexdigest()[:10]
        with st.container(border=True):
            C.md(C.queue_header(r, item_status(r, decisions, statuses)))
            st.code(r.diff or "(no diff)", language="diff")
            if r.needs_approval:
                c1, c2, _ = st.columns([1, 1, 3])
                c1.button("Approve", key=f"{prefix}_ok_{digest}", on_click=decide, args=(prefix, r, "approved"),
                          icon=":material/check:")
                c2.button("Reject", key=f"{prefix}_no_{digest}", on_click=decide, args=(prefix, r, "rejected"),
                          icon=":material/close:")
                d = decisions.get(r.finding_id)
                if d:
                    st.caption(f"Decision: {d.decision} by {d.approver} at {d.ts}")
    st.button("Apply low-risk fixes and approved changes", key=f"{prefix}_apply", on_click=apply_fixes,
              args=(prefix,), icon=":material/build:", type="primary")
    if result:
        counts: dict = {}
        for v in statuses.values():
            counts[v] = counts.get(v, 0) + 1
        st.caption("Last apply: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
                   + ". Changes without an approval stay unapplied.")


def view_remediation() -> None:
    C.hero("Remediation and Approvals",
           "Review every proposed change as a diff. Low-risk fixes can be applied automatically; everything else waits for a named human.",
           "shield-check", "STAGE 04")
    plan = S.plan
    decisions = S.decisions
    statuses = S.apply_result.statuses if S.apply_result else {}
    C.kpi_grid([
        ("Auto-eligible", sum(1 for r in plan if not r.needs_approval), "low risk", "#34d399", "check-circle"),
        ("Need approval", sum(1 for r in plan if r.needs_approval), "high risk", "#ffd23f", "lock"),
        ("Approved", sum(1 for d in decisions.values() if d.decision == "approved"), "by a named human", "#22d3ee", "user"),
        ("Rejected", sum(1 for d in decisions.values() if d.decision == "rejected"), "not applied", "#ff3b6b", "x"),
        ("Applied", sum(1 for v in statuses.values() if v == "applied"), "in corrected copy", "#8b5cf6", "shield-check"),
    ])
    with st.container(border=True):
        C.section("Approval policy", "Enforced in the backend, not only in the buttons.", "lock")
        C.checklist([
            ("ok", "Automatic only when severity is below high AND the fixer is classed low risk."),
            ("warn", "High or critical findings, and any non-low-risk fix, are never applied without a named approval."),
            ("ok", "Original files are never modified; fixes are applied to a copy and every action is audited."),
        ])
    render_queue("p2", plan)
    with st.container(border=True):
        C.section("Audit trail", "Decisions and remediation actions, newest first (UTC).", "list")
        C.md(C.timeline(S.audit))
    if S.apply_result:
        st.button("Continue to export", on_click=goto, args=(5,), key="cta_4", icon=":material/arrow_forward:", type="primary")


def _verify_github() -> None:
    pub = github_io.load_publish_config(cfg_get)
    if pub:
        S.gh_access = github_io.verify_access(pub.token, pub.repo)


def _export_card(changed: dict) -> None:
    with st.container(border=True):
        C.section("Corrected project", "Download the remediated source as a ZIP archive.", "package")
        if S.corrected is None:
            C.empty_state("package", "Nothing to export yet",
                          "Apply fixes in the Remediation stage first. The ZIP is built from the corrected files.")
            st.button("Go to remediation", on_click=goto, args=(4,), key="cta_export_back", icon=":material/arrow_back:")
            return
        C.kpi_grid([
            ("Files changed", len(changed), "", "#22d3ee", "file"),
            ("Files in ZIP", len(S.corrected) + len(S.project.binary_files), "", "#8b5cf6", "package"),
            ("ZIP size", f"{len(S.zip_bytes) / 1024:.1f} KB", "", "#34d399", "download"),
        ])
        st.download_button("Download corrected project (ZIP)", S.zip_bytes,
                           file_name=f"{safe_name(S.project.name)}-corrected.zip", mime="application/zip",
                           icon=":material/download:", key="dl_zip", type="primary")
        st.caption("Entries skipped at intake (symlinks, oversize files, VCS and dependency folders) are not in the ZIP.")
        diffs = export.diff_summary(S.project.text_files, S.corrected)
        with st.expander(f"Review changes ({len(diffs)} file(s))", expanded=bool(diffs)):
            if not diffs:
                st.caption("No files changed yet.")
            for path, diff in diffs:
                st.markdown(f"`{C.esc(path)}`")
                st.code(diff, language="diff")


def _publish_card(changed: dict) -> None:
    pub = github_io.load_publish_config(cfg_get)
    missing = github_io.publish_blockers(cfg_get)
    access = S.gh_access
    verified = bool(access and access.ok and access.can_push)
    with st.container(border=True):
        C.section("Publish to GitHub", "New branch and pull request only. Never the default branch, never a force-push.", "github")

        def have(key: str) -> str:
            return "ok" if cfg_get(key) else "muted"

        C.checklist([
            (have("GITHUB_TOKEN"), "GITHUB_TOKEN configured (secret, never displayed)"),
            (have("PUBLISH_KEY"), "PUBLISH_KEY configured (visitors must know it)"),
            (have("PUBLISH_REPO"), "PUBLISH_REPO configured (target repository is fixed)"),
            ("ok" if verified else "muted", "GitHub access verified: the token can push"),
            ("ok" if changed else "muted", "There are changed files to publish"),
        ])
        if missing:
            st.warning("Publishing is disabled. Missing settings: " + ", ".join(missing)
                       + ". Configure them as Streamlit secrets; never put them in source control.")
        st.button("Verify GitHub access", on_click=_verify_github, disabled=pub is None,
                  icon=":material/lock_open:", key="gh_verify")
        if access:
            (st.success if verified else st.error)(access.message)
        if pub and verified:
            st.text_input("Base branch", value=access.default_branch, key="gh_base")
            st.text_input("New branch (the default branch is refused)", value=S.branch_default, key="gh_branch")
            key = st.text_input("Publish key", type="password", key="gh_key")
            confirm = st.checkbox(f"I approve creating this branch and a pull request in {pub.repo}", key="gh_confirm")
            if st.button("Publish branch and pull request", disabled=not (changed and key and confirm),
                         icon=":material/publish:", key="gh_publish", type="primary"):
                if not github_io.key_matches(pub, key):
                    st.error("Publish key is incorrect.")
                else:
                    body = ("Automated remediation. Low-risk fixes were applied automatically; high-risk changes only after "
                            "named human approval (see audit trail). Review before merging.\n\nChanged files:\n"
                            + "\n".join(f"- {p}" for p in sorted(changed)))
                    with st.status("Publishing to GitHub...", expanded=True) as status:
                        try:
                            res = github_io.publish_changes(
                                pub.token, pub.repo, S.gh_base, S.gh_branch, changed,
                                "Security remediation by DevSecOps LXNORO AI Agent",
                                "Security remediation by DevSecOps LXNORO AI Agent", body)
                            S.gh_result = res
                            remediation.audit_event(S.audit, "human:publisher", "github_pr_created", "export",
                                                    detail=f"{res.repo} branch {res.branch} commit {res.commit_sha[:8]}")
                            status.update(label="Pull request created", state="complete")
                        except github_io.GitHubError as exc:
                            status.update(label="Publishing failed", state="error")
                            st.error(str(exc))
        res = S.gh_result
        if res:
            st.success(f"Published to {res.repo}: branch {res.branch}, commit {res.commit_sha[:8]}.")
            if res.pr_url:
                st.markdown(f"Pull request: [{res.pr_url}]({res.pr_url})")


def view_export() -> None:
    C.hero("Export and Publishing", "Take the corrected source with you, or publish it for review as a pull request.",
           "package", "STAGE 05")
    changed = export.changed_files(S.project.text_files, S.corrected) if S.corrected is not None else {}
    left, right = st.columns(2, gap="large")
    with left:
        _export_card(changed)
    with right:
        _publish_card(changed)
    if S.corrected is not None:
        st.button("Continue to deployment", on_click=goto, args=(6,), key="cta_5", icon=":material/arrow_forward:", type="primary")

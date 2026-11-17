#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

UPSTREAM_URL = "https://boringssl.googlesource.com/boringssl"
MIRROR_URL = "https://github.com/google/boringssl.git"
UPSTREAM_REF = "refs/heads/main"

PROVENANCE_PATH = Path(".vac/boringssl-upstream.json")
PR_BODY_PATH = Path(".vac/boringssl-sync-pr-body.md")
# The fork's local patches, replayed in this order on every sync. Each patch
# touches only its own paths, and has an invariant in INVARIANTS (by name) and a
# flag it sets in the provenance's `last_verification`. The list may be empty.
LOCAL_PATCHES = [
    {
        "name": "ssl-buffer-zeroing",
        "description": "With BORINGSSL_ZERO_RECORD_BUFFERS defined, allocate TLS record buffers with OPENSSL_malloc so that OPENSSL_free zeroes the decrypted records they hold; upstream's malloc/free otherwise.",
        "path": Path(".vac/patches/ssl-buffer-zeroing.patch"),
        "paths": [Path("ssl/ssl_buffer.cc")],
        "verified_as": "ssl_buffer_zeroing_present",
        "checklist": "Confirm `ssl/ssl_buffer.cc` still allocates and frees record buffers through its helpers, with `OPENSSL_malloc`/`OPENSSL_free` under `BORINGSSL_ZERO_RECORD_BUFFERS` and upstream's `malloc`/`free` otherwise, and that no new plain `malloc`/`free` of record data appeared in `ssl/`.",
    },
]
PATCHED_PATHS = [path for patch in LOCAL_PATCHES for path in patch["paths"]]
PROTECTED_WORKFLOW_DIR = Path(".github/workflows")
SENSITIVE_PATHS = ["crypto/", "ssl/", "include/openssl/", "third_party/fiat/"]


def run(args, *, cwd=None, check=True, capture=True):
    print("+ " + shlex.join(str(a) for a in args))
    proc = subprocess.run(
        [str(a) for a in args],
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and proc.returncode != 0:
        if proc.stdout:
            print(proc.stdout, end="")
        if proc.stderr:
            print(proc.stderr, end="", file=sys.stderr)
        raise SystemExit(proc.returncode)
    return proc


def print_proc_output(proc):
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)


def git(args, **kwargs):
    return run(["git", *args], **kwargs)


def git_output(args, **kwargs):
    return git(args, **kwargs).stdout.strip()


def set_output(name, value):
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as out:
            out.write(f"{name}={value}\n")


def append_summary(text):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as out:
            out.write(text)
            out.write("\n")


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_bool(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def resolve_remote_ref(url, ref):
    output = git_output(["ls-remote", url, ref])
    lines = [line.split() for line in output.splitlines() if line.strip()]
    matches = [parts[0] for parts in lines if len(parts) == 2 and parts[1] == ref]
    if len(matches) != 1:
        fail(f"expected exactly one {ref} from {url}, got {len(matches)}")
    return matches[0]


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as inp:
        for chunk in iter(lambda: inp.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def short_sha(sha):
    return sha[:12]


def require_clean_tree():
    status = git_output(["status", "--short"])
    if status:
        fail("working tree is not clean before sync:\n" + status)


def verify_patch_against_upstream(upstream_sha):
    repo = Path.cwd()
    tmp = Path(tempfile.mkdtemp(prefix="boringssl-upstream-"))
    worktree = tmp / "upstream"
    try:
        git(["worktree", "add", "--detach", str(worktree), upstream_sha])
        for patch in LOCAL_PATCHES:
            run(["git", "apply", str((repo / patch["path"]).resolve())], cwd=worktree)

        for rel_path in PATCHED_PATHS:
            expected = (worktree / rel_path).read_bytes()
            actual = (repo / rel_path).read_bytes()
            if expected != actual:
                fail(
                    f"{rel_path} does not match the local patches applied to "
                    f"upstream {upstream_sha}"
                )
    finally:
        git(["worktree", "remove", "--force", str(worktree)], check=False)
        shutil.rmtree(tmp, ignore_errors=True)


def unmerged_paths():
    output = git_output(["diff", "--name-only", "--diff-filter=U"])
    return [Path(line) for line in output.splitlines() if line.strip()]


def is_protected_workflow_path(path):
    try:
        path.relative_to(PROTECTED_WORKFLOW_DIR)
        return True
    except ValueError:
        return False


def path_exists_at_ref(ref, path):
    return git(["cat-file", "-e", f"{ref}:{path.as_posix()}"], check=False).returncode == 0


def restore_path_from_ref_or_remove(ref, path):
    if path_exists_at_ref(ref, path):
        git(["checkout", ref, "--", str(path)])
        git(["add", str(path)])
    else:
        git(["rm", "-f", "--ignore-unmatch", "--", str(path)])


def replay_local_patch(patch):
    patch_proc = git(["apply", "-3", str(patch["path"])], check=False)
    if patch_proc.returncode == 0:
        git(["add", *[str(path) for path in patch["paths"]]])
        return

    print_proc_output(patch_proc)
    conflicts = unmerged_paths()
    if not conflicts:
        fail(f"local patch {patch['name']} replay failed without producing unmerged paths")

    unexpected = [path for path in conflicts if path not in patch["paths"]]
    if unexpected:
        fail(
            f"local patch {patch['name']} replay produced conflicts outside its paths: "
            + ", ".join(str(path) for path in unexpected)
        )

    for path in conflicts:
        git(["checkout", "--theirs", str(path)])
    git(["add", *[str(path) for path in patch["paths"]]])


def restore_protected_workflow_changes(target_ref):
    output = git_output(["diff", "--name-only", "HEAD", "--", str(PROTECTED_WORKFLOW_DIR)])
    changed = [Path(line) for line in output.splitlines() if line.strip()]
    for path in changed:
        restore_path_from_ref_or_remove(target_ref, path)
    return [str(path) for path in changed]


def resolve_known_conflicts(upstream_sha, target_ref):
    conflicts = unmerged_paths()
    if not conflicts:
        fail("upstream merge failed without producing unmerged paths")

    unexpected = [
        path for path in conflicts
        if path not in PATCHED_PATHS and not is_protected_workflow_path(path)
    ]
    if unexpected:
        fail(
            "upstream merge produced conflicts outside known local paths: "
            + ", ".join(str(path) for path in unexpected)
        )

    workflow_conflicts = [path for path in conflicts if is_protected_workflow_path(path)]
    if workflow_conflicts:
        print(
            "Preserving target branch workflow files for upstream conflicts: "
            + ", ".join(str(path) for path in workflow_conflicts)
        )
        for path in workflow_conflicts:
            restore_path_from_ref_or_remove(target_ref, path)

    patch_conflicts = [path for path in conflicts if path in PATCHED_PATHS]
    if patch_conflicts:
        print(
            "Resolving upstream merge conflicts in known local patch paths: "
            + ", ".join(str(path) for path in patch_conflicts)
        )
        for patch in LOCAL_PATCHES:
            if any(path in patch_conflicts for path in patch["paths"]):
                for path in patch["paths"]:
                    git(["checkout", upstream_sha, "--", str(path)])
                replay_local_patch(patch)

    remaining = unmerged_paths()
    if remaining:
        fail(
            "known local patch conflict resolution left unmerged paths: "
            + ", ".join(str(path) for path in remaining)
        )


def refresh_patch_files(upstream_sha):
    for patch in LOCAL_PATCHES:
        patch_text = git(
            ["-c", "core.abbrev=9", "diff", upstream_sha, "--", *[str(path) for path in patch["paths"]]]
        ).stdout
        if not patch_text.strip():
            fail(f"local patch {patch['name']} is empty after replaying against upstream")
        patch["path"].write_text(patch_text, encoding="utf-8")
        git(["add", str(patch["path"])])


def verify_ssl_buffer_zeroing():
    # With BORINGSSL_ZERO_RECORD_BUFFERS the record buffer must be allocated and
    # released through the zeroing allocator; every call site goes through the
    # helpers, never plain malloc/free.
    ssl_buffer = Path("ssl/ssl_buffer.cc").read_text(encoding="utf-8")
    guard = "#if defined(BORINGSSL_ZERO_RECORD_BUFFERS)"
    if guard not in ssl_buffer or "#else" not in ssl_buffer.split(guard, 1)[1]:
        fail("ssl/ssl_buffer.cc has lost the BORINGSSL_ZERO_RECORD_BUFFERS guard")
    zeroing = ssl_buffer.split(guard, 1)[1].split("#else", 1)[0]
    if "OPENSSL_malloc(" not in zeroing or "OPENSSL_free(" not in zeroing:
        fail("ssl/ssl_buffer.cc's BORINGSSL_ZERO_RECORD_BUFFERS path no longer uses OPENSSL_malloc and OPENSSL_free")
    if "ssl_buffer_alloc(new_cap" not in ssl_buffer or ssl_buffer.count("ssl_buffer_free(buf_)") != 2:
        fail("ssl/ssl_buffer.cc no longer allocates and frees record buffers through its helpers")
    raw = [line.strip() for line in ssl_buffer.splitlines()
           if line.strip().startswith(("free(", "new_buf = (uint8_t *)malloc("))]
    if raw:
        fail("ssl/ssl_buffer.cc calls plain malloc or free outside its helpers: " + ", ".join(raw))


INVARIANTS = {
    "ssl-buffer-zeroing": verify_ssl_buffer_zeroing,
}


def verify_invariants():
    for patch in LOCAL_PATCHES:
        INVARIANTS[patch["name"]]()


def limited_lines(text, limit=100):
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) <= limit:
        return lines
    return lines[:limit] + [f"... truncated {len(lines) - limit} additional lines ..."]


def format_block(lines, empty_text):
    if not lines:
        return empty_text
    return "\n".join(f"- `{line}`" for line in lines)


def commit_subject(sha):
    return git_output(["show", "-s", "--format=%h %s", sha])


def commits_missing_review_metadata(previous_sha, upstream_sha):
    commits = git_output(["rev-list", "--reverse", f"{previous_sha}..{upstream_sha}"])
    missing = []
    for sha in [line for line in commits.splitlines() if line.strip()]:
        body = git_output(["show", "-s", "--format=%B", sha])
        has_review = "Reviewed-on: https://boringssl-review.googlesource.com/" in body
        has_reviewer = "Reviewed-by:" in body
        has_change_id = "Change-Id:" in body
        if not has_review or not has_reviewer or not has_change_id:
            missing.append(commit_subject(sha))
    return missing


def mirror_cross_check_status(upstream_sha, mirror_sha, allow_mirror_mismatch):
    if upstream_sha == mirror_sha:
        return "passed"

    mirror_is_ancestor = git(
        ["merge-base", "--is-ancestor", mirror_sha, upstream_sha],
        check=False,
    ).returncode == 0
    if mirror_is_ancestor:
        behind_count = int(git_output(["rev-list", "--count", f"{mirror_sha}..{upstream_sha}"]))
        commit_word = "commit" if behind_count == 1 else "commits"
        return f"GitHub mirror is behind canonical upstream by {behind_count} {commit_word}"

    if allow_mirror_mismatch:
        return "allowed non-ancestor mismatch by manual input"

    fail(
        "GitHub mirror does not match canonical BoringSSL upstream and is not "
        "an ancestor of it: "
        f"canonical={upstream_sha} mirror={mirror_sha}"
    )


def sensitive_commits(previous_sha, upstream_sha):
    output = git_output(
        [
            "log",
            "--format=%h %s",
            f"{previous_sha}..{upstream_sha}",
            "--",
            *SENSITIVE_PATHS,
        ]
    )
    return limited_lines(output)


def build_pr_body(
    *,
    previous_sha,
    upstream_sha,
    mirror_sha,
    mirror_status,
    fast_forward_status,
    commit_count,
    sensitive,
    missing_metadata,
    skipped_workflow_paths,
):
    sensitive_text = format_block(
        limited_lines("\n".join(sensitive)),
        "No commits in the upstream range touched the monitored paths.",
    )
    missing_text = format_block(
        limited_lines("\n".join(missing_metadata)),
        "No commits in the upstream range were missing the expected review metadata.",
    )
    skipped_workflow_text = format_block(
        limited_lines("\n".join(skipped_workflow_paths)),
        "No upstream workflow changes were skipped.",
    )

    return f"""## Summary
Syncs `vacp2p/boringssl` with BoringSSL upstream `main`.

## Security Review
- Canonical upstream: `{UPSTREAM_URL}` `{UPSTREAM_REF}`
- Previous upstream SHA: `{previous_sha}`
- New upstream SHA: `{upstream_sha}`
- GitHub mirror SHA: `{mirror_sha}`
- Mirror cross-check: {mirror_status}
- Fast-forward ancestry check: {fast_forward_status}
- Upstream commit count: {commit_count}
- Local patches replayed successfully against the new upstream SHA: {", ".join(f"`{patch['path']}`" for patch in LOCAL_PATCHES) or "none"}

### Commits Touching Monitored Crypto Paths
{sensitive_text}

### Commits Missing Expected BoringSSL Review Metadata
{missing_text}

### Upstream Workflow Changes Not Imported
{skipped_workflow_text}

## Manual Review Checklist
- [ ] Review commits touching `crypto/`, `ssl/`, `include/openssl/`, and `third_party/fiat/`.
- [ ] Check BoringSSL security advisories and the upstream README security notes before merge.
- [ ] Confirm skipped upstream workflow changes are not needed for this fork.
{"".join(f"- [ ] {patch['checklist']}\n" for patch in LOCAL_PATCHES)}- [ ] Wait for CI before merging.
"""


def load_provenance():
    if not PROVENANCE_PATH.exists():
        fail(f"{PROVENANCE_PATH} is missing")
    return json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))


def recorded_patches(provenance):
    """The local patch records, from schema 2's `local_patches` or schema 1's `local_patch`."""
    if "local_patches" in provenance:
        return {patch["path"]: patch for patch in provenance["local_patches"]}
    single = provenance.get("local_patch")
    return {single["path"]: single} if single else {}


def write_provenance(provenance, previous_sha, upstream_sha, mirror_sha):
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    recorded = recorded_patches(provenance)
    patch_records = []
    for patch in LOCAL_PATCHES:
        previous = recorded.get(str(patch["path"]), {})
        patch_records.append(
            {
                "name": patch["name"],
                "description": previous.get("description", patch["description"]),
                "commit": previous.get("commit"),
                "path": str(patch["path"]),
                "sha256": sha256_file(patch["path"]),
            }
        )
    history = provenance.get("sync_history", [])
    history.append(
        {
            "synced_at": now,
            "previous_upstream_sha": previous_sha,
            "new_upstream_sha": upstream_sha,
            "github_mirror_sha": mirror_sha,
            "local_patch_sha256": {record["name"]: record["sha256"] for record in patch_records},
        }
    )

    updated = {
        "schema_version": 2,
        "source": {
            "url": UPSTREAM_URL,
            "ref": UPSTREAM_REF,
            "mirror_url": MIRROR_URL,
        },
        "previous_upstream_sha": previous_sha,
        "current_upstream_sha": upstream_sha,
        "last_synced_at": now,
        "local_patches": patch_records,
        "last_verification": {
            "github_mirror_sha": mirror_sha,
            "patch_replayed": bool(LOCAL_PATCHES),
            **{patch["verified_as"]: True for patch in LOCAL_PATCHES},
        },
        "sync_history": history,
    }
    PROVENANCE_PATH.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")


def main():
    target_branch = os.environ.get("TARGET_BRANCH", "main")
    sync_branch = os.environ.get("SYNC_BRANCH", "automation/boringssl-upstream-sync")
    allow_mirror_mismatch = parse_bool(os.environ.get("ALLOW_MIRROR_MISMATCH", "false"))

    require_clean_tree()
    provenance = load_provenance()
    previous_sha = provenance["current_upstream_sha"]

    git(["fetch", "--no-tags", "origin", f"+refs/heads/{target_branch}:refs/remotes/origin/{target_branch}"])
    git(["checkout", "-B", sync_branch, f"origin/{target_branch}"])

    upstream_sha = resolve_remote_ref(UPSTREAM_URL, UPSTREAM_REF)
    mirror_sha = resolve_remote_ref(MIRROR_URL, UPSTREAM_REF)
    git(["fetch", "--no-tags", UPSTREAM_URL, f"+{UPSTREAM_REF}:refs/remotes/boringssl-upstream/main"])
    git(["fetch", "--no-tags", MIRROR_URL, f"+{UPSTREAM_REF}:refs/remotes/boringssl-github/main"])

    mirror_status = mirror_cross_check_status(upstream_sha, mirror_sha, allow_mirror_mismatch)

    ff = git(["merge-base", "--is-ancestor", previous_sha, upstream_sha], check=False)
    if ff.returncode != 0:
        fail(
            "new upstream SHA is not a fast-forward from the recorded base: "
            f"{previous_sha} -> {upstream_sha}"
        )
    fast_forward_status = "passed"

    if previous_sha == upstream_sha:
        print("BoringSSL upstream is already current.")
        set_output("has_changes", "false")
        append_summary("BoringSSL upstream is already current.")
        return

    commit_count = git_output(["rev-list", "--count", f"{previous_sha}..{upstream_sha}"])
    sensitive = sensitive_commits(previous_sha, upstream_sha)
    missing_metadata = commits_missing_review_metadata(previous_sha, upstream_sha)

    merge_proc = git(["merge", "--no-ff", "--no-commit", upstream_sha], check=False)
    if merge_proc.returncode != 0:
        print_proc_output(merge_proc)
        resolve_known_conflicts(upstream_sha, f"origin/{target_branch}")
    skipped_workflow_paths = restore_protected_workflow_changes(f"origin/{target_branch}")
    refresh_patch_files(upstream_sha)
    verify_patch_against_upstream(upstream_sha)
    verify_invariants()
    write_provenance(provenance, previous_sha, upstream_sha, mirror_sha)

    git(["add", str(PROVENANCE_PATH)])
    git(["commit", "-m", f"chore: sync BoringSSL upstream to {short_sha(upstream_sha)}"])

    pr_body = build_pr_body(
        previous_sha=previous_sha,
        upstream_sha=upstream_sha,
        mirror_sha=mirror_sha,
        mirror_status=mirror_status,
        fast_forward_status=fast_forward_status,
        commit_count=commit_count,
        sensitive=sensitive,
        missing_metadata=missing_metadata,
        skipped_workflow_paths=skipped_workflow_paths,
    )
    PR_BODY_PATH.write_text(pr_body, encoding="utf-8")

    set_output("has_changes", "true")
    set_output("upstream_sha", upstream_sha)
    set_output("sync_branch", sync_branch)
    set_output("pr_body_path", str(PR_BODY_PATH))
    append_summary(pr_body)


if __name__ == "__main__":
    main()

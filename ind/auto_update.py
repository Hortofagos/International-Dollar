import os
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path


AUTO_UPDATE_ENV = "IND_AUTO_UPDATE"
UPDATE_REMOTE_ENV = "IND_UPDATE_REMOTE"
UPDATE_REF_ENV = "IND_UPDATE_REF"
UPDATE_VERBOSE_ENV = "IND_UPDATE_VERBOSE"
SKIP_DEPS_ENV = "IND_UPDATE_SKIP_DEPS"
ALLOW_UNSIGNED_ENV = "IND_UPDATE_ALLOW_UNSIGNED"
INSTALL_DEPS_ENV = "IND_UPDATE_INSTALL_DEPS"


@dataclass
class UpdateInfo:
    available: bool
    source: str = ""
    upstream_ref: str = ""
    local_rev: str = ""
    remote_rev: str = ""
    ahead: int = 0
    behind: int = 0
    dirty: bool = False
    error: str = ""


@dataclass
class InstallResult:
    success: bool
    old_rev: str = ""
    new_rev: str = ""
    changed_files: tuple = ()
    dependencies_updated: bool = False
    dependencies_skipped: bool = False
    error: str = ""


def _run_git(repo_path, args, timeout=45):
    return subprocess.run(
        ["git", *args],
        cwd=str(repo_path),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _clean_output(process):
    return (process.stdout or "").strip()


def _process_error(process):
    return ((process.stderr or process.stdout) or "").strip()


def _env_true(name):
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _git_available(repo_path):
    try:
        process = _run_git(repo_path, ["rev-parse", "--is-inside-work-tree"], timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return process.returncode == 0 and _clean_output(process).lower() == "true"


def _configured_remote():
    return os.environ.get(UPDATE_REMOTE_ENV, "origin").strip() or "origin"


def _remote_url(repo_path, remote):
    process = _run_git(repo_path, ["remote", "get-url", remote], timeout=10)
    if process.returncode != 0:
        return remote
    return _clean_output(process)


def _current_head(repo_path):
    process = _run_git(repo_path, ["rev-parse", "HEAD"], timeout=10)
    if process.returncode != 0:
        raise RuntimeError(_process_error(process) or "Unable to read local git revision.")
    return _clean_output(process)


def _worktree_dirty(repo_path):
    process = _run_git(repo_path, ["status", "--porcelain"], timeout=15)
    if process.returncode != 0:
        return True
    return bool(_clean_output(process))


def _configured_ref(repo_path, remote):
    requested = os.environ.get(UPDATE_REF_ENV, "").strip()
    if requested:
        return requested

    process = _run_git(
        repo_path,
        ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        timeout=10,
    )
    if process.returncode == 0:
        return _clean_output(process)

    process = _run_git(repo_path, ["symbolic-ref", f"refs/remotes/{remote}/HEAD"], timeout=10)
    if process.returncode == 0:
        ref = _clean_output(process)
        prefix = f"refs/remotes/{remote}/"
        if ref.startswith(prefix):
            return f"{remote}/{ref[len(prefix):]}"

    for branch in ("main", "master"):
        candidate = f"{remote}/{branch}"
        process = _run_git(repo_path, ["rev-parse", "--verify", candidate], timeout=10)
        if process.returncode == 0:
            return candidate

    raise RuntimeError(f"No upstream branch found for remote '{remote}'.")


def _ahead_behind(repo_path, local_ref, upstream_ref):
    process = _run_git(
        repo_path,
        ["rev-list", "--left-right", "--count", f"{local_ref}...{upstream_ref}"],
        timeout=15,
    )
    if process.returncode != 0:
        raise RuntimeError(_process_error(process) or "Unable to compare git revisions.")
    ahead_text, behind_text = _clean_output(process).split()
    return int(ahead_text), int(behind_text)


def _verify_update_signatures(repo_path, old_rev, upstream_ref):
    process = _run_git(repo_path, ["rev-list", "--reverse", f"{old_rev}..{upstream_ref}"], timeout=20)
    if process.returncode != 0:
        return False, _process_error(process) or "Unable to list update commits for signature verification."
    commits = _clean_output(process).splitlines()
    if not commits:
        return True, ""
    for commit in commits:
        verify = _run_git(repo_path, ["verify-commit", commit], timeout=20)
        if verify.returncode != 0:
            detail = _process_error(verify) or "git verify-commit failed"
            return (
                False,
                "Update commits must have valid trusted signatures. "
                f"Commit {commit[:12]} was rejected: {detail}",
            )
    return True, ""


def _should_install_dependencies():
    return _env_true(INSTALL_DEPS_ENV) and not _env_true(SKIP_DEPS_ENV)


def check_for_updates(repo_path):
    """Fetch the configured remote and compare the local checkout with its upstream."""

    repo_path = Path(repo_path)
    if os.environ.get(AUTO_UPDATE_ENV, "1").strip().lower() in {"0", "false", "no", "off"}:
        return UpdateInfo(available=False)

    if not _git_available(repo_path):
        return UpdateInfo(available=False, error="This copy is not running from a git checkout.")

    remote = _configured_remote()
    source = _remote_url(repo_path, remote)
    try:
        fetch = _run_git(repo_path, ["fetch", "--quiet", remote], timeout=60)
        if fetch.returncode != 0:
            return UpdateInfo(available=False, source=source, error=_process_error(fetch))

        upstream_ref = _configured_ref(repo_path, remote)
        local_rev = _current_head(repo_path)
        remote_process = _run_git(repo_path, ["rev-parse", upstream_ref], timeout=10)
        if remote_process.returncode != 0:
            return UpdateInfo(
                available=False,
                source=source,
                upstream_ref=upstream_ref,
                error=_process_error(remote_process),
            )
        remote_rev = _clean_output(remote_process)
        ahead, behind = _ahead_behind(repo_path, "HEAD", upstream_ref)
        return UpdateInfo(
            available=behind > 0,
            source=source,
            upstream_ref=upstream_ref,
            local_rev=local_rev,
            remote_rev=remote_rev,
            ahead=ahead,
            behind=behind,
            dirty=_worktree_dirty(repo_path),
        )
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        return UpdateInfo(available=False, source=source, error=str(exc))


def _pull_args(upstream_ref):
    if "/" not in upstream_ref:
        return ["pull", "--ff-only"]
    remote, branch = upstream_ref.split("/", 1)
    if not remote or not branch:
        return ["pull", "--ff-only"]
    return ["pull", "--ff-only", remote, branch]


def install_update(repo_path, update_info):
    """Install an already detected update with a fast-forward git pull."""

    repo_path = Path(repo_path)
    if update_info.dirty or _worktree_dirty(repo_path):
        return InstallResult(
            success=False,
            error="Local files have changes. Commit, stash, or remove them before installing updates.",
        )
    if update_info.ahead:
        return InstallResult(
            success=False,
            error="The local branch has commits that are not on the update branch. Update manually.",
        )

    try:
        old_rev = _current_head(repo_path)
        if not _env_true(ALLOW_UNSIGNED_ENV):
            signatures_ok, signature_error = _verify_update_signatures(repo_path, old_rev, update_info.upstream_ref)
            if not signatures_ok:
                return InstallResult(success=False, old_rev=old_rev, error=signature_error)
        pull = _run_git(repo_path, _pull_args(update_info.upstream_ref), timeout=120)
        if pull.returncode != 0:
            return InstallResult(success=False, old_rev=old_rev, error=_process_error(pull))

        new_rev = _current_head(repo_path)
        changed_process = _run_git(repo_path, ["diff", "--name-only", old_rev, new_rev], timeout=20)
        changed_files = tuple(_clean_output(changed_process).splitlines()) if changed_process.returncode == 0 else ()

        dependencies_updated = False
        dependencies_skipped = False
        if "requirements.txt" in changed_files and _should_install_dependencies():
            deps = subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
                cwd=str(repo_path),
                text=True,
                capture_output=True,
                timeout=180,
                check=False,
            )
            if deps.returncode != 0:
                return InstallResult(
                    success=False,
                    old_rev=old_rev,
                    new_rev=new_rev,
                    changed_files=changed_files,
                    error=_process_error(deps),
                )
            dependencies_updated = True
        elif "requirements.txt" in changed_files:
            dependencies_skipped = True

        return InstallResult(
            success=True,
            old_rev=old_rev,
            new_rev=new_rev,
            changed_files=changed_files,
            dependencies_updated=dependencies_updated,
            dependencies_skipped=dependencies_skipped,
        )
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        return InstallResult(success=False, error=str(exc))


def start_startup_update_check(root, repo_path, restart_callback=None):
    """Check for updates in the background and ask the user before installing."""

    def worker():
        info = check_for_updates(repo_path)
        try:
            root.after(0, lambda: _handle_update_result(root, repo_path, info, restart_callback))
        except RuntimeError:
            pass

    threading.Thread(target=worker, name="INDUpdateCheck", daemon=True).start()


def _messagebox():
    from tkinter import messagebox

    return messagebox


def _short_rev(rev):
    return rev[:12] if rev else "unknown"


def _handle_update_result(root, repo_path, info, restart_callback):
    box = _messagebox()
    if not info.available:
        if info.error and os.environ.get(UPDATE_VERBOSE_ENV, "0").lower() in {"1", "true", "yes", "on"}:
            box.showwarning("Update check failed", info.error)
        return

    title = "International Dollar update available"
    details = (
        f"Source: {info.source}\n"
        f"Branch: {info.upstream_ref}\n"
        f"Current: {_short_rev(info.local_rev)}\n"
        f"Latest: {_short_rev(info.remote_rev)}"
    )
    if info.dirty:
        box.showwarning(
            title,
            details
            + "\n\nLocal files have changes, so the updater will not install automatically. "
            "Commit, stash, or remove local changes before updating.",
        )
        return
    if info.ahead:
        box.showwarning(
            title,
            details
            + "\n\nThis checkout has local commits that are not on the update branch. "
            "Please update manually.",
        )
        return

    if not box.askyesno(title, details + "\n\nInstall this update now?"):
        return

    def install_worker():
        result = install_update(repo_path, info)
        try:
            root.after(0, lambda: _handle_install_result(result, restart_callback))
        except RuntimeError:
            pass

    threading.Thread(target=install_worker, name="INDUpdateInstall", daemon=True).start()


def _handle_install_result(result, restart_callback):
    box = _messagebox()
    if not result.success:
        box.showerror("Update failed", result.error or "The update could not be installed.")
        return

    summary = f"Updated from {_short_rev(result.old_rev)} to {_short_rev(result.new_rev)}."
    if result.dependencies_updated:
        summary += "\nPython dependencies were also refreshed."
    if result.dependencies_skipped:
        summary += f"\nrequirements.txt changed; dependencies were not installed automatically. Set {INSTALL_DEPS_ENV}=1 to opt in."
    if restart_callback and box.askyesno("Update installed", summary + "\n\nRestart now to use the new version?"):
        restart_callback()
    else:
        box.showinfo("Update installed", summary + "\nRestart the app when you are ready.")

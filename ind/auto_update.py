import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

from . import settings as ind_settings
from . import update_manifest

AUTO_UPDATE_ENV = "IND_AUTO_UPDATE"
UPDATE_SOURCE_ENV = "IND_UPDATE_SOURCE"
UPDATE_REMOTE_ENV = "IND_UPDATE_REMOTE"
UPDATE_REF_ENV = "IND_UPDATE_REF"
UPDATE_VERBOSE_ENV = "IND_UPDATE_VERBOSE"
SKIP_DEPS_ENV = "IND_UPDATE_SKIP_DEPS"
ALLOW_UNSIGNED_ENV = "IND_UPDATE_ALLOW_UNSIGNED"
INSTALL_DEPS_ENV = "IND_UPDATE_INSTALL_DEPS"
UPDATE_MODE_ENV = "IND_UPDATE_MODE"
ALLOW_ROLLBACK_ENV = "IND_UPDATE_ALLOW_ROLLBACK"
USER_AGENT = "International-Dollar-Updater/1"


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
    update_type: str = "git"
    status: str = ""
    channel: str = ""
    release_id: str = ""
    sequence: int = 0
    manifest: dict | None = None
    artifact: dict | None = None
    requires_restart: bool = True


@dataclass
class InstallResult:
    success: bool
    old_rev: str = ""
    new_rev: str = ""
    changed_files: tuple = ()
    dependencies_updated: bool = False
    dependencies_skipped: bool = False
    error: str = ""
    update_type: str = "git"
    release_id: str = ""
    sequence: int = 0


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


def _configured_remote(repo_path=None):
    legacy_remote = os.environ.get(UPDATE_REMOTE_ENV, "").strip()
    if legacy_remote:
        return legacy_remote
    try:
        settings = ind_settings.load_security_settings(validate_production=False)
        return ind_settings.update_source(settings).strip() or "origin"
    except Exception:
        return "origin"


def _remote_exists(repo_path, remote):
    process = _run_git(repo_path, ["remote", "get-url", remote], timeout=10)
    return process.returncode == 0


def _git_update_source(source):
    source = str(source).strip()
    if "://" in source or source in {"origin", "upstream"}:
        return source
    first_segment = source.split("/", 1)[0]
    if "/" in source and "." in first_segment:
        return "https://" + source
    return source


def _direct_fetch_args(source):
    requested = os.environ.get(UPDATE_REF_ENV, "").strip()
    args = ["fetch", "--quiet", source]
    if requested:
        if "/" in requested and not requested.startswith("refs/"):
            requested = requested.split("/", 1)[1]
        args.append(requested)
    return args


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
    process = _run_git(
        repo_path, ["rev-list", "--reverse", f"{old_rev}..{upstream_ref}"], timeout=20
    )
    if process.returncode != 0:
        return (
            False,
            _process_error(process) or "Unable to list update commits for signature verification.",
        )
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


def _auto_update_enabled():
    try:
        return ind_settings.update_check_on_startup(
            ind_settings.load_security_settings(validate_production=False)
        )
    except Exception:
        return _env_true(AUTO_UPDATE_ENV)


def _configured_settings():
    try:
        return ind_settings.load_security_settings(validate_production=False)
    except Exception:
        return ind_settings.default_settings()


def _state_path(repo_path):
    return Path(repo_path) / update_manifest.UPDATE_STATE_PATH


def _manifest_latest_url(source):
    source = str(source or "").strip()
    if not source:
        source = ind_settings.DEFAULT_UPDATE_SOURCE
    if "://" not in source and source not in {"origin", "upstream"}:
        source = "https://" + source
    if source.endswith(".json"):
        return source
    return source.rstrip("/") + "/latest.json"


def _fetch_json(url, timeout=20):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _dev_git_update_mode(source, repo_path):
    mode = os.environ.get(UPDATE_MODE_ENV, "").strip().lower()
    if mode == "git":
        return True
    if mode in {"manifest", "signed-manifest"}:
        return False
    if (
        os.environ.get(UPDATE_REMOTE_ENV, "").strip()
        and not os.environ.get(UPDATE_SOURCE_ENV, "").strip()
    ):
        return True
    source = str(source or "").strip()
    if source in {"origin", "upstream"}:
        return True
    return _git_available(repo_path) and _remote_exists(repo_path, source)


def _select_artifact(manifest):
    artifacts = list(manifest.get("artifacts") or [])
    preferred = ("source", "python-source", "any")
    for platform in preferred:
        for artifact in artifacts:
            if str(artifact.get("platform", "")).strip().lower() == platform:
                return artifact
    return artifacts[0] if artifacts else None


def _check_manifest_updates(repo_path, settings):
    source = ind_settings.update_source(settings)
    channel = ind_settings.update_channel(settings)
    trusted_keys = ind_settings.trusted_update_signing_keys(settings)
    manifest_url = _manifest_latest_url(source)
    state = update_manifest.read_update_state(_state_path(repo_path))
    try:
        payload = _fetch_json(manifest_url)
        if payload.get("type") == update_manifest.UPDATE_STATUS_TYPE:
            status = update_manifest.normalize_update_status(payload)
            return UpdateInfo(
                available=False,
                source=manifest_url,
                update_type="manifest",
                status=status["status"],
                channel=channel,
            )
        manifest = update_manifest.verify_update_manifest(
            payload,
            trusted_keys,
            expected_channel=channel,
            min_sequence=int(state.get("last_accepted_sequence", 0)),
            allow_rollback=_env_true(ALLOW_ROLLBACK_ENV),
        )
        artifact = _select_artifact(manifest)
        if artifact is None:
            return UpdateInfo(
                available=False,
                source=manifest_url,
                update_type="manifest",
                channel=channel,
                error="Update manifest did not contain a usable artifact.",
            )
        local_sequence = int(state.get("last_accepted_sequence", 0))
        sequence = int(manifest["sequence"])
        dirty = _worktree_dirty(repo_path) if _git_available(repo_path) else False
        return UpdateInfo(
            available=sequence > local_sequence,
            source=manifest_url,
            upstream_ref=str(manifest.get("release_id", "")),
            local_rev=str(local_sequence),
            remote_rev=str(manifest.get("release_id", "")),
            behind=max(0, sequence - local_sequence),
            dirty=dirty,
            update_type="manifest",
            status="available" if sequence > local_sequence else "current",
            channel=str(manifest.get("channel", "")),
            release_id=str(manifest.get("release_id", "")),
            sequence=sequence,
            manifest=manifest,
            artifact=artifact,
            requires_restart=bool(manifest.get("requires_restart", True)),
        )
    except Exception as exc:
        return UpdateInfo(
            available=False,
            source=manifest_url,
            update_type="manifest",
            channel=channel,
            error=str(exc),
        )


# Fetch the configured remote and compare the local checkout with its upstream.
def _check_for_git_updates(repo_path, manual=False):
    repo_path = Path(repo_path)
    if not manual and not _auto_update_enabled():
        return UpdateInfo(available=False)

    if not _git_available(repo_path):
        return UpdateInfo(available=False, error="This copy is not running from a git checkout.")

    remote = _configured_remote(repo_path)
    direct_source = not _remote_exists(repo_path, remote)
    source = _git_update_source(remote) if direct_source else _remote_url(repo_path, remote)
    try:
        if direct_source:
            fetch = _run_git(repo_path, _direct_fetch_args(source), timeout=60)
        else:
            fetch = _run_git(repo_path, ["fetch", "--quiet", remote], timeout=60)
        if fetch.returncode != 0:
            return UpdateInfo(available=False, source=source, error=_process_error(fetch))

        upstream_ref = "FETCH_HEAD" if direct_source else _configured_ref(repo_path, remote)
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


# Check for a signed manifest update, or the dev/test git fallback.
def check_for_updates(repo_path, manual=False):
    repo_path = Path(repo_path)
    if not manual and not _auto_update_enabled():
        return UpdateInfo(available=False)
    settings = _configured_settings()
    source = ind_settings.update_source(settings)
    if _dev_git_update_mode(source, repo_path):
        return _check_for_git_updates(repo_path, manual=manual)
    return _check_manifest_updates(repo_path, settings)


def _pull_args(upstream_ref):
    if "/" not in upstream_ref:
        return ["pull", "--ff-only"]
    remote, branch = upstream_ref.split("/", 1)
    if not remote or not branch:
        return ["pull", "--ff-only"]
    return ["pull", "--ff-only", remote, branch]


# Install an already detected update with a fast-forward git pull.
def _install_git_update(repo_path, update_info):
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
            signatures_ok, signature_error = _verify_update_signatures(
                repo_path, old_rev, update_info.upstream_ref
            )
            if not signatures_ok:
                return InstallResult(success=False, old_rev=old_rev, error=signature_error)
        if update_info.upstream_ref == "FETCH_HEAD":
            pull = _run_git(repo_path, ["merge", "--ff-only", "FETCH_HEAD"], timeout=120)
        else:
            pull = _run_git(repo_path, _pull_args(update_info.upstream_ref), timeout=120)
        if pull.returncode != 0:
            return InstallResult(success=False, old_rev=old_rev, error=_process_error(pull))

        new_rev = _current_head(repo_path)
        changed_process = _run_git(repo_path, ["diff", "--name-only", old_rev, new_rev], timeout=20)
        changed_files = (
            tuple(_clean_output(changed_process).splitlines())
            if changed_process.returncode == 0
            else ()
        )

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


def _download_artifact(artifact, manifest_url, temp_dir):
    url = str(artifact["url"]).strip()
    if not urllib.parse.urlparse(url).scheme:
        url = urllib.parse.urljoin(manifest_url, url)
    target = Path(temp_dir) / Path(urllib.parse.urlparse(url).path).name
    if not target.name:
        target = Path(temp_dir) / "update-artifact"
    digest = hashlib.sha3_256()
    size = 0
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response, target.open("wb") as handle:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
            handle.write(chunk)
    expected_size = int(artifact["size_bytes"])
    expected_hash = str(artifact["sha3_256"]).lower()
    if size != expected_size:
        raise RuntimeError(f"artifact size mismatch: expected {expected_size}, got {size}")
    actual_hash = digest.hexdigest()
    if actual_hash != expected_hash:
        raise RuntimeError("artifact sha3_256 mismatch")
    return target


def _safe_tar_extract(archive, target):
    target = Path(target).resolve()
    for member in archive.getmembers():
        if member.issym() or member.islnk():
            raise RuntimeError("artifact tar archives must not contain links")
        member_path = (target / member.name).resolve()
        if target not in member_path.parents and member_path != target:
            raise RuntimeError("artifact contains a path outside the staging directory")
    archive.extractall(target)


def _safe_zip_extract(archive, target):
    target = Path(target).resolve()
    for member in archive.infolist():
        member_path = (target / member.filename).resolve()
        if target not in member_path.parents and member_path != target:
            raise RuntimeError("artifact contains a path outside the staging directory")
    archive.extractall(target)


def _extract_artifact(artifact_path, temp_dir):
    artifact_path = Path(artifact_path)
    extracted = Path(temp_dir) / "extracted"
    extracted.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(artifact_path):
        with zipfile.ZipFile(artifact_path) as archive:
            _safe_zip_extract(archive, extracted)
    elif tarfile.is_tarfile(artifact_path):
        with tarfile.open(artifact_path) as archive:
            _safe_tar_extract(archive, extracted)
    else:
        raise RuntimeError("update artifact must be a zip or tar archive")
    children = [item for item in extracted.iterdir() if item.name not in {"__MACOSX"}]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return extracted


def _copy_source_tree(source_root, repo_path):
    source_root = Path(source_root)
    repo_path = Path(repo_path)
    changed = []

    def ignore(_dir, names):
        return {name for name in names if name in update_manifest.RUNTIME_EXCLUDE_DIRS}

    for item in source_root.iterdir():
        if item.name in update_manifest.RUNTIME_EXCLUDE_DIRS:
            continue
        destination = repo_path / item.name
        if item.is_dir():
            shutil.copytree(item, destination, dirs_exist_ok=True, ignore=ignore)
            changed.append(item.name + "/")
        elif item.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, destination)
            changed.append(item.name)
    return tuple(changed)


def _install_manifest_update(repo_path, update_info):
    repo_path = Path(repo_path)
    manifest = update_info.manifest
    artifact = update_info.artifact
    if not manifest or not artifact:
        return InstallResult(
            success=False, update_type="manifest", error="No verified update manifest is attached."
        )
    if update_info.dirty or (_git_available(repo_path) and _worktree_dirty(repo_path)):
        return InstallResult(
            success=False,
            update_type="manifest",
            release_id=update_info.release_id,
            sequence=update_info.sequence,
            error="Local files have changes. Commit, stash, or remove them before installing updates.",
        )
    try:
        settings = _configured_settings()
        update_manifest.verify_update_manifest(
            manifest,
            ind_settings.trusted_update_signing_keys(settings),
            expected_channel=ind_settings.update_channel(settings),
            min_sequence=update_manifest.read_update_state(_state_path(repo_path)).get(
                "last_accepted_sequence", 0
            ),
            allow_rollback=_env_true(ALLOW_ROLLBACK_ENV),
        )
        old_rev = (
            _current_head(repo_path)
            if _git_available(repo_path)
            else str(
                update_manifest.read_update_state(_state_path(repo_path)).get(
                    "last_accepted_sequence", 0
                )
            )
        )
        with tempfile.TemporaryDirectory(prefix="ind-update-") as temp_dir:
            artifact_path = _download_artifact(artifact, update_info.source, temp_dir)
            source_root = _extract_artifact(artifact_path, temp_dir)
            changed_files = _copy_source_tree(source_root, repo_path)

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
                    changed_files=changed_files,
                    update_type="manifest",
                    release_id=update_info.release_id,
                    sequence=update_info.sequence,
                    error=_process_error(deps),
                )
            dependencies_updated = True
        elif "requirements.txt" in changed_files:
            dependencies_skipped = True

        update_manifest.record_accepted_update(manifest, _state_path(repo_path))
        new_rev = (
            _current_head(repo_path) if _git_available(repo_path) else str(update_info.sequence)
        )
        return InstallResult(
            success=True,
            old_rev=old_rev,
            new_rev=new_rev,
            changed_files=changed_files,
            dependencies_updated=dependencies_updated,
            dependencies_skipped=dependencies_skipped,
            update_type="manifest",
            release_id=update_info.release_id,
            sequence=update_info.sequence,
        )
    except Exception as exc:
        return InstallResult(
            success=False,
            update_type="manifest",
            release_id=update_info.release_id,
            sequence=update_info.sequence,
            error=str(exc),
        )


def install_update(repo_path, update_info):
    if getattr(update_info, "update_type", "git") == "manifest":
        return _install_manifest_update(repo_path, update_info)
    return _install_git_update(repo_path, update_info)


# Check for updates in the background and ask the user before installing.
def start_startup_update_check(root, repo_path, restart_callback=None):
    def worker():
        info = check_for_updates(repo_path)
        with contextlib.suppress(RuntimeError):
            root.after(0, lambda: _handle_update_result(root, repo_path, info, restart_callback))

    threading.Thread(target=worker, name="INDUpdateCheck", daemon=True).start()


def _messagebox():
    from tkinter import messagebox

    return messagebox


def _short_rev(rev):
    return rev[:12] if rev else "unknown"


def _handle_update_result(root, repo_path, info, restart_callback):
    box = _messagebox()
    if not info.available:
        if info.error and os.environ.get(UPDATE_VERBOSE_ENV, "0").lower() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            box.showwarning("Update check failed", info.error)
        return

    title = "International Dollar update available"
    if info.update_type == "manifest":
        details = (
            f"Source: {info.source}\n"
            f"Channel: {info.channel}\n"
            f"Release: {info.release_id}\n"
            f"Sequence: {info.sequence}"
        )
    else:
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
            details + "\n\nThis checkout has local commits that are not on the update branch. "
            "Please update manually.",
        )
        return

    if not box.askyesno(title, details + "\n\nInstall this update now?"):
        return

    def install_worker():
        result = install_update(repo_path, info)
        with contextlib.suppress(RuntimeError):
            root.after(0, lambda: _handle_install_result(result, restart_callback))

    threading.Thread(target=install_worker, name="INDUpdateInstall", daemon=True).start()


def _handle_install_result(result, restart_callback):
    box = _messagebox()
    if not result.success:
        box.showerror("Update failed", result.error or "The update could not be installed.")
        return

    if result.update_type == "manifest":
        summary = f"Installed release {result.release_id} (sequence {result.sequence})."
    else:
        summary = f"Updated from {_short_rev(result.old_rev)} to {_short_rev(result.new_rev)}."
    if result.dependencies_updated:
        summary += "\nPython dependencies were also refreshed."
    if result.dependencies_skipped:
        summary += f"\nrequirements.txt changed; dependencies were not installed automatically. Set {INSTALL_DEPS_ENV}=1 to opt in."
    if restart_callback and box.askyesno(
        "Update installed", summary + "\n\nRestart now to use the new version?"
    ):
        restart_callback()
    else:
        box.showinfo("Update installed", summary + "\nRestart the app when you are ready.")

#!/usr/bin/env python3
# Publish the public testnet transparency mirror to a git-hosted static branch.

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

DEFAULT_SOURCE = "https://international-dollar.com/transparency"
DEFAULT_BRANCH = "testnet-transparency-mirror"
DEFAULT_REMOTE = os.environ.get("IND_STATIC_MIRROR_REMOTE", "")
USER_AGENT = "International-Dollar-static-mirror-publisher/1"


# Raised when a static mirror cannot be published.
class MirrorPublishError(RuntimeError):
    pass


def fetch_bytes(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def fetch_json(url):
    return json.loads(fetch_bytes(url).decode("utf-8"))


def write_bytes(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _root_tuple(root):
    if not isinstance(root, dict):
        return None
    try:
        return (
            int(root["tree_size"]),
            str(root["root_hash"]).strip().lower(),
            int(root["timestamp"]),
        )
    except Exception:
        return None


def _existing_latest(transparency_dir):
    latest_path = Path(transparency_dir) / "latest.json"
    if not latest_path.exists() or not latest_path.is_file():
        return None
    try:
        return json.loads(latest_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def reject_latest_rollback(existing, latest):
    old = _root_tuple(existing)
    new = _root_tuple(latest)
    if old is None or new is None:
        return
    old_size, old_hash, old_timestamp = old
    new_size, new_hash, new_timestamp = new
    if new_size < old_size:
        raise MirrorPublishError(
            f"refusing to roll static mirror back from tree_size {old_size} to {new_size}"
        )
    if new_size == old_size and new_hash != old_hash:
        raise MirrorPublishError(
            "refusing to replace static mirror root with a different hash at the same tree_size"
        )
    if new_size == old_size and new_timestamp < old_timestamp:
        raise MirrorPublishError("refusing to replace static mirror latest.json with an older root")


def copy_root_files(source_url, transparency_dir):
    latest = None
    fetched = {}
    for name in ("latest.json", "manifest.json", "roots.jsonl"):
        data = fetch_bytes(f"{source_url}/{name}")
        fetched[name] = data
        if name == "latest.json":
            latest = json.loads(data.decode("utf-8"))
    reject_latest_rollback(_existing_latest(transparency_dir), latest)
    for name, data in fetched.items():
        write_bytes(transparency_dir / name, data)
    return latest


def copy_archive(source_url, transparency_dir):
    archive_manifest = fetch_json(f"{source_url}/archive/manifest.json")
    archive_dir = transparency_dir / "archive"
    if archive_dir.exists():
        shutil.rmtree(archive_dir)
    write_bytes(
        archive_dir / "manifest.json",
        (json.dumps(archive_manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        ),
    )
    for segment in archive_manifest.get("segments", []):
        relative = str(segment.get("path", "")).strip()
        if not relative or relative.startswith("/") or ".." in Path(relative).parts:
            raise MirrorPublishError(f"unsafe archive segment path: {relative}")
        write_bytes(archive_dir / relative, fetch_bytes(f"{source_url}/archive/{relative}"))
    return archive_manifest


def run_git(cwd, args):
    process = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        text=True,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        raise MirrorPublishError((process.stderr or process.stdout or "git command failed").strip())
    return process.stdout.strip()


def copy_public_transparency(
    source_url,
    target_dir,
    include_archive=True,
    allow_missing_archive=False,
):
    source_url = source_url.rstrip("/")
    target_dir = Path(target_dir)
    transparency_dir = target_dir / "transparency"
    transparency_dir.mkdir(parents=True, exist_ok=True)
    latest = copy_root_files(source_url, transparency_dir)

    archive_ok = not include_archive
    archive_error = ""
    if include_archive:
        try:
            copy_archive(source_url, transparency_dir)
            archive_ok = True
        except Exception as exc:  # noqa: BLE001 - root freshness must not depend on archive sync.
            archive_error = str(exc)
            if not allow_missing_archive:
                raise
    return {
        "transparency_dir": str(transparency_dir),
        "latest": latest,
        "archive_requested": bool(include_archive),
        "archive_ok": bool(archive_ok),
        "archive_error": archive_error,
    }


def publish_git_branch(workdir, remote, branch, message):
    if not remote:
        raise MirrorPublishError(
            "--git-remote or IND_STATIC_MIRROR_REMOTE is required for publishing"
        )
    run_git(workdir, ["init"])
    run_git(workdir, ["checkout", "-B", branch])
    run_git(workdir, ["config", "user.name", "IND Transparency Mirror Publisher"])
    run_git(workdir, ["config", "user.email", "ind-transparency@example.invalid"])
    run_git(workdir, ["add", "transparency"])
    status = run_git(workdir, ["status", "--porcelain"])
    if not status:
        return False
    run_git(workdir, ["commit", "-m", message])
    run_git(workdir, ["remote", "add", "origin", remote])
    run_git(workdir, ["push", "-f", "origin", f"HEAD:refs/heads/{branch}"])
    return True


def parse_args():
    parser = argparse.ArgumentParser(
        description="Publish an off-VPS static transparency mirror branch"
    )
    parser.add_argument("--source-url", default=DEFAULT_SOURCE)
    parser.add_argument("--git-remote", default=DEFAULT_REMOTE)
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    parser.add_argument("--no-archive", action="store_true")
    parser.add_argument(
        "--allow-missing-archive",
        action="store_true",
        help=(
            "publish root mirror files even when archive/manifest.json or archive "
            "segments are unavailable; existing archive files are preserved"
        ),
    )
    parser.add_argument("--keep-workdir", default="")
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="stage the mirror files without committing or pushing",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    managed_temp = not args.keep_workdir
    temp_dir = args.keep_workdir or tempfile.mkdtemp(prefix="ind-static-mirror-")
    try:
        workdir = Path(temp_dir)
        if managed_temp and workdir.exists():
            shutil.rmtree(workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        transparency_dir = workdir / "transparency"
        if transparency_dir.exists() and not args.allow_missing_archive:
            shutil.rmtree(transparency_dir)
        result = copy_public_transparency(
            args.source_url,
            workdir,
            include_archive=not args.no_archive,
            allow_missing_archive=args.allow_missing_archive,
        )
        latest = result["latest"]
        if args.local_only:
            print(
                json.dumps(
                    {
                        "ok": True,
                        "archive_error": result["archive_error"],
                        "archive_ok": result["archive_ok"],
                        "archive_requested": result["archive_requested"],
                        "local_only": True,
                        "workdir": str(workdir),
                        "tree_size": int(latest["tree_size"]),
                        "source_url": args.source_url.rstrip("/"),
                    },
                    sort_keys=True,
                    indent=2,
                )
            )
            return
        message = f"Publish testnet transparency mirror tree {int(latest['tree_size'])}"
        changed = publish_git_branch(workdir, args.git_remote, args.branch, message)
        raw_base = ""
        if "github.com/" in args.git_remote:
            repo = args.git_remote.rstrip("/").removesuffix(".git").split("github.com/", 1)[1]
            raw_base = f"https://raw.githubusercontent.com/{repo}/{args.branch}/transparency"
        print(
            json.dumps(
                {
                    "ok": True,
                    "archive_error": result["archive_error"],
                    "archive_ok": result["archive_ok"],
                    "archive_requested": result["archive_requested"],
                    "changed": changed,
                    "branch": args.branch,
                    "raw_base": raw_base,
                    "tree_size": int(latest["tree_size"]),
                    "source_url": args.source_url.rstrip("/"),
                },
                sort_keys=True,
                indent=2,
            )
        )
    finally:
        if managed_temp:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()

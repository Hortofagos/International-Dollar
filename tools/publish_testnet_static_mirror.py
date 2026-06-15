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


def copy_public_transparency(source_url, target_dir, include_archive=True):
    source_url = source_url.rstrip("/")
    target_dir = Path(target_dir)
    transparency_dir = target_dir / "transparency"
    for name in ("latest.json", "manifest.json", "roots.jsonl"):
        write_bytes(transparency_dir / name, fetch_bytes(f"{source_url}/{name}"))

    if include_archive:
        archive_manifest = fetch_json(f"{source_url}/archive/manifest.json")
        archive_dir = transparency_dir / "archive"
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
    return transparency_dir


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
        if transparency_dir.exists():
            shutil.rmtree(transparency_dir)
        copy_public_transparency(args.source_url, workdir, include_archive=not args.no_archive)
        latest = fetch_json(f"{args.source_url.rstrip('/')}/latest.json")
        if args.local_only:
            print(
                json.dumps(
                    {
                        "ok": True,
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

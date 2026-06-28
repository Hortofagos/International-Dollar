import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from ind import transparency_client as log_client  # noqa: E402
from ind.io_utils import atomic_write_text  # noqa: E402

DEFAULT_OPERATOR_URL = "http://127.0.0.1:8890"
DEFAULT_GIT_MIRROR_DIR = "operator_tools/git-root-mirror"
DEFAULT_WEBSITE_MIRROR_DIR = "operator_tools/website-root-mirror"
DEFAULT_STATE_FILE = "operator_tools/root_streamer_state.json"
DEFAULT_POLL_SECONDS = 60


# Raised when signed roots cannot be streamed to a mirror.
class RootStreamError(Exception):
    pass


def _canonical_line(data):
    return log_client.canonical_json(data) + "\n"


def root_id(root):
    return log_client.signed_root_id(root)


def root_filename(root):
    return f"root_{int(root['timestamp'])}_{int(root['tree_size'])}_{root['root_hash'][:16]}.json"


def root_state_key(root):
    return (
        int(root["tree_size"]),
        str(root["root_hash"]),
        str(root.get("spend_map_root") or ""),
    )


def load_state(path):
    path = Path(path)
    if not path.exists():
        return {"published_root_ids": []}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(path, state):
    atomic_write_text(path, log_client.canonical_json(state) + "\n")


# Fetch signed roots from a running log operator.
class OperatorRootSource:
    def __init__(self, operator_url=DEFAULT_OPERATOR_URL, timeout=10):
        self.operator_url = operator_url.rstrip("/")
        self.timeout = int(timeout)

    def roots(self, limit=1000):
        query = urllib.parse.urlencode({"limit": int(limit)})
        url = f"{self.operator_url}/v3/roots?{query}"
        with urllib.request.urlopen(url, timeout=self.timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return payload.get("roots", [])


# Fetch signed roots from a local root staging directory.
class DirectoryRootSource:
    def __init__(self, source_dir):
        self.source_dir = Path(source_dir)

    def roots(self, limit=1000):
        roots = log_client.DirectoryRootMirror(self.source_dir).roots()
        return sorted(roots, key=lambda item: (int(item["timestamp"]), int(item["tree_size"])))[
            -int(limit) :
        ]


# Write signed roots in the static mirror format clients can read.
class StaticRootMirrorWriter:
    def __init__(self, mirror_dir):
        self.mirror_dir = Path(mirror_dir)

    def _historical_roots(self):
        roots_jsonl = self.mirror_dir / "roots.jsonl"
        if not roots_jsonl.exists():
            return []
        roots = []
        for line in roots_jsonl.read_text(encoding="utf-8").splitlines():
            if line.strip():
                roots.append(json.loads(line))
        return roots

    def _write_historical_root(self, root):
        roots_dir = self.mirror_dir / "roots"
        roots_dir.mkdir(parents=True, exist_ok=True)
        root_path = roots_dir / root_filename(root)
        line = _canonical_line(root)
        if not root_path.exists():
            atomic_write_text(root_path, line)
        with (self.mirror_dir / "roots.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(line)

    def _should_append_historical_root(self, root, historical_roots, force_historical=False):
        current_id = root_id(root)
        if any(root_id(item) == current_id for item in historical_roots):
            return False
        if force_historical:
            return True
        current_state = root_state_key(root)
        return not any(root_state_key(item) == current_state for item in historical_roots)

    def publish_root(self, root, force_historical=False):
        self.mirror_dir.mkdir(parents=True, exist_ok=True)
        line = _canonical_line(root)
        changed = False

        latest_path = self.mirror_dir / "latest.json"
        current_latest = None
        if latest_path.exists():
            try:
                current_latest = json.loads(latest_path.read_text(encoding="utf-8"))
                current_latest_key = (
                    int(current_latest["timestamp"]),
                    int(current_latest["tree_size"]),
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                current_latest = None
                current_latest_key = None
        else:
            current_latest_key = None
        if (
            not current_latest
            or (int(root["timestamp"]), int(root["tree_size"])) >= current_latest_key
        ):
            atomic_write_text(latest_path, line)
            changed = True

        historical_roots = self._historical_roots()
        if self._should_append_historical_root(
            root, historical_roots, force_historical=force_historical
        ):
            self._write_historical_root(root)
            changed = True

        manifest = self._manifest()
        atomic_write_text(
            self.mirror_dir / "manifest.json", log_client.canonical_json(manifest) + "\n"
        )
        return changed

    def _manifest(self):
        roots = self._historical_roots()
        roots = sorted(roots, key=lambda item: (int(item["timestamp"]), int(item["tree_size"])))
        latest = None
        latest_path = self.mirror_dir / "latest.json"
        if latest_path.exists():
            try:
                latest = json.loads(latest_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                latest = None
        if latest is None:
            latest = roots[-1] if roots else None
        return {
            "type": "ind.transparency_root_mirror_manifest.v3",
            "version": 1,
            "root_count": len(roots),
            "latest_root_id": root_id(latest) if latest else None,
            "latest_timestamp": int(latest["timestamp"]) if latest else None,
            "latest_tree_size": int(latest["tree_size"]) if latest else None,
        }


def compact_static_mirror(mirror_dir, keep_root_ids=None):
    mirror_dir = Path(mirror_dir)
    keep_root_ids = {str(item) for item in (keep_root_ids or [])}
    roots = []
    seen_ids = set()
    roots_jsonl = mirror_dir / "roots.jsonl"
    if roots_jsonl.exists():
        for line in roots_jsonl.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            root = json.loads(line)
            current_id = root_id(root)
            if current_id in seen_ids:
                continue
            seen_ids.add(current_id)
            roots.append(root)
    else:
        roots = log_client.DirectoryRootMirror(mirror_dir).roots()

    by_state = {}
    for root in roots:
        current_id = root_id(root)
        state_key = root_state_key(root)
        current = by_state.get(state_key)
        if current is None or (int(root["timestamp"]), int(root["tree_size"])) < (
            int(current["timestamp"]),
            int(current["tree_size"]),
        ):
            by_state[state_key] = root

    compacted = {root_id(root): root for root in by_state.values()}
    for root in roots:
        current_id = root_id(root)
        if current_id in keep_root_ids:
            compacted[current_id] = root

    latest = None
    latest_path = mirror_dir / "latest.json"
    if latest_path.exists():
        try:
            latest = json.loads(latest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            latest = None
    if latest is not None:
        compacted[root_id(latest)] = latest

    keep = sorted(
        compacted.values(),
        key=lambda item: (int(item["timestamp"]), int(item["tree_size"]), root_id(item)),
    )
    roots_dir = mirror_dir / "roots"
    if roots_dir.exists():
        shutil.rmtree(roots_dir)
    roots_dir.mkdir(parents=True, exist_ok=True)
    lines = []
    for root in keep:
        line = _canonical_line(root)
        atomic_write_text(roots_dir / root_filename(root), line)
        lines.append(line)
    atomic_write_text(mirror_dir / "roots.jsonl", "".join(lines))
    if latest is not None:
        atomic_write_text(latest_path, _canonical_line(latest))
    manifest = StaticRootMirrorWriter(mirror_dir)._manifest()
    atomic_write_text(mirror_dir / "manifest.json", log_client.canonical_json(manifest) + "\n")
    return {"before": len(roots), "after": len(keep)}


# Write roots to a git mirror and optionally commit/push changes.
class GitRootMirrorWriter(StaticRootMirrorWriter):
    def __init__(self, mirror_dir, remote_url=None, branch="main", push=False, commit=True):
        super().__init__(mirror_dir)
        self.remote_url = remote_url
        self.branch = branch
        self.push = bool(push)
        self.commit = bool(commit)

    def ensure_repo(self):
        self.mirror_dir.mkdir(parents=True, exist_ok=True)
        git_dir = self.mirror_dir / ".git"
        if not git_dir.exists():
            self._git(["init"])
            if self.branch:
                self._git(["checkout", "-B", self.branch])
        if self.remote_url and not self._remote_exists("origin"):
            self._git(["remote", "add", "origin", self.remote_url])

    def publish_root(self, root):
        self.ensure_repo()
        changed = super().publish_root(root)
        if changed and self.commit:
            self._commit_and_push(root)
        return changed

    def _git(self, args, check=True):
        if not shutil.which("git"):
            raise RootStreamError("git executable is not available")
        result = subprocess.run(
            ["git", *args],
            cwd=self.mirror_dir,
            text=True,
            capture_output=True,
            check=False,
        )
        if check and result.returncode != 0:
            raise RootStreamError(
                result.stderr.strip() or result.stdout.strip() or "git command failed"
            )
        return result

    def _remote_exists(self, name):
        return self._git(["remote", "get-url", name], check=False).returncode == 0

    def _commit_and_push(self, root):
        self._git(["add", "roots", "roots.jsonl", "latest.json", "manifest.json"])
        status = self._git(["status", "--porcelain"], check=False).stdout.strip()
        if not status:
            return
        message = (
            f"Publish IND transparency root {int(root['tree_size'])} at {int(root['timestamp'])}"
        )
        self._git(
            [
                "-c",
                "user.name=IND Transparency Operator",
                "-c",
                "user.email=ind-transparency@example.invalid",
                "commit",
                "-m",
                message,
            ]
        )
        if self.push:
            push_args = ["push"]
            if self.branch:
                push_args.extend(["-u", "origin", self.branch])
            self._git(push_args)


def verify_roots(roots, operator_public_key=None):
    verified = []
    for root in roots:
        log_client.verify_signed_root(root, operator_public_key=operator_public_key)
        verified.append(root)
    log_client.detect_mirror_disagreement(verified, operator_public_key=operator_public_key)
    return verified


def publish_once(source, writers, state_path, operator_public_key=None, limit=1000):
    state = load_state(state_path)
    published = set(state.get("published_root_ids", []))
    try:
        raw_roots = source.roots(limit=limit)
    except TypeError:
        raw_roots = source.roots()
    roots = verify_roots(raw_roots, operator_public_key=operator_public_key)
    roots = sorted(roots, key=lambda item: (int(item["timestamp"]), int(item["tree_size"])))
    changed = 0

    for root in roots:
        current_id = root_id(root)
        if current_id in published:
            continue
        for writer in writers:
            writer.publish_root(root)
        published.add(current_id)
        changed += 1

    state["published_root_ids"] = sorted(published)
    state["updated_at"] = int(time.time())
    save_state(state_path, state)
    return changed


def stream_roots(
    source,
    writers,
    state_path,
    operator_public_key=None,
    poll_seconds=DEFAULT_POLL_SECONDS,
    limit=1000,
):
    while True:
        changed = publish_once(
            source,
            writers,
            state_path,
            operator_public_key=operator_public_key,
            limit=limit,
        )
        print(f"published {changed} new signed root(s)")
        time.sleep(int(poll_seconds))


def build_source(args):
    if args.source_dir:
        return DirectoryRootSource(args.source_dir)
    return OperatorRootSource(args.operator_url, timeout=args.timeout)


def build_writers(args):
    writers = []
    if args.git_mirror_dir:
        writers.append(
            GitRootMirrorWriter(
                args.git_mirror_dir,
                remote_url=args.git_remote_url,
                branch=args.git_branch,
                push=args.git_push,
                commit=not args.no_git_commit,
            )
        )
    if args.website_mirror_dir:
        writers.append(StaticRootMirrorWriter(args.website_mirror_dir))
    if not writers:
        raise RootStreamError("configure at least one mirror writer")
    return writers


def main():
    parser = argparse.ArgumentParser(
        description="Stream IND signed transparency roots to git and website mirrors"
    )
    parser.add_argument(
        "--operator-url", default=os.environ.get("IND_LOG_OPERATOR_URL", DEFAULT_OPERATOR_URL)
    )
    parser.add_argument("--source-dir", default=os.environ.get("IND_ROOT_SOURCE_DIR", ""))
    parser.add_argument(
        "--operator-public-key", default=os.environ.get("IND_LOG_OPERATOR_PUBLIC_KEY", "")
    )
    parser.add_argument(
        "--git-mirror-dir",
        default=os.environ.get("IND_ROOT_GIT_MIRROR_DIR", DEFAULT_GIT_MIRROR_DIR),
    )
    parser.add_argument("--git-remote-url", default=os.environ.get("IND_ROOT_GIT_REMOTE_URL", ""))
    parser.add_argument("--git-branch", default=os.environ.get("IND_ROOT_GIT_BRANCH", "main"))
    parser.add_argument(
        "--git-push",
        action="store_true",
        default=os.environ.get("IND_ROOT_GIT_PUSH", "").lower() in {"1", "true", "yes"},
    )
    parser.add_argument("--no-git-commit", action="store_true")
    parser.add_argument(
        "--website-mirror-dir",
        default=os.environ.get("IND_ROOT_WEBSITE_DIR", DEFAULT_WEBSITE_MIRROR_DIR),
    )
    parser.add_argument(
        "--state-file", default=os.environ.get("IND_ROOT_STREAM_STATE", DEFAULT_STATE_FILE)
    )
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=int(os.environ.get("IND_ROOT_STREAM_POLL_SECONDS", DEFAULT_POLL_SECONDS)),
    )
    parser.add_argument(
        "--limit", type=int, default=int(os.environ.get("IND_ROOT_STREAM_FETCH_LIMIT", "1000"))
    )
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--compact-existing",
        action="store_true",
        help="rewrite the static mirror history to one root per tree state",
    )
    parser.add_argument(
        "--keep-root-id",
        action="append",
        default=[],
        help="signed root id to retain when compacting; repeatable",
    )
    args = parser.parse_args()

    if args.compact_existing:
        result = compact_static_mirror(args.website_mirror_dir, keep_root_ids=args.keep_root_id)
        print(
            "compacted static mirror from "
            f"{result['before']} to {result['after']} historical root(s)"
        )
        return

    source = build_source(args)
    writers = build_writers(args)
    operator_public_key = args.operator_public_key.strip() or None
    if args.once:
        changed = publish_once(
            source,
            writers,
            args.state_file,
            operator_public_key=operator_public_key,
            limit=args.limit,
        )
        print(f"published {changed} new signed root(s)")
        return
    stream_roots(
        source,
        writers,
        args.state_file,
        operator_public_key=operator_public_key,
        poll_seconds=args.poll_seconds,
        limit=args.limit,
    )


if __name__ == "__main__":
    main()

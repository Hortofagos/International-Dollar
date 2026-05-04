import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import auto_update


def run_git(repo_path, *args):
    process = subprocess.run(
        ["git", *args],
        cwd=str(repo_path),
        text=True,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        raise AssertionError(process.stderr or process.stdout)
    return process.stdout.strip()


class temporary_update_env:
    def __enter__(self):
        self.previous = {
            auto_update.AUTO_UPDATE_ENV: os.environ.get(auto_update.AUTO_UPDATE_ENV),
            auto_update.UPDATE_REMOTE_ENV: os.environ.get(auto_update.UPDATE_REMOTE_ENV),
            auto_update.UPDATE_REF_ENV: os.environ.get(auto_update.UPDATE_REF_ENV),
            auto_update.SKIP_DEPS_ENV: os.environ.get(auto_update.SKIP_DEPS_ENV),
            auto_update.ALLOW_UNSIGNED_ENV: os.environ.get(auto_update.ALLOW_UNSIGNED_ENV),
        }
        os.environ[auto_update.AUTO_UPDATE_ENV] = "1"
        os.environ.pop(auto_update.UPDATE_REMOTE_ENV, None)
        os.environ.pop(auto_update.UPDATE_REF_ENV, None)
        os.environ[auto_update.SKIP_DEPS_ENV] = "1"
        os.environ[auto_update.ALLOW_UNSIGNED_ENV] = "1"

    def __exit__(self, exc_type, exc_value, traceback):
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class AutoUpdateTests(unittest.TestCase):
    def _make_repositories(self, temp_dir):
        remote = Path(temp_dir) / "remote.git"
        seed = Path(temp_dir) / "seed"
        clone = Path(temp_dir) / "clone"

        run_git(temp_dir, "init", "--bare", str(remote))
        seed.mkdir()
        run_git(seed, "init")
        run_git(seed, "config", "user.email", "test@example.com")
        run_git(seed, "config", "user.name", "Updater Test")
        (seed / "app.txt").write_text("v1\n", encoding="utf-8")
        run_git(seed, "add", "app.txt")
        run_git(seed, "commit", "-m", "initial")
        run_git(seed, "branch", "-M", "main")
        run_git(seed, "remote", "add", "origin", str(remote))
        run_git(seed, "push", "-u", "origin", "main")

        run_git(temp_dir, "clone", str(remote), str(clone))
        run_git(clone, "checkout", "main")
        run_git(clone, "branch", "--set-upstream-to=origin/main", "main")
        return seed, clone

    def _push_update(self, seed):
        (seed / "app.txt").write_text("v2\n", encoding="utf-8")
        run_git(seed, "add", "app.txt")
        run_git(seed, "commit", "-m", "update")
        run_git(seed, "push", "origin", "main")

    def test_check_and_install_fast_forward_update(self):
        with tempfile.TemporaryDirectory() as temp_dir, temporary_update_env():
            seed, clone = self._make_repositories(Path(temp_dir))
            self._push_update(seed)

            info = auto_update.check_for_updates(clone)
            self.assertTrue(info.available)
            self.assertEqual(info.behind, 1)
            self.assertFalse(info.dirty)

            result = auto_update.install_update(clone, info)
            self.assertTrue(result.success, result.error)
            self.assertIn("app.txt", result.changed_files)
            self.assertEqual((clone / "app.txt").read_text(encoding="utf-8"), "v2\n")

            refreshed = auto_update.check_for_updates(clone)
            self.assertFalse(refreshed.available)

    def test_install_refuses_dirty_worktree(self):
        with tempfile.TemporaryDirectory() as temp_dir, temporary_update_env():
            seed, clone = self._make_repositories(Path(temp_dir))
            self._push_update(seed)
            info = auto_update.check_for_updates(clone)

            (clone / "local.txt").write_text("local work\n", encoding="utf-8")
            result = auto_update.install_update(clone, info)

            self.assertFalse(result.success)
            self.assertIn("Local files have changes", result.error)

    def test_install_rejects_unsigned_update_without_explicit_escape_hatch(self):
        with tempfile.TemporaryDirectory() as temp_dir, temporary_update_env():
            os.environ.pop(auto_update.ALLOW_UNSIGNED_ENV, None)
            seed, clone = self._make_repositories(Path(temp_dir))
            self._push_update(seed)
            info = auto_update.check_for_updates(clone)

            result = auto_update.install_update(clone, info)

            self.assertFalse(result.success)
            self.assertIn("valid trusted signatures", result.error)


if __name__ == "__main__":
    unittest.main()

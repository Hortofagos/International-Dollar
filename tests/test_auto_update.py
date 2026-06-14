import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import auto_update
from ind import address_generation
from ind import auto_update as auto_update_impl
from ind import update_manifest


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
            auto_update.UPDATE_SOURCE_ENV: os.environ.get(auto_update.UPDATE_SOURCE_ENV),
            auto_update.UPDATE_REMOTE_ENV: os.environ.get(auto_update.UPDATE_REMOTE_ENV),
            auto_update.UPDATE_REF_ENV: os.environ.get(auto_update.UPDATE_REF_ENV),
            auto_update.SKIP_DEPS_ENV: os.environ.get(auto_update.SKIP_DEPS_ENV),
            auto_update.ALLOW_UNSIGNED_ENV: os.environ.get(auto_update.ALLOW_UNSIGNED_ENV),
            auto_update.UPDATE_MODE_ENV: os.environ.get(auto_update.UPDATE_MODE_ENV),
        }
        os.environ[auto_update.AUTO_UPDATE_ENV] = "1"
        os.environ.pop(auto_update.UPDATE_SOURCE_ENV, None)
        os.environ[auto_update.UPDATE_REMOTE_ENV] = "origin"
        os.environ.pop(auto_update.UPDATE_REF_ENV, None)
        os.environ[auto_update.SKIP_DEPS_ENV] = "1"
        os.environ[auto_update.ALLOW_UNSIGNED_ENV] = "1"
        os.environ[auto_update.UPDATE_MODE_ENV] = "git"

    def __exit__(self, exc_type, exc_value, traceback):
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class AutoUpdateTests(unittest.TestCase):
    def test_check_for_updates_is_disabled_by_default_for_automatic_checks(self):
        settings = auto_update_impl.ind_settings.default_settings()
        settings["update_check_on_startup"] = False
        with mock.patch.object(
            auto_update_impl.ind_settings,
            "load_security_settings",
            return_value=settings,
        ), mock.patch.object(auto_update_impl, "_git_available") as git_available:
            info = auto_update_impl.check_for_updates(Path("."))

        self.assertFalse(info.available)
        git_available.assert_not_called()

    def test_manual_check_bypasses_startup_auto_update_toggle(self):
        settings = auto_update_impl.ind_settings.default_settings()
        settings["update_check_on_startup"] = False
        with temporary_update_env(), mock.patch.object(
            auto_update_impl.ind_settings,
            "load_security_settings",
            return_value=settings,
        ), mock.patch.object(auto_update_impl, "_git_available", return_value=False) as git_available:
            os.environ[auto_update.UPDATE_MODE_ENV] = "git"
            info = auto_update_impl.check_for_updates(Path("."), manual=True)

        self.assertFalse(info.available)
        self.assertEqual(info.error, "This copy is not running from a git checkout.")
        git_available.assert_called_once()

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

    def test_domain_update_source_is_normalized_to_https_fetch_source(self):
        self.assertEqual(
            auto_update_impl._git_update_source("international-dollar.com/update"),
            "https://international-dollar.com/update",
        )

    def _signed_manifest(self, artifact, sequence=1, channel="stable"):
        _address, private_key, public_key = address_generation.generate_keypair()
        manifest = {
            "type": update_manifest.UPDATE_MANIFEST_TYPE,
            "version": 1,
            "channel": channel,
            "release_id": f"release-{sequence}",
            "sequence": sequence,
            "published_at": 1_700_000_000 + sequence,
            "min_supported_sequence": 0,
            "requires_restart": True,
            "artifacts": [artifact],
        }
        return update_manifest.sign_update_manifest(manifest, private_key, public_key), public_key

    def _write_source_zip(self, temp_dir, files):
        source_root = Path(temp_dir) / "source"
        for relative, text in files.items():
            path = source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        artifact_path = Path(temp_dir) / "release.zip"
        with zipfile.ZipFile(artifact_path, "w") as archive:
            for path in source_root.rglob("*"):
                if path.is_file():
                    archive.write(path, path.relative_to(source_root).as_posix())
        data = artifact_path.read_bytes()
        return artifact_path, {
            "platform": "source",
            "url": artifact_path.as_uri(),
            "sha3_256": update_manifest.sha3_hex(data),
            "size_bytes": len(data),
        }

    def test_signed_manifest_install_preserves_runtime_dirs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir) / "repo"
            repo.mkdir()
            (repo / "app.py").write_text("old\n", encoding="utf-8")
            (repo / "files").mkdir()
            (repo / "files" / "secret.txt").write_text("keep\n", encoding="utf-8")
            artifact_path, artifact = self._write_source_zip(
                temp_dir,
                {
                    "app.py": "new\n",
                    "files/secret.txt": "replace-me-not\n",
                    "wallet_folder/private.txt": "replace-me-not\n",
                },
            )
            manifest, public_key = self._signed_manifest(artifact, sequence=7)
            latest = Path(temp_dir) / "latest.json"
            latest.write_text(update_manifest.canonical_json(manifest), encoding="utf-8")

            with mock.patch.dict(
                os.environ,
                {
                    auto_update.UPDATE_MODE_ENV: "manifest",
                    auto_update.UPDATE_SOURCE_ENV: latest.as_uri(),
                    "IND_UPDATE_SIGNING_KEYS": public_key,
                    "IND_UPDATE_CHANNEL": "stable",
                },
                clear=False,
            ):
                info = auto_update_impl.check_for_updates(repo, manual=True)
                self.assertTrue(info.available, info.error)
                result = auto_update_impl.install_update(repo, info)

            self.assertTrue(result.success, result.error)
            self.assertEqual((repo / "app.py").read_text(encoding="utf-8"), "new\n")
            self.assertEqual((repo / "files" / "secret.txt").read_text(encoding="utf-8"), "keep\n")
            self.assertEqual(update_manifest.read_update_state(repo / "files" / "update_state.json")["last_accepted_sequence"], 7)
            self.assertTrue(artifact_path.exists())

    def test_signed_manifest_bad_signature_and_rollback_reject(self):
        artifact = {"platform": "source", "url": "file:///release.zip", "sha3_256": "0" * 64, "size_bytes": 0}
        manifest, public_key = self._signed_manifest(artifact, sequence=5)
        tampered = dict(manifest)
        tampered["sequence"] = 6
        with self.assertRaises(update_manifest.UpdateManifestError):
            update_manifest.verify_update_manifest(tampered, [public_key], expected_channel="stable")
        with self.assertRaises(update_manifest.UpdateManifestError):
            update_manifest.verify_update_manifest(manifest, [public_key], min_sequence=6)

    def test_disabled_update_status_is_clean(self):
        status = update_manifest.normalize_update_status(
            {"type": update_manifest.UPDATE_STATUS_TYPE, "version": 1, "status": "disabled"}
        )
        self.assertEqual(status["status"], "disabled")

    def test_artifact_hash_or_size_mismatch_rejects_install(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir) / "repo"
            repo.mkdir()
            _artifact_path, artifact = self._write_source_zip(temp_dir, {"app.py": "new\n"})
            artifact["sha3_256"] = "1" * 64
            manifest, public_key = self._signed_manifest(artifact, sequence=3)
            latest = Path(temp_dir) / "latest.json"
            latest.write_text(update_manifest.canonical_json(manifest), encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {
                    auto_update.UPDATE_MODE_ENV: "manifest",
                    auto_update.UPDATE_SOURCE_ENV: latest.as_uri(),
                    "IND_UPDATE_SIGNING_KEYS": public_key,
                    "IND_UPDATE_CHANNEL": "stable",
                },
                clear=False,
            ):
                info = auto_update_impl.check_for_updates(repo, manual=True)
                result = auto_update_impl.install_update(repo, info)
        self.assertFalse(result.success)
        self.assertIn("sha3_256", result.error)


if __name__ == "__main__":
    unittest.main()

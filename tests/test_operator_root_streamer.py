import base64
import tempfile
import unittest
from hashlib import sha3_256
from pathlib import Path

import ecdsa

import ind_token
import log_client
import log_server
from operator_tools import hash_log_exporter
from operator_tools import root_streamer


def keypair():
    signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha3_256)
    verify_key = signing_key.get_verifying_key()
    private_key = base64.b85encode(signing_key.to_string()).decode("utf-8")
    public_key = base64.b85encode(verify_key.to_string()).decode("utf-8")
    return private_key, public_key


class OperatorRootStreamerTests(unittest.TestCase):
    def test_publish_once_writes_static_website_root_log(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            private_key, public_key = keypair()
            log = log_server.TransparencyLog(str(Path(temp_dir) / "log.db"), private_key, public_key)
            log.append_entry_hash(ind_token.sha3_hex(b"entry"))
            root = log.publish_root(1_700_000_000)

            website_dir = Path(temp_dir) / "website"
            state_file = Path(temp_dir) / "state.json"
            changed = root_streamer.publish_once(
                log_client.StaticRootMirror([root]),
                [root_streamer.StaticRootMirrorWriter(website_dir)],
                state_file,
                operator_public_key=public_key,
            )

            self.assertEqual(changed, 1)
            self.assertTrue((website_dir / "latest.json").exists())
            self.assertTrue((website_dir / "roots.jsonl").exists())
            self.assertTrue((website_dir / "manifest.json").exists())
            roots = log_client.DirectoryRootMirror(website_dir).roots()
            self.assertEqual(len(roots), 1)
            self.assertEqual(roots[0]["root_hash"], root["root_hash"])

            changed_again = root_streamer.publish_once(
                log_client.StaticRootMirror([root]),
                [root_streamer.StaticRootMirrorWriter(website_dir)],
                state_file,
                operator_public_key=public_key,
            )
            self.assertEqual(changed_again, 0)

    def test_static_writer_replaces_disabled_latest_placeholder(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            private_key, public_key = keypair()
            log = log_server.TransparencyLog(str(Path(temp_dir) / "log.db"), private_key, public_key)
            root = log.publish_root(1_700_000_000)
            website_dir = Path(temp_dir) / "website"
            website_dir.mkdir()
            (website_dir / "latest.json").write_text(
                '{"type":"ind.transparency_status.v1","status":"disabled"}\n',
                encoding="utf-8",
            )

            changed = root_streamer.StaticRootMirrorWriter(website_dir).publish_root(root)

            self.assertTrue(changed)
            latest = ind_token._load_json((website_dir / "latest.json").read_text(encoding="utf-8"))
            self.assertEqual(latest["root_hash"], root["root_hash"])

    def test_hash_log_exporter_writes_contiguous_entry_segments(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            private_key, public_key = keypair()
            log = log_server.TransparencyLog(str(Path(temp_dir) / "log.db"), private_key, public_key)
            first_hash = ind_token.sha3_hex(b"first")
            second_hash = ind_token.sha3_hex(b"second")
            log.append_entry_hash(first_hash)
            log.append_entry_hash(second_hash)
            root = log.publish_root(1_700_000_000)

            entries = log.entries(start=0, end=1, limit=2)
            self.assertEqual([entry["entry_hash"] for entry in entries], [first_hash, second_hash])

            class Source:
                def entries(self, start, end, limit):
                    return log.entries(start=start, end=end, limit=limit), log.tree_size()

                def latest_root(self):
                    return root

            archive_dir = Path(temp_dir) / "hash_archive"
            state_file = Path(temp_dir) / "hash_state.json"

            exported = hash_log_exporter.export_once(
                Source(),
                hash_log_exporter.StaticHashLogArchive(archive_dir, private_key, public_key),
                state_file,
                page_size=2,
            )

            self.assertEqual(exported, 2)
            self.assertTrue((archive_dir / "manifest.json").exists())
            manifest = ind_token._load_json((archive_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["signed_root_hash"], root["root_hash"])
            self.assertTrue(hash_log_exporter.verify_manifest_signature(manifest, public_key))
            segment_files = list((archive_dir / "entries").glob("*.jsonl"))
            self.assertEqual(len(segment_files), 1)
            self.assertEqual(len(segment_files[0].read_text(encoding="utf-8").splitlines()), 2)


if __name__ == "__main__":
    unittest.main()

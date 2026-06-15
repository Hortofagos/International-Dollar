import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pytest

from ind import address_generation
from ind import token as ind_token
from operator_tools import gossip_archive

os.environ.setdefault("IND_ALLOW_UNTRUSTED_GENESIS", "1")
pytestmark = pytest.mark.skip(reason="archived V1/V2 bill protocol tests")


class GossipArchiveTests(unittest.TestCase):
    def _store_with_message(self, db_path):
        issuer_address, issuer_private, issuer_public = address_generation.generate_legacy_keypair()
        owner_address, owner_private, owner_public = address_generation.generate_legacy_keypair()
        recipient_address, _recipient_private, _recipient_public = (
            address_generation.generate_legacy_keypair()
        )
        bill = ind_token.make_genesis_token(5, owner_address, issuer_private, issuer_public)
        transferred = ind_token.create_transfer(
            bill, owner_private, owner_public, recipient_address
        )
        announcement = ind_token.create_transfer_announcement(transferred)
        store = ind_token.INDLocalStore(db_path=db_path)
        result = store.ingest_message(announcement)
        self.assertTrue(result["accepted"])
        return announcement, issuer_address

    def test_export_audit_and_replay(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "gossip.db")
            announcement, _issuer_address = self._store_with_message(db_path)
            signer_address, signer_private, signer_public = (
                address_generation.generate_legacy_keypair()
            )
            self.assertTrue(signer_address)

            manifest = gossip_archive.export_archive(
                Path(temp_dir) / "archive",
                db_path=db_path,
                network="testnet",
                private_key=signer_private,
                public_key=signer_public,
                segment_size=1,
                manifest_timestamp=1_700_000_000,
            )

            self.assertEqual(manifest["message_count"], 1)
            audit = gossip_archive.audit_archive(
                Path(temp_dir) / "archive",
                expected_public_key=signer_public,
            )
            self.assertTrue(audit["ok"])

            with mock.patch.object(
                gossip_archive.testnet_peers,
                "broadcast_message_to_peers",
                return_value=[{"peer": "seed-a", "ok": True, "response": "ok"}],
            ) as broadcast:
                replay = gossip_archive.replay_archive(
                    Path(temp_dir) / "archive",
                    ["seed-a"],
                    expected_public_key=signer_public,
                )

            self.assertTrue(replay["ok"])
            self.assertEqual(replay["replayed_count"], 1)
            broadcast.assert_called_once()
            self.assertEqual(broadcast.call_args.args[0]["type"], announcement["type"])


if __name__ == "__main__":
    unittest.main()

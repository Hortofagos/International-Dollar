#!/usr/bin/env python3
import base64
import json
import os
import tempfile
import time
from hashlib import sha3_256
from pathlib import Path
import sys

import ecdsa

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import ind_token


os.environ.setdefault("IND_ALLOW_UNTRUSTED_GENESIS", "1")


def keypair():
    signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=sha3_256)
    verify_key = signing_key.get_verifying_key()
    private_key = base64.b85encode(signing_key.to_string()).decode("utf-8")
    public_key = base64.b85encode(verify_key.to_string()).decode("utf-8")
    return private_key, public_key, ind_token.address_from_public_key(public_key)


def main():
    issuer_private, issuer_public, _issuer_address = keypair()
    alice_private, alice_public, alice_address = keypair()
    bob_private, bob_public, bob_address = keypair()
    carol_private, carol_public, carol_address = keypair()

    token = ind_token.make_genesis_token(0, alice_address, issuer_private, issuer_public)
    branch_a = ind_token.create_transfer(token, alice_private, alice_public, bob_address)
    branch_b = ind_token.create_transfer(token, alice_private, alice_public, carol_address)

    with tempfile.TemporaryDirectory() as temp_dir:
        node_a = ind_token.INDLocalStore(str(Path(temp_dir) / "node_a.db"))
        node_b = ind_token.INDLocalStore(str(Path(temp_dir) / "node_b.db"))

        node_a.ingest_message(ind_token.create_transfer_announcement(branch_a))
        node_a.ingest_message(ind_token.create_receipt_announcement(branch_a, bob_private, bob_public))
        node_b.ingest_message(ind_token.create_transfer_announcement(branch_b))
        node_b.ingest_message(ind_token.create_receipt_announcement(branch_b, carol_private, carol_public))

        now = int(time.time()) + ind_token.FINALITY_BUFFER_SECONDS + 1
        settled_a = node_a.finalize_pending(now=now)
        settled_b = node_b.finalize_pending(now=now)

        conflict = ind_token.create_conflict_proof(branch_a, branch_b)
        node_a.ingest_message(conflict)
        node_b.ingest_message(conflict)

        result = {
            "settled_during_partition": {
                "node_a": bool(settled_a),
                "node_b": bool(settled_b),
            },
            "after_partition_heals": {
                "node_a_status": node_a.get_token_record(branch_a["token_id"])["status"],
                "node_b_status": node_b.get_token_record(branch_b["token_id"])["status"],
                "conflict_proof_valid": ind_token.verify_conflict_proof(conflict),
            },
        }
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

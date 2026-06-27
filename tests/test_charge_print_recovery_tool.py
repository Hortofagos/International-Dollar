from tools import charge_printed_bills_from_recovery as charge_recovery

from ind import keys_v3


def test_read_charge_map_text_file(tmp_path):
    address, _private_key, _public_key = keys_v3.generate_keypair(b"\x71" * 32)
    mapping_path = tmp_path / "paper_wallet_charge_addresses.txt"
    mapping_path.write_text(f"100000x4701 {address}\n", encoding="utf-8")

    assert charge_recovery._read_charge_map(mapping_path) == {"100000x4701": address}


def test_read_charge_map_generated_csv(tmp_path):
    address, _private_key, _public_key = keys_v3.generate_keypair(b"\x74" * 32)
    mapping_path = tmp_path / "paper_wallet_charge_addresses.csv"
    mapping_path.write_text(
        "serial,charge_address,next_sequence,selection_index,pdf_order_index,print_mode,created_at_utc\n"
        f"100000x4701,{address},2,1,1,full,2026-06-25T10:00:00Z\n",
        encoding="utf-8",
    )

    assert charge_recovery._read_charge_map(mapping_path) == {"100000x4701": address}


def test_charge_from_recovery_dry_run_counts_ready_and_missing():
    owner_address, _private_key, _public_key = keys_v3.generate_keypair(b"\x72" * 32)
    paper_address, _paper_private, _paper_public = keys_v3.generate_keypair(b"\x73" * 32)

    class Store:
        def bill_v3_records_for_owner(self, owner, statuses=None, limit=None):
            assert owner == owner_address
            assert statuses == ("settled", "verified")
            return [{"display_id": "100000x4701"}]

    result = charge_recovery.charge_from_recovery(
        {
            "100000x4701": paper_address,
            "100000x4702": paper_address,
        },
        [
            owner_address + "\n",
            "private\n",
            "public\n",
            "100000x4701 2 1700000000\n",
        ],
        Store(),
        execute=False,
    )

    assert result["ready"] == ["100000x4701"]
    assert result["missing"] == ["100000x4702"]
    assert result["errors"] == []

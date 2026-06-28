import types
from hashlib import sha3_256

import pytest

from ind import keys_v3
from ind import operator_storage
from ind import transparency_server as log_server
from tools import operator_db


def _operator_keypair(label):
    seed = sha3_256(label.encode("utf-8")).digest()
    _address, private_key, public_key = keys_v3.generate_keypair(seed)
    return private_key, public_key


def test_operator_status_reports_sqlite_storage_health(tmp_path):
    private_key, public_key = _operator_keypair("storage-status")
    log = log_server.TransparencyLog(tmp_path / "operator.db", private_key, public_key)

    status = log.status()

    assert status["storage_backend"] == "sqlite"
    assert status["storage_healthy"] is True
    assert status["storage"]["schema_version"] >= 1


def test_operator_db_readonly_verify_checks_signed_roots(tmp_path):
    private_key, public_key = _operator_keypair("storage-verify")
    log = log_server.TransparencyLog(tmp_path / "operator.db", private_key, public_key)
    log.append_entry_hash("11" * 32, submitted_at=1_700_000_001)
    root = log.publish_root(1_700_000_010)

    result = operator_db.verify_storage(
        operator_db.ReadOnlySQLiteStorage(tmp_path / "operator.db"),
        public_key,
    )

    assert result["ok"] is True
    assert result["tree_size"] == 1
    assert result["latest_signed_root"]["root_hash"] == root["root_hash"]


def test_operator_db_requires_explicit_mainnet_readonly_copy_flag():
    args = types.SimpleNamespace(network="mainnet", allow_mainnet_read_only_copy=False)

    with pytest.raises(SystemExit, match="mainnet operator storage"):
        operator_db._mainnet_guard(args)


def test_mariadb_backend_refuses_non_loopback_host():
    with pytest.raises(operator_storage.OperatorStorageError, match="127.0.0.1"):
        operator_storage.MariaDBOperatorStorage(
            host="203.0.113.10",
            database="operator",
            user="operator",
            password="secret",
        )

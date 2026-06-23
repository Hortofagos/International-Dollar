import io
import json
import tarfile

import pytest

from tools import testnet_backup


def _write_backup_key(path):
    key = bytes(range(32))
    testnet_backup.atomic_write_json(
        path,
        {
            "type": "ind.testnet_offsite_backup_key.v3",
            "version": 1,
            "algorithm": "AES-256-GCM",
            "created_at": 1_700_000_000,
            "key_b64": testnet_backup.b64encode(key),
        },
    )
    return key


def _tar_bytes(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in entries.items():
            raw = data.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return buffer.getvalue()


def _write_encrypted_backup(path, key, tar_bytes):
    metadata = {
        "type": "ind.testnet_offsite_backup.v3",
        "version": 1,
        "created_at": 1_700_000_001,
        "created_at_iso": "2023-11-14T22:13:21+00:00",
        "source_host": "operator.example.test",
        "source_user": "indnode",
        "algorithm": "AES-256-GCM",
        "tar_format": "tar.gz",
        "tar_sha3_256": testnet_backup.hashlib.sha3_256(tar_bytes).hexdigest(),
        "tar_size_bytes": len(tar_bytes),
        "included_paths": ["var/lib/ind-node/operator.db"],
    }
    nonce, ciphertext = testnet_backup.encrypt_backup(tar_bytes, key, metadata)
    payload = {
        **metadata,
        "nonce_b64": testnet_backup.b64encode(nonce),
        "ciphertext_b64": testnet_backup.b64encode(ciphertext),
    }
    testnet_backup.atomic_write_json(path, payload)
    return payload


def test_verify_and_extract_encrypted_backup(tmp_path):
    key_file = tmp_path / "backup-key.json"
    key = _write_backup_key(key_file)
    backup_path = tmp_path / "backup.json"
    _write_encrypted_backup(
        backup_path,
        key,
        _tar_bytes({"var/lib/ind-node/operator.db": "sqlite bytes"}),
    )

    verified = testnet_backup.verify_backup_file(backup_path, key_file)
    extracted = testnet_backup.extract_backup_file(backup_path, key_file, tmp_path / "restore")

    assert verified["ok"] is True
    assert verified["tar_entry_count"] == 1
    assert extracted["extracted_entry_count"] == 1
    assert (tmp_path / "restore" / "var/lib/ind-node/operator.db").read_text(
        encoding="utf-8"
    ) == "sqlite bytes"


def test_verify_backup_rejects_authenticated_metadata_tamper(tmp_path):
    key_file = tmp_path / "backup-key.json"
    key = _write_backup_key(key_file)
    backup_path = tmp_path / "backup.json"
    payload = _write_encrypted_backup(
        backup_path,
        key,
        _tar_bytes({"var/lib/ind-node/operator.db": "sqlite bytes"}),
    )
    payload["source_host"] = "attacker.example.test"
    backup_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(testnet_backup.BackupError, match="authentication failed"):
        testnet_backup.verify_backup_file(backup_path, key_file)


def test_verify_backup_rejects_unsafe_tar_path(tmp_path):
    key_file = tmp_path / "backup-key.json"
    key = _write_backup_key(key_file)
    backup_path = tmp_path / "backup.json"
    _write_encrypted_backup(backup_path, key, _tar_bytes({"../escape": "bad"}))

    with pytest.raises(testnet_backup.BackupError, match="unsafe backup tar member"):
        testnet_backup.verify_backup_file(backup_path, key_file)


def test_remote_tar_paths_must_be_absolute():
    with pytest.raises(testnet_backup.BackupError, match="must be absolute"):
        testnet_backup.tar_paths(["var/lib/ind-node"])

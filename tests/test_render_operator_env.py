import json

import pytest

from tools import render_operator_env


def test_testnet_operator_set_loads():
    operator_set = render_operator_env.load_operator_set(
        render_operator_env.DEFAULT_OPERATOR_SET
    )

    assert len(operator_set["operators"]) == 2


def test_operator_set_rejects_same_origin_mirror(tmp_path):
    path = tmp_path / "operator-set.json"
    path.write_text(
        json.dumps(
            {
                "operators": [
                    {
                        "name": "bad",
                        "url": "https://operator.example.test/operator-api",
                        "public_key": "operator-key",
                        "mirrors": [
                            "https://operator.example.test/transparency",
                            "https://mirror.example.test/transparency",
                        ],
                        "proof_archives": [
                            "https://mirror.example.test/transparency/archive"
                        ],
                    }
                ],
                "min_root_mirrors": 2,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        render_operator_env.OperatorSetError,
        match="must not share the operator append HTTP origin",
    ):
        render_operator_env.load_operator_set(path)


def test_operator_set_rejects_missing_proof_archives(tmp_path):
    path = tmp_path / "operator-set.json"
    path.write_text(
        json.dumps(
            {
                "operators": [
                    {
                        "name": "bad",
                        "url": "https://operator.example.test/operator-api",
                        "public_key": "operator-key",
                        "mirrors": [
                            "https://mirror-a.example.test/transparency",
                            "https://mirror-b.example.test/transparency",
                        ],
                        "proof_archives": [
                            "https://archive-a.example.test/transparency/archive"
                        ],
                    }
                ],
                "min_root_mirrors": 2,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        render_operator_env.OperatorSetError,
        match="has 1 proof archive",
    ):
        render_operator_env.load_operator_set(path)


def test_operator_set_rejects_same_origin_proof_archive(tmp_path):
    path = tmp_path / "operator-set.json"
    path.write_text(
        json.dumps(
            {
                "operators": [
                    {
                        "name": "bad",
                        "url": "https://operator.example.test/operator-api",
                        "public_key": "operator-key",
                        "mirrors": [
                            "https://mirror-a.example.test/transparency",
                            "https://mirror-b.example.test/transparency",
                        ],
                        "proof_archives": [
                            "https://operator.example.test/transparency/archive",
                            "https://archive-b.example.test/transparency/archive",
                        ],
                    }
                ],
                "min_root_mirrors": 2,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        render_operator_env.OperatorSetError,
        match="proof archive must not share the operator append HTTP origin",
    ):
        render_operator_env.load_operator_set(path)

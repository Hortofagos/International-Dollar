import pytest

from ind import keys_v3
from tools import operator_admission


def _keypair(seed):
    _address, private_key, public_key = keys_v3.generate_keypair(bytes([seed]) * 32)
    return private_key, public_key


def _operator_set():
    _private_key, public_key = _keypair(1)
    return {
        "network": "testnet",
        "min_root_mirrors": 2,
        "operators": [
            {
                "name": "primary",
                "url": "https://primary.example.test/operator-api",
                "public_key": public_key,
                "mirrors": [
                    "https://primary-mirror-a.example.test/transparency",
                    "https://primary-mirror-b.example.test/transparency",
                ],
                "proof_archives": [
                    "https://primary-archive-a.example.test/transparency/archive",
                    "https://primary-archive-b.example.test/transparency/archive",
                ],
            }
        ],
    }


def _candidate_bundle(seed=2, **overrides):
    private_key, public_key = _keypair(seed)
    bundle = operator_admission.make_candidate_bundle(
        name=overrides.pop("name", "candidate"),
        network=overrides.pop("network", "testnet"),
        public_key=public_key,
        append_url=overrides.pop("append_url", "https://candidate.example.test/operator-api"),
        mirrors=overrides.pop(
            "mirrors",
            [
                "https://candidate-mirror-a.example.test/transparency",
                "https://candidate-mirror-b.example.test/transparency",
            ],
        ),
        proof_archives=overrides.pop(
            "proof_archives",
            [
                "https://candidate-archive-a.example.test/transparency/archive",
                "https://candidate-archive-b.example.test/transparency/archive",
            ],
        ),
        stage=overrides.pop("stage", "burn_in_passed"),
        uptime_status=overrides.pop("uptime_status", "passed"),
        audit_status=overrides.pop("audit_status", "passed"),
        created_at=1_800_000_000,
        **overrides,
    )
    return operator_admission.sign_candidate_bundle(bundle, private_key), private_key, public_key


def test_signed_candidate_bundle_verifies_against_operator_set():
    bundle, _private_key, _public_key = _candidate_bundle()

    report = operator_admission.verify_candidate_bundle(
        bundle,
        operator_set=_operator_set(),
        require_burn_in=True,
    )

    assert report["ok"] is True
    assert report["operator"]["name"] == "candidate"
    assert {check["name"] for check in report["checks"]} >= {
        "operator_shape",
        "candidate_signature",
        "burn_in",
        "operator_set_candidate",
    }


def test_candidate_bundle_requires_operator_key_signature():
    bundle, _private_key, _public_key = _candidate_bundle()
    bundle["operator"]["mirrors"][0] = "https://changed.example.test/transparency"

    with pytest.raises(operator_admission.OperatorAdmissionError, match="signature"):
        operator_admission.verify_candidate_bundle(bundle, operator_set=_operator_set())


def test_candidate_bundle_rejects_duplicate_operator_identity():
    bundle, _private_key, _public_key = _candidate_bundle(name="primary")

    with pytest.raises(operator_admission.OperatorAdmissionError, match="already exists"):
        operator_admission.verify_candidate_bundle(bundle, operator_set=_operator_set())


def test_operator_set_update_is_signed_and_verified():
    operator_set = _operator_set()
    bundle, _candidate_private, _candidate_public = _candidate_bundle()
    maintainer_private, maintainer_public = _keypair(9)

    update = operator_admission.make_operator_set_update(
        operator_set,
        bundle,
        signing_private_key=maintainer_private,
        signing_public_key=maintainer_public,
        created_at=1_800_000_100,
    )
    report = operator_admission.verify_operator_set_update(
        update,
        operator_set,
        bundle,
        [maintainer_public],
    )

    assert report["ok"] is True
    assert report["operator_count"] == 2
    assert report["proposed_operator_set"]["operators"][-1]["name"] == "candidate"


def test_operator_set_update_requires_burn_in_by_default():
    bundle, _private_key, _public_key = _candidate_bundle(
        stage="candidate_mirror",
        uptime_status="running",
        audit_status="pending",
    )
    maintainer_private, maintainer_public = _keypair(9)

    with pytest.raises(operator_admission.OperatorAdmissionError, match="burn-in"):
        operator_admission.make_operator_set_update(
            _operator_set(),
            bundle,
            signing_private_key=maintainer_private,
            signing_public_key=maintainer_public,
        )

# Run local V3 testnet readiness smoke checks.

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _python():
    candidate = ROOT / ".venv" / "Scripts" / "python.exe"
    return str(candidate if candidate.exists() else sys.executable)


def check_wallet_and_store():
    from ind import address_generation, keys_v3
    from ind.store import INDLocalStore

    address, private_key, public_key = address_generation.generate_keypair()
    keys_v3.validate_address(address)
    if not keys_v3.public_key_matches_address(public_key, address):
        raise RuntimeError("generated V3 public key does not match address")
    store = INDLocalStore(require_transparency=False)
    with store._connect() as conn:
        schema_version = store._schema_version(conn)
    return {
        "active_bill_protocol": "v3",
        "address_prefix": address[:4],
        "private_key_prefix": private_key[:7],
        "public_key_prefix": public_key[:7],
        "store_schema": schema_version,
    }


def check_transparency(strict):
    from ind import transparency_client as log_client

    verifier = log_client.verifier_from_environment(strict_mode=strict)
    if verifier is None:
        if strict:
            raise RuntimeError("strict transparency verifier is not configured")
        return {"configured": False}
    root = verifier.current_mirrored_root()
    return {
        "configured": True,
        "log_id": root["log_id"],
        "tree_size": int(root["tree_size"]),
        "timestamp": int(root["timestamp"]),
        "min_mirrors": int(verifier.min_mirrors),
    }


def run_pytest():
    tests = [
        "tests/test_v3_testnet_readiness.py",
        "tests/test_archive_segment_v3.py",
        "tests/test_protocol_v3.py",
        "tests/test_store_v3.py",
        "tests/test_spend_map_v3.py",
        "tests/test_testnet_operator_tools.py::test_v3_double_spend_drill_builds_native_conflict",
    ]
    command = [_python(), "-m", "pytest", *tests, "-q"]
    env = _pytest_environment()
    completed = subprocess.run(command, cwd=ROOT, check=False, env=env)
    if completed.returncode != 0:
        raise RuntimeError(f"pytest smoke tests failed with exit code {completed.returncode}")
    return {"command": " ".join(command), "environment": "isolated-local", "passed": True}


def _pytest_environment():
    env = os.environ.copy()
    env["IND_REQUIRE_TRANSPARENCY_LOG"] = "0"
    env["IND_SUBMIT_TO_TRANSPARENCY_LOG"] = "0"
    live_operator_env = [
        "IND_LOG_OPERATORS",
        "IND_LOG_OPERATOR_URL",
        "IND_LOG_OPERATOR_PUBLIC_KEY",
        "IND_LOG_MIRROR_URLS",
        "IND_LOG_PROOF_ARCHIVES",
        "IND_LOG_MIN_MIRRORS",
        "IND_LOG_OBSERVED_ROOTS_DB",
        "IND_LOG_CONSISTENCY_ANCHOR",
        "IND_OPERATOR_APPEND_FANOUT",
        "IND_OPERATOR_CORE_DOMAINS",
        "IND_OPERATOR_FINALITY_MIN_PROOFS",
        "IND_OPERATOR_RECOVERY_FEEDS",
        "IND_OPERATOR_RECOVERY_MIRRORS",
        "IND_OPERATOR_RECOVERY_PROOF_ARCHIVES",
        "IND_OPERATOR_RECOVERY_MIN_FEEDS",
        "IND_SETTLEMENT_QUORUM_ENABLED",
        "IND_SETTLEMENT_REQUIRE_ALL_CONFIGURED_PEERS",
        "IND_TRANSPARENCY_SUBMIT_ASYNC",
    ]
    for name in live_operator_env:
        env.pop(name, None)
    return env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict-transparency", action="store_true")
    parser.add_argument("--run-pytest", action="store_true")
    args = parser.parse_args()

    report = {
        "wallet_store": check_wallet_and_store(),
        "transparency": check_transparency(strict=args.strict_transparency),
    }
    if args.run_pytest:
        report["pytest"] = run_pytest()
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()

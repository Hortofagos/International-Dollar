import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".cfg",
    ".example",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SKIP_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "files",
    "full_activation",
    "output",
    "print_folder",
    "transaction_folder",
    "venv",
    "wallet_folder",
}
SKIP_FILES = {
    Path("tests/test_no_active_legacy_protocol_refs.py"),
}
ALLOWED_MATCHES = {
    # Batch gossip is a transport envelope version, not the retired V1/V2 bill protocol.
    (Path("ind/node_client.py"), "versioned type suffix", ".v1"),
    # Probe report schema version, not the retired V1/V2 bill protocol.
    (Path("tools/v3_operator_fanout_probe.py"), "versioned type suffix", ".v1"),
}
FORBIDDEN = {
    "versioned type suffix": re.compile(r"\.v[12]\b"),
    "versioned HTTP path": re.compile(r"/v[12]\b"),
    "old domain suffix": re.compile(r"_V[12]\b"),
    "old wallet prefix": re.compile(r"\bINDW[12]\b"),
    "old token version constant": re.compile(r"\bTOKEN_VERSION\s*=\s*1\b"),
    "old bill version constant": re.compile(r"\bBILL_VERSION\s*=\s*2\b"),
    "old compact transfer helper": re.compile(r"\bcreate_transfer_v2\b"),
    "old spend-claim migration table": re.compile(r"\bspend_claims_v2\b"),
    "old paired protocol wording": re.compile(r"\bV1/V2\b"),
    "old protocol prose": re.compile(r"\bprotocol-v[12]\b|\bv2 compact\b"),
    "old genesis domain": re.compile(r"IND-(?:MERKLE-[A-Z]+|GENESIS)-v[12]"),
}


def _is_scanned(path):
    rel = path.relative_to(ROOT)
    if rel in SKIP_FILES:
        return False
    if any(part in SKIP_DIRS for part in rel.parts):
        return False
    return path.suffix.lower() in TEXT_SUFFIXES


def test_active_tree_has_no_v1_v2_protocol_references():
    failures = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or not _is_scanned(path):
            continue
        rel = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8")
        for label, pattern in FORBIDDEN.items():
            match = pattern.search(text)
            if match:
                if (rel, label, match.group(0)) in ALLOWED_MATCHES:
                    continue
                failures.append(f"{rel}: {label}: {match.group(0)!r}")

    assert not failures, "active legacy protocol references remain:\n" + "\n".join(failures)


def test_active_wallet_generation_has_no_ecdsa_fallbacks():
    path = ROOT / "ind" / "address_generation.py"
    text = path.read_text(encoding="utf-8")
    forbidden = {
        "ecdsa import": "ecdsa",
        "legacy wallet env": "IND_LEGACY_WALLET_KEYS",
        "legacy keypair helper": "generate_legacy_keypair",
        "legacy address helper": "address_from_public_key",
    }
    failures = [label for label, needle in forbidden.items() if needle in text]

    assert not failures, "wallet generation still exposes legacy ECDSA paths: " + ", ".join(
        failures
    )


def test_active_tree_does_not_depend_on_python_ecdsa():
    scanned = [ROOT / "requirements.txt"]
    scanned.extend((ROOT / "ind").rglob("*.py"))
    scanned.extend((ROOT / "tools").rglob("*.py"))
    failures = []
    for path in scanned:
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        text = path.read_text(encoding="utf-8").lower()
        if "ecdsa" in text or "secp256" in text or "signingkey" in text or "verifyingkey" in text:
            failures.append(str(rel))

    assert not failures, "python-ecdsa references remain in active code: " + ", ".join(failures)


def test_retired_json_bill_entrypoints_are_removed():
    removed_paths = [
        Path("confirm_validity.py"),
        Path("ind/conflicts.py"),
        Path("ind/genesis.py"),
        Path("ind/receipts.py"),
        Path("ind/transfers.py"),
        Path("ind/validity.py"),
        Path("tools/generate_genesis.py"),
        Path("tools/mint_lazy_token.py"),
        Path("tools/simulate_partition.py"),
        Path("tools/testnet_double_spend_drill.py"),
        Path("tools/testnet_faucet.py"),
        Path("tools/testnet_multihop_smoke.py"),
        Path("tools/testnet_smoke.py"),
    ]
    existing = [str(path) for path in removed_paths if (ROOT / path).exists()]

    assert not existing, "retired JSON bill entrypoints still exist: " + ", ".join(existing)

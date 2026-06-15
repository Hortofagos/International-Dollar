# V3 Testnet Runbook

V3 testnet nodes should run with V3 wallet generation, V3 gossip enabled, and
strict transparency verification unless the node is an explicitly local
developer sandbox.

V3 is the only active bill protocol for the clean testnet.

## Local Smoke

```powershell
.\.venv\Scripts\python.exe tools\v3_testnet_smoke.py --run-pytest
```

This checks:

- default wallet generation returns x3 Ed25519 keys
- the local store initializes the V3 schema
- V3 transfer/proof/archive gossip tests pass
- V3 archive, proof bundle, receipt, conflict, and spend-map tests pass
- native V3 double-spend drill message construction passes

## Strict Transparency Gate

Production-like testnet nodes must configure independent root mirrors:

```powershell
$env:IND_REQUIRE_TRANSPARENCY_LOG = "1"
$env:IND_LOG_OPERATOR_URL = "https://operator.example"
$env:IND_LOG_OPERATOR_PUBLIC_KEY = "<operator-public-key>"
$env:IND_LOG_MIRROR_URLS = "https://mirror-a.example,https://mirror-b.example"
$env:IND_LOG_MIN_MIRRORS = "2"
.\.venv\Scripts\python.exe tools\v3_testnet_smoke.py --strict-transparency
```

Do not set `IND_LOG_UNSAFE_SINGLE_MIRROR=1` outside a local developer sandbox.

## Operator Gate

Before advertising an operator:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_v3_testnet_readiness.py tests\test_transparency_log.py -q
```

The operator must:

- accept V3 transfer announcements with embedded proof/archive evidence
- serve spend-map proofs from the persisted current sparse-map cache
- publish roots whose spend-map root matches a full rebuild
- reject conflicting spend claims

## Node Gate

Before joining public peers:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_node_services.py tests\test_network_request_results.py -q
```

The node must ingest and relay:

- `ind.transfer_announcement.v3`
- `ind.receipt_announcement.v3`
- `ind.proof_bundle_announcement.v3`
- `ind.archive_segment_announcement.v3`
- `ind.conflict_proof.v3`

It must reject legacy bill gossip (`ind.transfer_announcement.v1`,
`ind.transfer_announcement.v2`, `ind.receipt_announcement.v1`,
`ind.receipt_announcement.v2`, and `ind.conflict_proof.v1`).

## V3 Conflict Drill

Build a native V3 double-spend drill from a stored BillV3:

```powershell
.\.venv\Scripts\python.exe tools\v3_double_spend_drill.py --display-id <display-id> --wallet-address <x3-wallet> --peer seed-a --peer seed-b
```

Use `--dry-run` to generate and verify the two V3 transfer announcements and
V3 conflict proof without broadcasting.

## Launch Checklist

- V3 smoke script passes.
- Full test suite passes.
- At least two independent root mirrors are configured.
- Operator root freshness and consistency monitors are active.
- Proof archive publication is enabled.
- Faucet/wallet tooling creates x3 wallets by default.
- V1/V2 generation is used only with `IND_LEGACY_WALLET_KEYS=1`.
- V1/V2 bill protocol execution is disabled.

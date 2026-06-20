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
- V3 archive, proof bundle, conflict, spend-map, and receipt-retirement tests pass
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

Strict public-testnet nodes should render their transparency environment from
`testnet/operator_set.testnet.json`:

```powershell
python tools/render_operator_env.py --format systemd
```

For systemd services, prefer an `EnvironmentFile` for the generated JSON:

```powershell
python tools/render_operator_env.py --format systemd-envfile
```

Install the same operator-set environment for both the node service and the
transparency operator service. The node uses it for append fanout/finality; the
operator uses it to verify that historical checkpoints were signed by any
configured operator in the network.

Each operator entry with a `url` is append-capable and counts toward
`IND_OPERATOR_FINALITY_MIN_PROOFS`. To add operators, append another object with
`url`, `public_key`, at least two independent `mirrors`, and `proof_archives`;
the renderer will raise if the set is incomplete.

Do not count a mirror hosted on the same HTTP origin as the operator append API.
Strict verification rejects that shape because it cannot defend against an
operator/API-origin split view.

## Mirror Freshness

Run root publication and archive publication as separate jobs. Root mirrors are
the current-spend safety path; a missing or delayed hash-log archive must not
block `latest.json` from refreshing.

For cross-host static mirrors, use `tools/publish_testnet_static_mirror.py` with
`--allow-missing-archive`, or `--no-archive` when the job is intentionally
root-only. Each operator should have independent root publishers for:

- local operator root to local website mirror
- local operator root to the opposite VPS website mirror

Configure the testnet monitor with every required public root mirror so stale
heartbeat roots fail loudly:

```powershell
$env:IND_TESTNET_MONITOR_MIRROR_ROOT_URLS = "https://mirror-a.example/transparency,https://mirror-b.example/transparency"
python tools/testnet_monitor.py --json --strict
```

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
- `ind.proof_bundle_announcement.v3`
- `ind.archive_segment_announcement.v3`
- `ind.conflict_proof.v3`

It must reject legacy bill gossip and retired receipt announcements
(`ind.receipt_announcement.v3`).

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
- Root mirror publication is independent from proof/archive publication.
- Proof archive publication is enabled and monitored separately.
- Faucet/wallet tooling creates x3 wallets by default.
- Historical bill generation toggles are absent from runtime configuration.
- V3 bill protocol execution is the only enabled path.

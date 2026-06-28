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
the append operator directory. Wallets/nodes submit each transfer to at most
`IND_OPERATOR_APPEND_FANOUT` selected operators, default 5. Operators whose
append URLs are under `international-dollar.com` or `internetofthebots.com` are
pinned into that selected pool when configured, then the remaining slots rotate
across the rest of the operator set. `IND_OPERATOR_FINALITY_MIN_PROOFS=0`
requires proofs from every selected append operator, not every known operator.
To add operators, append another object with `url`, `public_key`, at least two
independent `mirrors`, and `proof_archives`; the renderer will raise if the set
is incomplete.

Do not count a mirror hosted on the same HTTP origin as the operator append API.
Strict verification rejects that shape because it cannot defend against an
operator/API-origin split view.

## Operator Admission

Normal nodes are permissionless. Anyone can run the GUI node or `node_client.py`
and join gossip if their TCP port is reachable. That does not give finality
weight and does not make the node an append-capable operator.

For a headless public-testnet VPS that should join as seed/mirror/auditor only,
use the seed bootstrap renderer from the synced repo:

```bash
python tools/testnet_seed_bootstrap.py \
  --public-host <this-vps-ip-or-dns> \
  --peer testnet-seed.international-dollar.com \
  --peer testnet-seed.internetofthebots.com \
  --canary-ref 1x1782156155 \
  --canary-ref 2x1782156156
```

Review the rendered files, then run the same command with `--install` on the
VPS after `/opt/international-dollar/.venv` exists. The generated service
initializes the testnet runtime state with `kill_node=false`, installs an
`ExecStartPre` guard so restarts stay up, uses a systemd EnvironmentFile for
operator-set verification variables, configures explicit peers without editing
the committed operator set, serves only static mirror paths, blocks
`/operator-api/`, and filters the VPS public host out of on-box convergence
checks to avoid false self-query failures. Monitor units run with small retry
windows so ordinary mirror propagation lag does not create noisy failures.

After install, run the generated local check on the VPS:

```bash
/usr/local/bin/ind-testnet-seed-local-verify
```

From another host, verify public reachability and convergence with the new seed
included:

```powershell
$env:IND_NETWORK='testnet'
$env:IND_NODE_PORT='18888'
.\.venv\Scripts\python.exe tools\testnet_convergence_monitor.py --json --strict `
  --peer testnet-seed.international-dollar.com `
  --peer testnet-seed.internetofthebots.com `
  --peer <new-seed-ip-or-dns> `
  --ref 1x1782156155 `
  --ref 2x1782156156
```

Append-capable transparency operators are admitted through a signed operator-set
update. The intended public flow is:

1. Anyone runs a GUI/gossip node.
2. A candidate opts into operator-candidate mode and runs mirrors first.
3. The candidate produces an admission bundle naming their operator public key,
   append URL, mirrors, proof archives, uptime proof, and audit report.
4. The candidate signs that bundle with the proposed operator key.
5. Existing maintainers verify mirror/auditor burn-in.
6. A maintainer signs an operator-set update.
7. Nodes upgrade to the new operator set together.

Create a candidate bundle:

```powershell
python tools/operator_admission.py candidate-bundle `
  --name candidate-name `
  --network testnet `
  --public-key indpk3:... `
  --append-url https://candidate.example/operator-api `
  --mirror https://mirror-a.example/transparency `
  --mirror https://mirror-b.example/transparency `
  --proof-archive https://archive-a.example/transparency/archive `
  --proof-archive https://archive-b.example/transparency/archive `
  --stage burn_in_passed `
  --uptime-status passed `
  --audit-status passed `
  --private-key-file candidate_operator_private_key.local `
  --output files/testnet/candidate-operator-bundle.local.json
```

Verify the bundle before it can affect finality:

```powershell
python tools/operator_admission.py verify-bundle `
  files/testnet/candidate-operator-bundle.local.json `
  --operator-set testnet/operator_set.testnet.json `
  --require-burn-in
```

Sign an add-operator proposal after burn-in:

```powershell
python tools/operator_admission.py propose-update `
  files/testnet/candidate-operator-bundle.local.json `
  --operator-set testnet/operator_set.testnet.json `
  --signing-private-key-file maintainer_operator_set_signing_key.local `
  --signing-public-key indpk3:... `
  --output files/testnet/operator-set-update.local.json
```

Verify and write the proposed operator set:

```powershell
python tools/operator_admission.py apply-update `
  files/testnet/operator-set-update.local.json `
  --bundle files/testnet/candidate-operator-bundle.local.json `
  --operator-set testnet/operator_set.testnet.json `
  --trusted-signing-key indpk3:... `
  --output files/testnet/operator_set.next.local.json
```

Do not distribute the new operator-set environment until the new operator has
passed the full burn-in round and every configured mirror/archive URL is live.

## Mirror Freshness

Run root publication and archive publication as separate jobs. Root mirrors are
the current-spend safety path; hash-log archives are the required operator audit
path. A missing or delayed archive must not block `latest.json` from refreshing,
but it is still a production-readiness failure for an append-capable operator.

For cross-host static mirrors, use `tools/publish_testnet_static_mirror.py` with
`--allow-missing-archive` only for emergency root freshness. Each append-capable
operator must also publish `archive/manifest.json` and every segment referenced
by it at each configured `proof_archives` URL. Each operator should have
independent root publishers for:

- local operator root to local website mirror
- local operator root to the opposite VPS website mirror

Configure the testnet monitor with every required public root mirror so stale
heartbeat roots fail loudly:

```powershell
$env:IND_TESTNET_MONITOR_MIRROR_ROOT_URLS = "https://mirror-a.example/transparency,https://mirror-b.example/transparency"
python tools/testnet_monitor.py --json --strict
```

## Backup And Restore Drills

Encrypted off-server backups are not considered healthy until they pass a local
restore drill. `tools/testnet_backup.py` can now verify an existing encrypted
backup without contacting the VPS:

```powershell
python tools/testnet_backup.py `
  --verify-backup files/testnet/backups/ind-testnet-offsite-YYYYMMDD-HHMMSS.tar.gz.aesgcm.json `
  --key-file files/testnet/offsite_backup_key.local.json
```

For a restore drill, extract only into a disposable local directory:

```powershell
python tools/testnet_backup.py `
  --extract-backup files/testnet/backups/ind-testnet-offsite-YYYYMMDD-HHMMSS.tar.gz.aesgcm.json `
  --key-file files/testnet/offsite_backup_key.local.json `
  --restore-dir files/testnet/restore-drills/YYYYMMDD-HHMMSS
```

The verifier checks AES-GCM authentication, the decrypted tar SHA3-256 digest,
declared tar size, non-empty tar contents, and unsafe tar paths before any
extract. Extraction refuses path traversal, device files, FIFOs, hard links, and
symlinks. A production operator should run this drill after backup changes and
before any mainnet genesis material depends on that operator.

## MariaDB Operator Storage

MariaDB is optional and only for append-capable transparency operators. Do not
move wallet/node gossip stores to MariaDB, and do not use Redis/NoSQL as
canonical operator truth.

Install the optional Python dependency only on operator hosts:

```bash
/opt/international-dollar/.venv/bin/pip install -r /opt/international-dollar/requirements-operator.txt
```

Each append-capable operator should use a local MariaDB database:

- primary testnet: `ind_operator_primary_testnet`
- iotb testnet: `ind_operator_iotb_testnet`
- operator3 testnet: `ind_operator3_testnet`

Keep MariaDB bound to a local socket or `127.0.0.1`. Use SSH tunnels or on-box
sudo for remote administration; do not expose port `3306` publicly.

Initialize a MariaDB target after setting `IND_LOG_MARIADB_*` in the operator
service environment:

```bash
cd /var/lib/ind-node
export PYTHONPATH=/opt/international-dollar
export IND_LOG_BACKEND=mariadb
/opt/international-dollar/.venv/bin/python /opt/international-dollar/tools/operator_db.py init-mariadb
```

Copy an existing testnet operator SQLite log into an empty MariaDB database:

```bash
/opt/international-dollar/.venv/bin/python /opt/international-dollar/tools/operator_db.py sqlite-to-mariadb \
  --network testnet \
  --sqlite-db /var/lib/ind-node/ind_transparency_testnet_log.db \
  --operator-public-key "$IND_LOG_OPERATOR_PUBLIC_KEY"
```

For mainnet, the migration helper requires `--allow-mainnet-read-only-copy` and
still treats the SQLite database as a read-only source. Do not overwrite or
delete `/var/lib/ind-mainnet-node` databases, genesis manifests, signed hash
files, operator keys, mirror roots, or archive outputs. Mainnet rollback must
write a new SQLite file with `mariadb-to-sqlite`, verify roots, and only then be
considered for a manual service switch.

Recommended testnet rollout order:

1. Migrate operator3 on `108.61.23.82` as the MariaDB canary.
2. Observe append fanout, root freshness, hash-log export, and backups for 24-48 hours.
3. Migrate iotb on `91.99.175.174`.
4. Migrate primary on `167.233.115.216`.
5. Leave OVH `51.83.199.25` mirror/seed-only; it should not hold canonical operator truth.

After a service switch, `/v3/status` must report `storage_backend=mariadb` and
`storage_healthy=true`; strict monitors should fail if an expected MariaDB
operator reports otherwise.

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

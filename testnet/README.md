# IND Public Testnet

This folder contains public testnet metadata. The active testnet path is native V3 BillV3 gossip, proof bundles, archive segments, owner-addressed wallet sync, conflicts, and transparency-log checks. Historical pre-V3 faucet issuance has been removed from the active tree.

## Parameters

- Network: `testnet`
- TCP node port: `18888`
- Metadata: `testnet/testnet.json`
- DNS seeds: `testnet-seed.international-dollar.com`, `testnet-seed.internetofthebots.com`
- Explicit peers: `testnet-seed.international-dollar.com`, `testnet-seed.internetofthebots.com`, `51.83.199.25`, `108.61.23.82`

## Run

```powershell
$env:IND_NETWORK="testnet"
python node_client.py
```

This repository bundles the active public-testnet native V3 genesis manifest at
`testnet/genesis_manifest.json`. Local clients pin its hash via
`trusted_genesis_manifest_hashes` so manifest-rooted bills must match the active
testnet anchor.

Open/forward TCP `18888` to make the node reachable. Before DNS seeds are live, share one reachable bootstrap IPv4 and have other users set:

```powershell
$env:IND_PEER_PING_SERVERS="<public-node-ipv4>"
```

## Headless VPS Seed

For a permissionless testnet seed/mirror/auditor VPS, render the systemd/nginx
bootstrap files first and review them:

```bash
python tools/testnet_seed_bootstrap.py \
  --public-host <this-vps-ip-or-dns> \
  --canary-ref 1x1782156155 \
  --canary-ref 2x1782156156
```

Run with `--install` on the VPS after `/opt/international-dollar` and its
`.venv` are present. The generated service clears the headless runtime
`kill_node` flag before start, serves static mirrors, monitors with retries,
and returns `404` for `/operator-api/`. It does not make the VPS an
append-capable operator and does not edit `operator_set.testnet.json`.

## V3 Smoke

Run the local V3 readiness smoke:

```powershell
$env:IND_NETWORK="testnet"
python tools/v3_testnet_smoke.py --run-pytest
```

Build a native V3 double-spend drill from a stored BillV3:

```powershell
python tools/v3_double_spend_drill.py --display-id <display-id> --wallet-address <x3-wallet> --dry-run
```

## Readiness Checks

Use `tools/v3_testnet_smoke.py` for readiness checks and
`tools/v3_double_spend_drill.py` for native BillV3 conflict construction.

To check current public seed status without unlocking any wallet:

```powershell
$env:IND_NETWORK="testnet"
python tools/testnet_report.py --ref 1x1 --ref 1x2 --ref 1x3
```

## Current artifacts

- `1x0` is an invalid early test artifact on the VPS. Public serials are one-based; do not use it as success proof.
- `1x1` is an early transfer to an old unrecoverable local wallet. Do not use it as success proof.
- `1x2` is the first clean settled testnet bill. Any old local receipt artifact for this bill is historical and is not used by active sync or settlement.

The clean local recipient wallet metadata is `files/testnet/local_clean_wallet.local.json`, and its passphrase file is `files/testnet/local_clean_wallet_passphrase.local.txt`. Both are local operator artifacts; never commit private keys, passphrases, or decrypted wallet payloads.

## Public metadata readiness

- `/testnet/testnet.json` is the active public testnet metadata file.
- `/transparency/latest.json` should either contain the latest signed transparency root or return an explicit JSON "disabled/not ready" response until the operator is ready.
- `/update` should either return a real signed update manifest or an explicit JSON "disabled/not ready" response. Public clients should keep automatic update checks disabled until the signed update flow is ready.

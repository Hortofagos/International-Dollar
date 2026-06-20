# IND Public Testnet

This folder contains public testnet metadata. The active testnet path is native V3 BillV3 gossip, proof bundles, archive segments, owner-addressed wallet sync, conflicts, and transparency-log checks. Historical lazy-genesis faucet issuance is disabled in the active tree.

## Parameters

- Network: `testnet`
- TCP node port: `18888`
- Metadata: `testnet/testnet.json`

## Run

```powershell
$env:IND_NETWORK="testnet"
$env:IND_TRUSTED_GENESIS_MANIFEST_HASHES="20581461c25568d36446b0c0cbd87f04c35d5d0930965c58058841ce95a04eb8"
python node_client.py
```

Open/forward TCP `18888` to make the node reachable. Before DNS seeds are live, share one reachable bootstrap IPv4 and have other users set:

```powershell
$env:IND_PEER_PING_SERVERS="<public-node-ipv4>"
```

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

## Retired Legacy Smoke

The old faucet-backed `tools/testnet_smoke.py` lifecycle is retired. Use
`tools/v3_testnet_smoke.py` for readiness checks and
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

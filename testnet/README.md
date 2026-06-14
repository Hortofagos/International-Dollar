# IND Public Testnet

This folder contains the public testnet trust anchor. Testnet bills are real IND bearer bills under the normal protocol, but they are only valid on nodes configured for `IND_NETWORK=testnet` and the testnet manifest hash.

## Parameters

- Network: `testnet`
- TCP node port: `18888`
- Manifest: `testnet/genesis_manifest.json`
- Manifest hash: `20581461c25568d36446b0c0cbd87f04c35d5d0930965c58058841ce95a04eb8`
- Faucet owner address: `x1F75rwW6ah8jBByt4dJLsWRyd22aQFKx`

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

## Faucet

The faucet operator keeps private keys in `files/testnet/`, which is ignored by git. To issue one bill to a recipient:

```powershell
$env:IND_NETWORK="testnet"
$env:IND_TRUSTED_GENESIS_MANIFEST_HASHES="20581461c25568d36446b0c0cbd87f04c35d5d0930965c58058841ce95a04eb8"
python tools/testnet_faucet.py `
  --recipient-address <recipient-address> `
  --faucet-private-key-file files/testnet/faucet_private_key.local.json `
  --faucet-public-key-file files/testnet/faucet_public_key.local.json
```

The tool mints a lazy-genesis test bill, transfers it to the recipient, stores it locally, queues the transfer announcement, and broadcasts it to configured peers.

## Operator smoke test

The full testnet smoke command exercises the live receipt lifecycle:

1. unlock the local testnet recipient wallet and refuse to continue if it cannot decrypt;
2. unlock the VPS testnet wallet over SSH and refuse stale wallet metadata;
3. issue one faucet bill to the VPS wallet;
4. make the VPS sign and broadcast the receipt;
5. wait for finality and spend the settled bill from the VPS wallet to the local wallet;
6. make the local wallet sign and broadcast the receipt;
7. wait for finality and check the final remote status.

Run it from the protocol repo:

```powershell
$env:IND_NETWORK="testnet"
$env:IND_TRUSTED_GENESIS_MANIFEST_HASHES="20581461c25568d36446b0c0cbd87f04c35d5d0930965c58058841ce95a04eb8"
python tools/testnet_smoke.py `
  --remote-wallet-address <vps-wallet-address> `
  --remote-wallet-passphrase-file <local-secret-passphrase-file>
```

The faucet private key stays local at `files/testnet/faucet_private_key.local.json`. Do not copy it to the VPS for normal smoke tests. If a one-off recovery ever requires the faucet key on the VPS, upload it only for that issuance and remove it immediately afterward.

To check current public seed status without unlocking any wallet:

```powershell
$env:IND_NETWORK="testnet"
python tools/testnet_report.py --ref 1x0 --ref 1x1 --ref 1x2
```

## Current artifacts

- `1x0` is a conflicted/invalid early test artifact on the VPS. Do not use it as success proof.
- `1x1` is an unreceipted early transfer to an old unrecoverable local wallet. Do not use it as success proof.
- `1x2` is the first clean settled testnet bill. The clean local receipt is stored outside git at `files/testnet/local_clean_receipt_1x2.local.json`.

The clean local recipient wallet metadata is `files/testnet/local_clean_wallet.local.json`, and its passphrase file is `files/testnet/local_clean_wallet_passphrase.local.txt`. Both are local operator artifacts; never commit private keys, passphrases, or decrypted wallet payloads.

## Public metadata readiness

- `/testnet/testnet.json` and `/testnet/genesis_manifest.json` are the active public testnet metadata files.
- `/transparency/latest.json` should either contain the latest signed transparency root or return an explicit JSON "disabled/not ready" response until the operator is ready.
- `/update` should either return a real signed update manifest or an explicit JSON "disabled/not ready" response. Public clients should keep automatic update checks disabled until the signed update flow is ready.

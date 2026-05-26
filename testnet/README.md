# IND Public Testnet

This folder contains the public testnet trust anchor. Testnet tokens are real IND bearer tokens under the normal protocol, but they are only valid on nodes configured for `IND_NETWORK=testnet` and the testnet manifest hash.

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

The faucet operator keeps private keys in `files/testnet/`, which is ignored by git. To issue one token to a recipient:

```powershell
$env:IND_NETWORK="testnet"
$env:IND_TRUSTED_GENESIS_MANIFEST_HASHES="20581461c25568d36446b0c0cbd87f04c35d5d0930965c58058841ce95a04eb8"
python tools/testnet_faucet.py `
  --recipient-address <recipient-address> `
  --faucet-private-key-file files/testnet/faucet_private_key.local.json `
  --faucet-public-key-file files/testnet/faucet_public_key.local.json
```

The tool mints a lazy-genesis test token, transfers it to the recipient, stores it locally, queues the transfer announcement, and broadcasts it to configured peers.

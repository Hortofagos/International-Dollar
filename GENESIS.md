# Genesis And Supply Audit

Status: policy draft.

IND has a fixed maximum supply of 33,000,000,000 bill indexes. The protocol only accepts genesis records with indexes inside that range and positive values, but a serious public launch also needs an auditable genesis process.

The V3 launch path is native BillV3: publish auditable genesis references, checkpoint/proof-bundle evidence, and archive material that can be independently reconstructed. The retired pre-V3 JSON bill path has been removed from the active tree.

## Required For Public Alpha

- Publish the trusted issuer public key or keys.
- Set `IND_TRUSTED_GENESIS_ISSUER_KEYS` on public nodes.
- Publish the signed genesis manifest and set `IND_TRUSTED_GENESIS_MANIFEST_HASHES` on public nodes.
- Publish test vectors for at least one valid and one invalid genesis bill.

## Recommended Supply Commitment

Before launch, generate the intended supply manifest and publish:

- denomination ranges
- starting index and count for each range
- one-based per-denomination serial caps matching the V3 display-id table
- owner address for each range
- deterministic nonce seed for each range
- total bill count
- total face value
- SHA3-256 hash of the unsigned manifest
- issuer public key policy
- signed `issued_at` launch timestamp

Anyone should be able to recompute the manifest hash and verify that no hidden launch supply map is being used.

## Native V3 Manifest Tooling

Use `tools/genesis_manifest_v3.py` to create and verify the native V3 supply
manifest. The tool signs the canonical unsigned manifest with a V3 Ed25519
`indsk3` issuer key and emits an `ind.genesis_manifest.v3` document whose
`manifest_hash` can be pinned by public nodes.

For an air-gapped launch ceremony, copy the standalone bundle from
`tools/offline_genesis_bundle/` to an offline Ubuntu machine and run the
commands in `README_OFFLINE.md`. The standalone script uses only Python's
standard library, so it does not need `pip` or network access.

Retired JSON-bill genesis generators are not part of the active tree. Native V3
genesis/proof-bundle tooling must not produce or accept retired ECDSA JSON bill
objects.

## Public Testnet Genesis

The public testnet metadata is in `testnet/testnet.json`. Any pre-V3 JSON
genesis metadata is historical only and is not an active V3 issuance path.

- Network: `testnet`
- Node port: TCP `18888`
- Metadata: `testnet/testnet.json`

Public testnet nodes should set:

```bash
IND_NETWORK=testnet
IND_TRUSTED_GENESIS_MANIFEST_HASHES=20581461c25568d36446b0c0cbd87f04c35d5d0930965c58058841ce95a04eb8
```

Use `tools/v3_testnet_smoke.py` for readiness checks and
`tools/v3_double_spend_drill.py` for native BillV3 conflict construction.

## Current Trust Assumption

Public nodes must set `IND_TRUSTED_GENESIS_ISSUER_KEYS`, `IND_TRUSTED_GENESIS_MANIFEST_HASHES`, or both. Pinning the manifest hash is strongest because it locks the exact supply map. Local tests can opt into unsigned-network experimentation with `IND_ALLOW_UNTRUSTED_GENESIS=1`, but that setting should never be used for a public network.

## Launch Rule

No real-value public launch should happen until the genesis set or Merkle commitment is published and independently reproducible.

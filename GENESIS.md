# Genesis And Supply Audit

Status: policy draft.

IND has a fixed maximum supply of 33,000,000,000 token indexes. The protocol only accepts genesis records with indexes inside that range and positive values, but a serious public launch also needs an auditable genesis process.

The preferred launch path is now lazy genesis: publish one signed supply manifest with denomination ranges, then mint individual genesis tokens only when a bill first moves. Users verify a lazy bill by checking the issuer signature, the pinned manifest hash, the bill index inside the signed range, and the deterministic nonce/commitment. This avoids dumping tens of terabytes of pre-generated bills onto the network.

## Required For Public Alpha

- Publish the trusted issuer public key or keys.
- Set `IND_TRUSTED_GENESIS_ISSUER_KEYS` on public nodes.
- Publish the signed genesis manifest and set `IND_TRUSTED_GENESIS_MANIFEST_HASHES` on public nodes.
- Publish test vectors for at least one valid and one invalid genesis token.

## Recommended Supply Commitment

Before launch, generate the intended supply manifest and publish:

- denomination ranges
- starting index and count for each range
- owner address for each range
- deterministic nonce seed for each range
- total token count
- total face value
- deterministic `ind_alignment` metadata carrying the 33/777/8/9 motif
- SHA3-256 hash of the unsigned manifest
- issuer public key policy
- signed `issued_at` launch timestamp

Anyone should be able to recompute the manifest hash and verify that no hidden launch supply map is being used.

`tools/generate_genesis.py` can either create local genesis shards or a lazy manifest. It is safe by default: without `--write` it only estimates the run, and huge materialized writes require `--allow-huge`.

Example dry run:

```bash
python tools/generate_genesis.py --count 33000000000 --owner-address x...x
```

Lazy manifest with denominations:

```bash
python tools/generate_genesis.py --lazy-manifest --write --denominations 1:11000000000,2:11000000000,8:11000000000 --owner-address x...x --issuer-private-key-file issuer_private.json --issuer-public-key-file issuer_public.json
```

Mint one lazy bill from the manifest:

```bash
python tools/mint_lazy_token.py --manifest genesis/manifest.json --index 12345 --output genesis/token_12345.json
```

Small local test set:

```bash
python tools/generate_genesis.py --write --count 100 --owner-address x...x --generate-local-issuer-keypair
```

## Current Trust Assumption

Public nodes must set `IND_TRUSTED_GENESIS_ISSUER_KEYS`, `IND_TRUSTED_GENESIS_MANIFEST_HASHES`, or both. Pinning the manifest hash is strongest because it locks the exact supply map. Local tests can opt into unsigned-network experimentation with `IND_ALLOW_UNTRUSTED_GENESIS=1`, but that setting should never be used for a public network.

## Launch Rule

No real-value public launch should happen until the genesis set or Merkle commitment is published and independently reproducible.

# IND Mainnet Genesis Offline Bundle

This bundle is for an air-gapped Ubuntu machine. It needs only `python3`; it
does not need internet access or Python packages.

## 1. Check Python

```bash
python3 --version
```

## 2. Generate Offline Keys

Generate the issuer key. Keep `issuer_private.local.txt` offline forever.

```bash
python3 genesis_manifest_v3_offline.py keygen --out-dir keys --prefix issuer
```

Generate one launch owner key/address per denomination. This gives `1x`, `2x`,
`5x`, ... `100000x` separate owner wallets instead of one treasury wallet for
the entire supply.

```bash
python3 genesis_manifest_v3_offline.py keygen-denominations --out-dir keys --prefix owner
```

## 3. Create The Mainnet Manifest

Pick the exact Unix launch timestamp first. Then run:

```bash
python3 genesis_manifest_v3_offline.py create-mainnet-denominations \
  --issuer-private-key-file keys/issuer_private.local.txt \
  --owner-addresses-file keys/denomination_owner_addresses.json \
  --issued-at 1800000000 \
  --output genesis_manifest.mainnet.json
```

The command prints the manifest hash. That is the value public nodes should pin
with `IND_TRUSTED_GENESIS_MANIFEST_HASHES`.

## 4. Verify Before Moving Anything

```bash
python3 genesis_manifest_v3_offline.py verify genesis_manifest.mainnet.json \
  --require-full-supply
```

You can derive a sample V3 genesis reference:

```bash
python3 genesis_manifest_v3_offline.py derive-ref genesis_manifest.mainnet.json \
  --value 1 \
  --serial 1
```

## 5. What To Copy Back

Copy back only public artifacts:

- `genesis_manifest.mainnet.json`
- `keys/issuer_public.txt`
- `keys/issuer_address.txt`
- `keys/denomination_owner_addresses.json`
- `keys/denomination_owner_public_keys.json`
- `keys/owner_<denomination>_address.txt`

Do not copy back:

- `keys/issuer_private.local.txt`
- `keys/owner_<denomination>_private.local.txt`

The private files should remain on the air-gapped machine or be moved only by
your offline key ceremony rules.

## Single-Owner Alternative

If you intentionally want one owner wallet for the whole supply, generate one
owner key and use `create-mainnet`:

```bash
python3 genesis_manifest_v3_offline.py keygen --out-dir keys --prefix owner
python3 genesis_manifest_v3_offline.py create-mainnet \
  --issuer-private-key-file keys/issuer_private.local.txt \
  --owner-address-file keys/owner_address.txt \
  --issued-at 1800000000 \
  --output genesis_manifest.mainnet.json
```

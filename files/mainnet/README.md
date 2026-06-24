# IND Mainnet Genesis

This directory contains the public mainnet genesis pointers for the fixed 2026-06-24 release candidate.

- Code tag: `mainnet-genesis-rc-20260624-fixed-transfer`
- Code commit: `27648bd40745757fd9f7e3c597320029a5c66e4b`
- Manifest: `genesis_manifest.mainnet.json`
- Manifest hash: `81a79b2567f5eaf83a92d5f60c0b754106329d3f3cc17f895a575ecf21a39e36`
- Manifest SHA-256: `d4cbceedde012b525731d159157b41c899e5d73135a74b8cdfce27b668c50bba`
- Fixed treasury transfer bundle id: `07018d098c2f97c0bb08c30bf2f47ffb6fb4dc84ba38ce32e2c7e9df61494071`
- Fixed treasury transfer bundle SHA-256: `ee28dbd50e10a3aafd17e05f1d90f024a33384a731b9e66d08e8d0bfbfc4e6c4`
- Treasury recipient address: `x33wYCL7xrCF9aZ5oZxbyXvsNg2sozfFx`
- Treasury transfer timestamp: `2026-06-24T21:07:30Z`

`TRANSFER_SHA256SUMS.txt` includes the hash for the signed treasury transfer bundle, but the 59 MB bundle itself is intentionally not stored in Git history. Private genesis keys, encrypted private backups, passphrase files, local serial ledgers, and offline working bundles must never be committed.

# Changelog

This file records notable changes to International Dollar from this point forward.

Use it to document user-facing changes, protocol changes, security fixes, breaking
changes, migration notes, new features, and important internal updates. Keep entries
clear enough that a developer, auditor, or future maintainer can understand what
changed, why it changed, and whether users or node operators need to take action.

Recommended entry format:

```markdown
## YYYY-MM-DD

### Added
- ...

### Changed
- ...

### Fixed
- ...

### Security
- ...

### Notes
- ...
```

## 2026-06-10

### Changed
- Renamed the desktop "Full operator" wording to "Transparency operator" so the UI matches the actual Merkle receipt-log role.
- Normalized new node runtime config labels from "FULL NODE" to "NODE" while preserving legacy operator settings.
- Documented the simple IND role model: wallet, node, transparency operator, mirror/auditor, and optional archive/index service.
- Added `IND_LOG_WRITE_MIRROR_PROOF_ARCHIVES` so public operators can avoid writing full proof-archive snapshots for every mirrored root.
- Removed the count-based lifetime transfer cap from bill validation; bills remain limited by daily transfer rate and serialized history size.

### Notes
- The reference transparency operator still uses SQLite for local storage. PostgreSQL is a possible future production backend, but the required scale fix is an incremental persistent spend map before switching databases.

## 2026-05-23

### Added
- Added first-class public testnet mode with `IND_NETWORK=testnet`, TCP port `18888`, isolated runtime folders, isolated peer cache, and `ind_gossip_testnet.db`.
- Added the public testnet lazy-genesis manifest, testnet parameter file, and faucet CLI for issuing real IND protocol bills on testnet.
- Added `IND_PEER_PING_SERVERS`, `IND_NODE_PORT`, and `IND_STORE_PATH` environment overrides for bootstrap and deployment.

### Notes
- Testnet IND has no mainnet or real-world value. Nodes validate it through the pinned testnet manifest hash.

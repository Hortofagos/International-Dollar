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

## 2026-05-23

### Added
- Added first-class public testnet mode with `IND_NETWORK=testnet`, TCP port `18888`, isolated runtime folders, isolated peer cache, and `ind_gossip_testnet.db`.
- Added the public testnet lazy-genesis manifest, testnet parameter file, and faucet CLI for issuing real IND protocol tokens on testnet.
- Added `IND_PEER_PING_SERVERS`, `IND_NODE_PORT`, and `IND_STORE_PATH` environment overrides for bootstrap and deployment.

### Notes
- Testnet IND has no mainnet or real-world value. Nodes validate it through the pinned testnet manifest hash.

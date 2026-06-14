# Security Policy

IND is experimental alpha software. Do not use it for real funds or irreversible commerce until the protocol and implementation have been independently reviewed.

## Reporting

Please report security issues privately before publishing details. If no dedicated project security email is available yet, open a GitHub issue requesting a private disclosure channel and include no exploit details in the public issue.

Helpful reports include:

- affected version or commit
- steps to reproduce
- expected impact
- proof-of-concept data, if safe to share privately

## Sensitive Files

Never commit runtime secrets or local state, including:

- wallet files
- private keys
- passphrases
- local databases
- public IP cache
- transaction scratch files
- testnet faucet and issuer private keys under `files/testnet/`

Any key that was previously committed or shared should be treated as compromised and regenerated.

## Mainnet Launch Gate

Mainnet value must remain disabled until these requirements are complete and reviewed:

- a mainnet genesis manifest that is separate from testnet, signed, pinned, and documented
- offline generation and storage for mainnet issuer/genesis keys
- no public mainnet faucet unless an explicit launch decision says otherwise
- at least two independent public seed nodes
- signed release/update manifests or disabled public update checks
- monitoring for node liveness, peer count, disk, nginx, certificate expiry, and failed SSH attempts
- encrypted off-server backups for node data, nginx config, website artifacts, and deployment scripts
- a restore drill proving backups can rebuild a node without copying faucet private keys to it

## Audit Track

Audit in this order before any real-value launch:

- protocol: signature validation, transfer-chain rules, double-spend proof generation, receipt finality, timestamp rules, manifest trust, compact checkpoints, and conflict handling
- wallet: INDW2 encryption, Argon2id parameters, temporary decrypted wallet handling, passphrase UX, in-memory session handling, and recovery behavior
- network: INDN1 transport, peer discovery, DNS seed trust boundaries, peer poisoning, replay resistance, rate limits, and malformed message handling
- deployment: nginx, TLS, Cloudflare, SSH, systemd service users, file permissions, secret placement, logs, and backup restore
- release/update: signed manifests, binary signing, reproducible builds, rollback protection, and `/update` endpoint behavior

## Incident Runbook

For a suspected compromise:

1. Disable affected public endpoints or replace them with a signed maintenance notice.
2. Preserve logs and current databases before rotating or rebuilding.
3. Rotate SSH keys and verify admin sudo access before disabling old access.
4. Rotate testnet wallet/faucet keys if they touched an untrusted host.
5. Rebuild the VPS from a clean image and restore only audited backups.
6. Publish a signed post-incident root/genesis/update status before resuming service.

## Supported Versions

Only the current `main` branch is in scope during alpha.

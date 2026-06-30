# International Dollar (IND)

International Dollar is a fixed-supply digital bearer-bill experiment. IND does not use a blockchain, mining, staking, KYC, or IP-based voting. Bills carry their own cryptographic history, and desktop nodes gossip transfers, proof evidence, transparency roots, and double-spend proofs.

## Core Architecture

IND is designed around a maximum supply of exactly 33,000,000,000 unique bill indexes. At genesis, the issuer publishes a signed native V3 supply manifest. The manifest defines denomination ranges, issuer policy, and the fixed supply map that BillV3 genesis references bind to.

A native V3 genesis reference commits to:

- a bill index inside the fixed supply range
- a manifest hash
- an issuer key identity
- an issued-at timestamp
- proof-bundle and archive evidence for reconstruction

After genesis, no further issuance occurs. A BillV3 can be validated from its payload plus referenced proof material using the V3 implementation in `ind/protocol_v3.py` and the shared helpers in the `ind/` package.

The launch constants define the fixed 33 billion bill supply and current 33-character wallet addresses. Native V3 genesis metadata stays limited to auditable supply-manifest context and does not carry symbolic alignment fields.

Public nodes must pin accepted genesis issuer keys with `IND_TRUSTED_GENESIS_ISSUER_KEYS`, exact supply manifests with `IND_TRUSTED_GENESIS_MANIFEST_HASHES`, or both. If neither is set, genesis validation fails unless `IND_ALLOW_UNTRUSTED_GENESIS=1` is explicitly enabled for local tests.

## Network Roles

IND keeps the public roles intentionally small:

- **Wallet:** holds and spends the user's own bills.
- **Node:** gossips transfers, proof evidence, transparency roots, and conflict proofs; it stores only local knowledge, not every possible bill.
- **Transparency operator:** runs the Merkle transparency log, accepts validated transfer hashes, and publishes signed roots.
- **Mirror/auditor:** republishes or checks signed roots and hash-log archives.
- **Archive/index service:** optional heavy infrastructure for explorers and historical search; ordinary nodes do not need this role.

The old phrase "full operator" should be read as "transparency operator." A normal IND node fully verifies every bill or proof it sees, but it is not expected to store the whole 33 billion bill-index universe.

## Transfer Model

Bills transfer peer to peer with signature chains. When holder A sends bill T to holder B, A appends a signed transfer to T:

```text
BILL_payload + sig(A -> B) + sig(B -> C) + ...
```

Every recipient can verify provenance back to genesis. There is no global ordered ledger.

V3 bills use one active protocol surface. A bill may carry full recent transfer data, or a compact checkpoint plus only the transfers after that checkpoint. The checkpoint commits to the settled bill tip: bill id (`token_id`), genesis hash, sequence, current owner, value, display id, last transfer hash/timestamp, the daily transfer counter needed for the 10/day rule, and the previous checkpoint hash. The checkpoint hash is logged as its own transparency-log leaf.

A compact V3 payment is therefore not "the operator says so." The recipient verifies the genesis, the checkpoint hash, the checkpoint inclusion proof against mirrored signed roots, the spend-map proof for the settled last transfer, and the recent transfer signatures after the checkpoint. The tradeoff is honest and explicit: compact V3 is not fully offline full-history verification of old transfer bodies. It is log-backed, mirror-backed, and archive-auditable. Operators or archive services should keep full transfer archives so deep audits and rebuilds remain possible.

Checkpoint submissions include the source bill as validation input. The operator verifies that source bill, recomputes the checkpoint, and logs only the checkpoint hash. Nodes store history in decomposed form: native genesis references, proof bundles, archive segments, each transfer, compact checkpoints, and compact state/message references for current ownership and recipient inboxes. Nodes can still rebuild a full bearer bill from local or archive storage, but normal wallet sends prefer compact V3 once a valid checkpoint exists. By default, local stores create the first automatic checkpoint after 10 settled transfers, then every 10 settled transfers after the latest checkpoint. A wallet or operator can force "compact now" for a settled bill, and operators can set a high-value threshold for immediate checkpointing. Gossip messages also support a compressed `indz1:` wire format while remaining compatible with plain JSON.

To limit intentional per-bill bloat, the protocol enforces at most 10 transfers per bill per UTC day. Transfer timestamps must be strictly increasing and cannot be more than 300 seconds in the future when verified.

Metadata is capped to keep bills from being used as arbitrary file storage: genesis metadata is limited to 1024 canonical JSON bytes and transfer metadata to 256 canonical JSON bytes.

Genesis records include a signed `issued_at` timestamp. Transfers before the genesis issuance time are invalid, which limits fake backdated histories.

## Transparency Log Layer

IND now defaults to a Merkle-tree transparency log layer for bill validation.
Nodes can submit validated transfer announcements and compact
checkpoint announcements to a public log. The operator validates the
announcement, appends only the latest signed transfer hash or checkpoint hash,
and publishes signed tree roots. Clients can then reject a full bill chain
unless every transfer hash has an inclusion proof, and reject a compact bill
unless its checkpoint hash has an inclusion proof and its settled tip has a
valid spend-map proof.

This uses a Certificate Transparency-style Merkle construction: domain-separated
leaves and interior nodes, append-only roots, inclusion proofs, and consistency
proofs. The reference algorithm identifier is `CT_STYLE_SHA3_256_V3`: CT-style
tree framing with SHA3-256. It is intentionally not called RFC 6962 compliant,
because RFC 6962 uses SHA-256 and real CT tooling should not be expected to
interoperate with IND roots. The intended production shape is the same family
of operated, audited systems as CT and Sigstore Rekor, not a custom consensus
ledger.

Phase 1 is honest about trust: append-capable operators are explicitly listed
in the operator set, clients verify signatures and consistency proofs, and
signed roots must be mirrored to independent locations such as the project
website, a git repo, IPFS, and archive.org. Mainnet now has two append-capable
operators, but mirror and gossip diversity remain load-bearing because a small
operator set is still not blockchain-style consensus.

The reference transparency operator currently stores its append log in a local
SQLite database. That is appropriate for development, desktop experiments, and
early testnet operation. Production-scale operators should first move the
spend-map implementation to an incremental persistent structure, then choose a
stronger backend such as PostgreSQL or RocksDB if the workload requires it. A
SQL server alone does not fix scale if roots and proofs are rebuilt from every
stored spend claim.

Append-capable operators can opt into MariaDB with `IND_LOG_BACKEND=mariadb`
after installing `requirements-operator.txt`. MariaDB is only for the
transparency operator's canonical append log; wallets and ordinary gossip nodes
still use local SQLite. Do not use Redis or NoSQL as canonical operator truth.
For mainnet, migration tooling must treat existing SQLite databases, genesis
manifests, and published hash files as read-only inputs. Copy into MariaDB only
after verification, and never delete or overwrite current mainnet runtime data.

Useful environment switches:

- `IND_SUBMIT_TO_TRANSPARENCY_LOG=0`: local-development escape hatch; default settings submit accepted transfer announcements to `IND_LOG_OPERATOR_URL`
- `IND_REQUIRE_TRANSPARENCY_LOG=0`: local-development escape hatch; default settings require valid inclusion proofs
- `IND_LOG_OPERATOR_URL`: HTTP URL for the operator proof/append API
- `IND_LOG_MIRROR_URLS`: comma-separated HTTP URLs or local mirror directories used for signed historical roots
- `IND_LOG_OPERATOR_PUBLIC_KEY`: expected operator signing key
- `IND_OPERATOR_APPEND_FANOUT`: maximum append-capable operators contacted for one transfer, default `5`
- `IND_OPERATOR_CORE_DOMAINS`: operator URL domains always pinned into the append pool, default `international-dollar.com,internetofthebots.com`
- `IND_OPERATOR_FINALITY_MIN_PROOFS`: distinct append-capable operator proofs required for V3 `strong_local`; `0` means a majority of selected append-capable operators
- `IND_ALLOW_UNTRUSTED_EMBEDDED_ROOTS=1`: dev/test-only escape hatch for compact bills; production compact verification must use a mirrored verifier or pinned operator key
- `IND_LOG_BACKEND=sqlite|mariadb`: operator storage backend; defaults to `sqlite`
- `IND_LOG_MARIADB_PASSWORD_FILE`: path to the MariaDB operator password file; avoid putting DB passwords directly in service files
- `IND_LOG_MIN_MIRRORS`: required count of independent signed-root mirrors, default `2`
- `IND_LOG_UNSAFE_SINGLE_MIRROR=1`: local development escape hatch for one mirror; incompatible with `IND_REQUIRE_TRANSPARENCY_LOG=1`
- `IND_LOG_OBSERVED_ROOTS_DB`: local SQLite store for observed signed roots, default `files/transparency_observed_roots.db`
- `IND_LOG_CONSISTENCY_ANCHOR`: path to a signed-root JSON anchor obtained out-of-band
- `IND_LOG_CONSISTENCY_CHECK_INTERVAL_SECONDS`: background append-only consistency check interval, default `900`
- `IND_LOG_CONSISTENCY_MAX_STALE_SECONDS`: strict-mode maximum age for the last successful consistency check, default `3600`
- `IND_LOG_ROOT_GOSSIP=0`: opt out of transparency root/equivocation gossip; root gossip is on by default
- `IND_LOG_MAX_ROOT_LAG_SECONDS`: maximum accepted delay between transfer timestamp and mirrored root, default `120`
- `IND_LOG_MAX_CURRENT_ROOT_AGE_SECONDS`: maximum wall-clock age for roots used as the current log state, default `300`; strict mode refuses values above `600`
- `IND_LOG_CURRENT_ROOT_FUTURE_SKEW_SECONDS`: allowed future timestamp skew for current roots, default `120`, hard ceiling `300`, and it must be smaller than the current-root age window
- `IND_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS`: post-submission inclusion-proof retry window, default `30`; raise it for slow root signing/mirror propagation, lower it to reject unreachable or dishonest operators faster
- `IND_FIRST_CHECKPOINT_AFTER_TRANSFERS`: first automatic compact checkpoint cadence, default `10`
- `IND_CHECKPOINT_INTERVAL_TRANSFERS`: automatic checkpoint interval after the latest checkpoint, default `10`
- `IND_HIGH_VALUE_CHECKPOINT_THRESHOLD`: bill value at or above which settled payments checkpoint immediately, default `0` meaning disabled
- `IND_LOG_ACCEPT_LEGACY_ALGORITHM_NAMES`: accepts the deprecated legacy tree algorithm identifier `RFC6962_SHA3_256_PYMERKLE_V3` for old roots, default on; set to `0` once no trusted production roots use the old name
- `IND_LOG_WRITE_MIRROR_PROOF_ARCHIVES=0`: skip writing full proof-archive snapshots for every mirrored root; public operators should prefer segmented hash-log exports instead
- `IND_HASH_LOG_ARCHIVE_DIR`: static export directory for the full transfer/checkpoint hash-log archive
- `IND_LOG_OPERATOR_PRIVATE_KEY_FILE` / `IND_LOG_OPERATOR_PUBLIC_KEY_FILE`: operator key files used to sign hash-log archive manifests

Mirror independence is checked by normalized source identity. HTTP sources use
scheme, host, and effective port; directory mirrors use resolved local paths;
custom mirror adapters must provide an `identity_id`. This catches accidental
same-service configs such as one origin with different paths, but it does not
prove real-world independence. It does not catch the same operator behind two
hostnames, CNAME/DNS aliases pointing to one backend, two mirrors on the same
CDN or hosting account, or mirrors controlled by the same organization. Treat
mirror diversity as operationally load-bearing, not just a URL formatting rule.

Clients persist observed signed roots locally and request consistency proofs so
newer roots must extend older roots. The first trusted root is a configured
anchor when `IND_LOG_CONSISTENCY_ANCHOR` is set; otherwise the client falls back
to trust-on-first-use. TOFU is only as trustworthy as the network and mirrors
were during first contact. Production deployments should pin a signed root
anchor obtained out-of-band. A consistency failure blacklists that operator
locally and preserves evidence in the observed-roots database.

Current-root replay protection is separate from historical verification. A
historical root proves that a transfer hash was logged near that transfer's
timestamp; it does not prove the log's current state. Normal validation with a
transparency verifier therefore also fetches the latest mirrored root and
requires it to be fresh relative to the local wall clock. Strict mode caps the
current-root age window at 600 seconds: 60 seconds for the signing interval,
roughly 60-120 seconds for mirror propagation, 120 seconds of allowed clock
skew, plus safety margin. Future-dated roots are accepted only within a small
skew window, never above 300 seconds, and the skew window must be smaller than
the staleness window so future timestamps cannot extend replay life.

Nodes gossip operator-signed roots with
`ind.transparency_root_announcement.v3` and gossip split-view evidence with
`ind.transparency_equivocation_proof.v3`. Peer roots are stored separately from
mirror-fetched roots and do not count toward the mirror quorum. They are used to
detect equivocation: two valid roots from the same operator with the same tree
size but different root hashes, or the same timestamp but different tree state,
are permanent evidence. Equivocation evidence is forwarded ahead of ordinary
gossip, rate-limited, and independently verified before forwarding.

Nodes also gossip `ind.transparency_operator_policy_violation.v3` when a signed
root's spend-map proof contains two transfer bodies for the same spend key. The
affected bill is rejected, the operator is locally blacklisted, and the signed
root plus spend-map proof becomes portable evidence. Incomplete proofs that lack
the conflicting transfer bodies reject the bill but do not blacklist the
operator by themselves.

Operators can also publish the full transfer/checkpoint hash archive as fixed-size JSONL
segments plus a signed `manifest.json`. The manifest embeds the operator-signed
root that the segment prefix must produce, commits to each segment hash, and is
signed by the operator key. Anyone can run:

```bash
python operator_tools/audit_hash_log.py --manifest operator_tools/hash-log-archive/manifest.json --archive-base operator_tools/hash-log-archive --operator-public-key=<operator-public-key>
```

Archive-only verification proves the segment archive cryptographically
corresponds to the embedded signed root. Add `--mirror <mirror>` to confirm that
same signed root was independently published; add `--strict` to require that
mirror cross-check. Full transfer archives remain optional for ordinary wallet
operation but important for rebuilding old full histories and auditing compact
checkpoints back to genesis.

The first reference builds used the misleading algorithm identifier
`RFC6962_SHA3_256_PYMERKLE_V3`. Verifiers still accept it by default so old
test roots and early archives remain readable, but it is deprecated. New signed
roots and archive manifests use `CT_STYLE_SHA3_256_V3`, and unknown algorithm
names fail closed.

Operators can publish signed key-rotation records with
`operator_tools/key_rotation.py`. A scheduled rotation is signed by both the old
and new operator keys, names an `effective_from_tree_size`, and carries an
`overlap_until_timestamp`; clients accept either key during that overlap, then
only the new key for current roots while old roots remain historically
verifiable. Rotation records for one `log_id` must be strictly monotonic in
`effective_from_tree_size`.

Emergency revocation records must reference a previously accepted rotation
record and are signed by the successor key. This is an important limit: if an
operator's only key is stolen before any rotation has established a successor
key, the protocol cannot cleanly recover by itself. Operators should perform an
early scheduled rotation and keep the successor/recovery material offline and
well backed up.

## Wallet Sync and Local Confidence

When B receives a valid bill transfer whose latest owner is B's address, the bill is stored as verified. In local-only mode that verified bill is locally spendable; when settlement quorum is enabled, `verified` means valid but awaiting finality and only `settled` bills are wallet-spendable. Receipts are not active protocol messages and are not broadcast to nodes. Wallets track local sync cursors and known bill sequences, then ask peers for newer owner-addressed BillV3 records instead of replaying the entire wallet.

- If a node already knows one branch, a later sibling transfer from the same bill state is rejected locally.
- `pending` is reserved for actual finality, quorum, or transparency-proof waiting.
- `settled` means the transfer survived the local finality buffer and, when quorum is enabled, a majority of configured append-capable operators prove the same spend-map claim.
- Conflict proofs remain portable evidence, but they do not burn or invalidate an already settled bill. Stale post-settlement conflict proofs may be dropped locally instead of stored forever.

The conflict proof is a cryptographic fact: both signatures are from the same key, reference the same bill state, and spend it to different recipients. No vote is needed.

Merchants can apply stricter local policy before releasing real-world value. The local store exposes `token_confidence(...)` so wallets and merchants can reject unknown, pending, wrong-owner, conflicted, or too-fresh bills and optionally require extra settled age for larger payments. Late conflict proofs are evidence against the signer, not a rule that destroys downstream holders' bills; with operator quorum enabled, final settlement depends on the majority operator spend-map proof for the exact spend key and transfer hash.

## Network Topology

IND nodes are volunteer-operated desktop nodes. Nodes communicate through the TCP gossip service on port `8888` on mainnet and `18888` on public testnet; UDP rendezvous/NAT traversal has been removed. To run a reachable node, open/forward the active TCP port on your router and allow it through the host firewall. IP addresses are discovery hints only. They do not grant voting power.

Nodes bootstrap from three hint sources: local cached peers in `ip_folder`, configured peer servers, and DNS seed hostnames from `dns_seed_hosts` or `IND_DNS_SEED_HOSTS`. Mainnet defaults to DNS seeds `seed.international-dollar.com` and `seed.internetofthebots.com` plus the explicit OVH peer `51.83.199.25`; public testnet defaults to DNS seeds `testnet-seed.international-dollar.com` and `testnet-seed.internetofthebots.com` plus explicit peers `51.83.199.25` and `108.61.23.82`. Publish node A and AAAA records only for hosts that run the active TCP gossip port. DNS results are filtered to globally routable IPv4 or IPv6 addresses and cached as ordinary peer hints, not trusted identities.

Node connections use the `INDN1` encrypted transport: X25519 key agreement with ChaCha20-Poly1305 authenticated encryption. Peer transport keys are pinned on first contact by IP address; development/client nodes refresh the pin on key rotation unless `reject_peer_key_changes` or `IND_REJECT_PEER_KEY_CHANGES=1` enables strict rejection. Bill validity never depends on transport encryption; every bill remains verified from its own signatures.

The reference node uses token-bucket abuse guards with separate gossip, critical-evidence, control, and invalid-message lanes. Limits are enforced at global, subnet, and source-IP levels, and saturated nodes return explicit `rate_limited:<seconds>` backpressure instead of spawning unbounded validation work. `IND_NODE_CAPACITY_PROFILE=auto` uses the higher local `operator` profile when this machine is configured as a transparency operator; peers do not receive special remote privileges for claiming to be operators. Operators can tune the shared implementation with `IND_NODE_*` environment variables from `.env.example`.

Local mainnet node state is stored in `ind_gossip.db`; public testnet state is stored in `ind_gossip_testnet.db`. Runtime files, queued transactions, wallets, peer caches, and transport key pins are also separated under per-network folders when `IND_NETWORK=testnet` is active.

## Public Testnet

The public testnet is the V3 readiness network for native BillV3 gossip, proof bundles, archive segments, conflicts, owner-addressed wallet sync, and transparency-log checks. Retired pre-V3 faucet tooling has been removed; use the V3 testnet smoke and BillV3 drill tools while the native funding flow is being finalized.

Public testnet parameters are recorded in `testnet/testnet.json`:

- Network: `testnet`
- TCP node port: `18888`
- Testnet DNS seeds: `testnet-seed.international-dollar.com`, `testnet-seed.internetofthebots.com`
- Testnet explicit peers: `testnet-seed.international-dollar.com`, `testnet-seed.internetofthebots.com`, `51.83.199.25`, `108.61.23.82`

Run a public testnet node:

```powershell
$env:IND_NETWORK="testnet"
$env:IND_TRUSTED_GENESIS_MANIFEST_HASHES="9d1a9cfeb6ceefa4aa39b702af1f5c6be204ddd5fb2e8dd1df0041a47dd31aa6"
python node_client.py
```

Until DNS seed records are live, give users at least one reachable bootstrap node:

```powershell
$env:IND_PEER_PING_SERVERS="<public-node-ipv4>"
```

Run the desktop wallet on testnet:

```powershell
$env:IND_NETWORK="testnet"
$env:IND_TRUSTED_GENESIS_MANIFEST_HASHES="20581461c25568d36446b0c0cbd87f04c35d5d0930965c58058841ce95a04eb8"
python main.py
```

Run local V3 readiness checks:

```powershell
$env:IND_NETWORK="testnet"
python tools/v3_testnet_smoke.py --run-pytest
```

Build a native V3 double-spend drill from a stored BillV3:

```powershell
python tools/v3_double_spend_drill.py --display-id <display-id> --wallet-address <x3-wallet> --dry-run
```

## Current Implementation Map

- `ind/protocol.py`: shared V3 bill primitives, genesis, compact checkpoints, signature-chain validation, conflict proofs, wire encoding, and protocol constants
- `ind/crypto.py`, `ind/addresses.py`, `ind/genesis.py`, `ind/transfers.py`, `ind/conflicts.py`, `ind/wire.py`: focused import surfaces over the protocol core
- `ind/store.py`: SQLite-backed local bill state, compact checkpoints, finality buffer, local confidence checks, message compaction, and conflict persistence
- `ind/token.py` and `ind_token.py`: public compatibility API for existing scripts and tests
- `ind/transparency_server.py` and `log_server.py`: transparency log operator with transfer/checkpoint append, signed-root, inclusion-proof, consistency-proof, and local root-mirror staging endpoints
- `ind/transparency_client.py` and `log_client.py`: client-side signed-root, inclusion-proof, checkpoint, spend-map, consistency-proof, and mirror-disagreement verification
- `ind/sender_node.py` and `sender_node.py`: wallet-side peer communication, transfer broadcast, owner-addressed bill sync, settled-bill import
- `ind/node_client.py` and `node_client.py`: desktop gossip node, peer discovery, local finality, conflict propagation
- `ind/wallet_services.py`: testable wallet send/claim actions used by the UI
- `ind/desktop.py` and `main.py`: Tkinter wallet integration for sending, receiving, and claiming bearer bills
- `tests/`: focused unit tests for receipt retirement, double-spend proof generation, storage limits, transparency logs, wallet crypto, and abuse controls
- `SPEC.md`: alpha protocol specification
- `THREAT_MODEL.md`: current threat model and open hardening work
- `SECURITY.md`: security policy and private-disclosure guidance
- `GENESIS.md`: fixed-supply audit policy draft
- `tools/v3_testnet_smoke.py`: V3 wallet/store/transparency readiness smoke checks
- `tools/v3_double_spend_drill.py`: native BillV3 conflict-drill construction

## Setup

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the wallet:

```bash
python main.py
```

Run a desktop gossip node:

```bash
python node_client.py
```

Run the public testnet node instead:

```bash
IND_NETWORK=testnet IND_TRUSTED_GENESIS_MANIFEST_HASHES=20581461c25568d36446b0c0cbd87f04c35d5d0930965c58058841ce95a04eb8 python node_client.py
```

Run a local transparency log operator:

```bash
python log_server.py --host 127.0.0.1 --port 8890 --mirror-dir files/transparency_roots
```

Configure a node to submit validated transfers to that operator:

```bash
$env:IND_LOG_OPERATOR_URL="http://127.0.0.1:8890"
$env:IND_SUBMIT_TO_TRANSPARENCY_LOG="1"
python node_client.py
```

Strict clients also need independent mirrors and the operator public key printed by
`log_server.py`:

```bash
$env:IND_LOG_MIRROR_URLS="files/transparency_roots,<published-root-mirror-url>"
$env:IND_LOG_OPERATOR_PUBLIC_KEY="<operator-public-key>"
$env:IND_REQUIRE_TRANSPARENCY_LOG="1"
```

Port used by the node:

- mainnet TCP `8888`
- public testnet TCP `18888`

There is no small UDP node mode anymore. If peers cannot connect to your node, check that the active TCP port is forwarded on your router and allowed by your operating system firewall.

## Open Source Hygiene

Runtime keys, passphrases, local databases, wallet files, peer caches, and generated print/transaction artifacts are intentionally ignored by git. A fresh clone creates local transport keys and runtime files on first run. Never commit real files from `wallet_folder`, `transaction_folder`, `print_folder`, `ip_folder`, or ignored files under `files`.

## Known Open Problems

This implementation removes Proof of IP voting, but it does not magically solve every economic or network problem:

- Initial distribution and fair launch remain unresolved.
- Long network partitions or isolated peers can allow conflicting branches to appear settled until the partition heals.
- Full supply auditability requires publishing the genesis set or an equivalent commitment.
- Phase 1 transparency logging still trusts one operator not to equivocate unless clients compare gossiped/mirrored roots.
- Mirror diversity is security-critical; mirrors controlled by the same operator do not give strong evidence.
- Compact V3 payments require transparency-log evidence and archived history for deep offline audit; they intentionally do not carry every old transfer body in every payment.
- Transparency root gossip does not solve eclipse attacks, it only makes hidden retroactive history detectable once honest roots are seen.
- Free identities make reputation cheap; the direct protocol response to double-spending is rejecting the later locally observed sibling branch.
- New users still need to acquire bills from existing holders after genesis.
- Users must trust the issuer's genesis process unless the complete genesis set and issuer key policy are independently audited.

## Disclaimer

This is experimental software with no warranty. Do not treat pending bills as final until the finality buffer has elapsed, and do not treat the current implementation as production financial infrastructure.

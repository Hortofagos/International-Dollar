# International Dollar (IND)

International Dollar is a fixed-supply digital bearer-token experiment. IND does not use a blockchain, mining, staking, KYC, or IP-based voting. Tokens carry their own cryptographic history, and desktop nodes gossip transfers, receipts, and double-spend proofs.

## Core Architecture

IND is designed around a maximum supply of exactly 33,000,000,000 unique token indexes. At genesis, the issuer can publish a signed supply manifest instead of materializing every bill. The manifest defines denomination ranges and lets bills be minted on demand when they first move.

A materialized or lazy genesis record commits to:

- a token index inside the fixed supply range
- an owner address
- an issuer public key and issuer signature
- a deterministic success commitment checked by the IND verification algorithm

After genesis, no further issuance occurs. A token can be validated offline from its payload by running the IND algorithm exposed through `ind_token.py` and implemented in the `ind/` package. Lazy bills verify against the signed manifest hash, so users do not need a 20+ TB dump of every possible genesis payload.

The launch constants intentionally carry the IND numerology motif: 33 billion fixed supply, 33-character current wallet addresses, a 777 angel-number marker, the 8/8888 money motif already used by the node port, and the 9 / 09.10.2003 birthday motif. New genesis and lazy-genesis metadata include a deterministic `ind_alignment` seal so the motif is committed without changing transfer validation rules.

Public nodes must pin accepted genesis issuer keys with `IND_TRUSTED_GENESIS_ISSUER_KEYS`, exact supply manifests with `IND_TRUSTED_GENESIS_MANIFEST_HASHES`, or both. If neither is set, genesis validation fails unless `IND_ALLOW_UNTRUSTED_GENESIS=1` is explicitly enabled for local tests.

## Transfer Model

Tokens transfer peer to peer with signature chains. When holder A sends token T to holder B, A appends a signed transfer to T:

```text
TOKEN_payload + sig(A -> B) + sig(B -> C) + ...
```

Every recipient can verify the full provenance chain back to genesis. There is no global ordered ledger.

Nodes store this history in decomposed form: genesis once, each lazy manifest once, each transfer once, and compact state/message references for current ownership and recipient inboxes. Nodes can rebuild a full bearer token when a wallet needs to spend it, but the local database no longer stores the same growing history or repeated manifest in every transfer and message row. Gossip messages also support a compressed `indz1:` wire format while remaining backwards-compatible with plain JSON. The bearer token itself still grows linearly with its spend count; the storage fix prevents local quadratic blowups without adding checkpoint trust.

To limit intentional per-bill bloat, the protocol enforces at most 100 transfers per token per UTC day. Transfer timestamps must be strictly increasing and cannot be more than 300 seconds in the future when verified.

Metadata is capped to keep tokens from being used as arbitrary file storage: genesis metadata is limited to 1024 canonical JSON bytes and transfer metadata to 256 canonical JSON bytes.

Genesis records include a signed `issued_at` timestamp. Transfers before the genesis issuance time are invalid, which limits fake backdated histories.

## Transparency Log Layer

IND now has an optional Merkle-tree transparency log layer for stricter bill
validation. Nodes can submit validated transfer announcements to a public log.
The operator validates the announcement, appends only the latest signed
transfer hash, and publishes signed tree roots. Clients can then reject a bill
chain unless every transfer hash has an inclusion proof against a mirrored
historical root near that transfer's timestamp.

This uses a Certificate Transparency-style Merkle construction: domain-separated
leaves and interior nodes, append-only roots, inclusion proofs, and consistency
proofs. The reference algorithm identifier is `CT_STYLE_SHA3_256_V1`: CT-style
tree framing with SHA3-256. It is intentionally not called RFC 6962 compliant,
because RFC 6962 uses SHA-256 and real CT tooling should not be expected to
interoperate with IND roots. The intended production shape is the same family
of operated, audited systems as CT and Sigstore Rekor, not a custom consensus
ledger.

Phase 1 is honest about trust: there is a single operator, clients verify
signatures and consistency proofs, and signed roots must be mirrored to
independent locations such as the project website, a git repo, IPFS, and
archive.org. This prevents retroactive hidden history against those mirrors,
but it does not fully prevent split-view equivocation until clients gossip
roots and multiple independent operators exist.

Useful environment switches:

- `IND_SUBMIT_TO_TRANSPARENCY_LOG=1`: normal nodes submit accepted transfer announcements to `IND_LOG_OPERATOR_URL`
- `IND_REQUIRE_TRANSPARENCY_LOG=1`: validation rejects token histories without valid inclusion proofs
- `IND_LOG_OPERATOR_URL`: HTTP URL for the operator proof/append API
- `IND_LOG_MIRROR_URLS`: comma-separated HTTP URLs or local mirror directories used for signed historical roots
- `IND_LOG_OPERATOR_PUBLIC_KEY`: expected operator signing key
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
- `IND_LOG_ACCEPT_LEGACY_ALGORITHM_NAMES`: accepts the deprecated legacy tree algorithm identifier `RFC6962_SHA3_256_PYMERKLE_V1` for old roots, default on; set to `0` once no trusted production roots use the old name
- `IND_HASH_LOG_ARCHIVE_DIR`: static export directory for the full transfer-hash log archive
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
`ind.transparency_root_announcement.v1` and gossip split-view evidence with
`ind.transparency_equivocation_proof.v1`. Peer roots are stored separately from
mirror-fetched roots and do not count toward the mirror quorum. They are used to
detect equivocation: two valid roots from the same operator with the same tree
size but different root hashes, or the same timestamp but different tree state,
are permanent evidence. Equivocation evidence is forwarded ahead of ordinary
gossip, rate-limited, and independently verified before forwarding.

Operators can also publish the full transfer-hash archive as fixed-size JSONL
segments plus a signed `manifest.json`. The manifest embeds the operator-signed
root that the segment prefix must produce, commits to each segment hash, and is
signed by the operator key. Anyone can run:

```bash
python operator_tools/audit_hash_log.py --manifest operator_tools/hash-log-archive-placeholder/manifest.json --archive-base operator_tools/hash-log-archive-placeholder --operator-public-key=<operator-public-key>
```

Archive-only verification proves the segment archive cryptographically
corresponds to the embedded signed root. Add `--mirror <mirror>` to confirm that
same signed root was independently published; add `--strict` to require that
mirror cross-check.

The first reference builds used the misleading algorithm identifier
`RFC6962_SHA3_256_PYMERKLE_V1`. Verifiers still accept it by default so old
test roots and early archives remain readable, but it is deprecated. New signed
roots and archive manifests use `CT_STYLE_SHA3_256_V1`, and unknown algorithm
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

## Receipt Gossip and Finality

When B receives a token transfer, B signs a receipt announcement and gossips it to peers. Nodes store the announcement locally in SQLite and hold the transfer in a pending state for `60` seconds by default. Operators can raise this with `IND_FINALITY_BUFFER_SECONDS`; the code clamps the minimum to 60 seconds.

- If no conflicting transfer appears during the buffer, the token settles to B.
- If two conflicting transfers from the same owner and same token state appear, any node can build a conflict proof.
- A valid conflict proof permanently invalidates that token locally and is gossiped to peers.

The conflict proof is a cryptographic fact: both signatures are from the same key, reference the same token state, and spend it to different recipients. No vote is needed.

Merchants should wait through the finality buffer before releasing real-world value. The local store exposes `token_confidence(...)` so wallets and merchants can reject unknown, pending, wrong-owner, or conflicted tokens and optionally require extra settled age for larger payments. A later valid conflict proof still invalidates the token, so this is practical settlement over a healthy gossip network rather than a global blockchain-style ordering guarantee.

## Network Topology

IND nodes are volunteer-operated desktop nodes. Nodes communicate through the TCP gossip service on port `8888`; UDP rendezvous/NAT traversal has been removed. To run a reachable node, open/forward TCP port `8888` on your router and allow it through the host firewall. IP addresses are discovery hints only. They do not grant voting power.

Node connections use the `INDN1` encrypted transport: X25519 key agreement with ChaCha20-Poly1305 authenticated encryption. Peer transport keys are pinned on first contact by IP address, so later key changes are rejected instead of silently trusted. Token validity never depends on transport encryption; every bill remains verified from its own signatures.

Local node state is stored in `ind_gossip.db`.

## Current Implementation Map

- `ind/protocol.py`: token genesis, signature-chain validation, receipts, conflict proofs, wire encoding, and protocol constants
- `ind/crypto.py`, `ind/addresses.py`, `ind/genesis.py`, `ind/transfers.py`, `ind/receipts.py`, `ind/conflicts.py`, `ind/wire.py`: focused import surfaces over the protocol core
- `ind/store.py`: SQLite-backed local token state, finality buffer, local confidence checks, message compaction, and conflict persistence
- `ind/token.py` and `ind_token.py`: public compatibility API for existing scripts and tests
- `ind/transparency_server.py` and `log_server.py`: transparency log operator with append, signed-root, inclusion-proof, consistency-proof, and local root-mirror staging endpoints
- `ind/transparency_client.py` and `log_client.py`: client-side signed-root, inclusion-proof, consistency-proof, and mirror-disagreement verification
- `ind/sender_node.py` and `sender_node.py`: wallet-side peer communication, transfer/receipt broadcast, settled-token import
- `ind/node_client.py` and `node_client.py`: desktop gossip node, peer discovery, local finality, conflict propagation
- `ind/wallet_services.py`: testable wallet send/claim actions used by the UI
- `ind/desktop.py` and `main.py`: Tkinter wallet integration for sending, receiving, and claiming token-backed bills
- `tests/`: focused unit tests for receipt finality, double-spend proof generation, storage limits, transparency logs, wallet crypto, and abuse controls
- `SPEC.md`: alpha protocol specification
- `THREAT_MODEL.md`: current threat model and open hardening work
- `SECURITY.md`: security policy and private-disclosure guidance
- `GENESIS.md`: fixed-supply audit policy draft
- `tools/generate_genesis.py`: local genesis shard and commitment generator
- `tools/mint_lazy_token.py`: on-demand lazy-genesis token minter from a signed manifest
- `tools/simulate_partition.py`: local partition/conflict-proof simulation

## Setup

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the wallet:

```bash
python main.py
```

Run a full desktop gossip node:

```bash
python node_client.py
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
$env:IND_LOG_MIRROR_URLS="files/transparency_roots,https://example.invalid/ind/transparency-roots"
$env:IND_LOG_OPERATOR_PUBLIC_KEY="<operator-public-key>"
$env:IND_REQUIRE_TRANSPARENCY_LOG="1"
```

Port used by the node:

- TCP `8888`

There is no small UDP node mode anymore. If peers cannot connect to your node, check that TCP `8888` is forwarded on your router and allowed by your operating system firewall.

## Open Source Hygiene

Runtime keys, passphrases, local databases, wallet files, peer caches, and generated print/transaction artifacts are intentionally ignored by git. A fresh clone creates local transport keys and runtime files on first run. Never commit real files from `wallet_folder`, `transaction_folder`, `print_folder`, `ip_folder`, or ignored files under `files`.

## Known Open Problems

This implementation removes Proof of IP voting, but it does not magically solve every economic or network problem:

- Initial distribution and fair launch remain unresolved.
- Long network partitions or isolated peers can allow conflicting branches to appear settled until the partition heals.
- Full supply auditability requires publishing the genesis set or an equivalent commitment.
- Phase 1 transparency logging still trusts one operator not to equivocate unless clients compare gossiped/mirrored roots.
- Mirror diversity is security-critical; mirrors controlled by the same operator do not give strong evidence.
- Transparency root gossip does not solve eclipse attacks, it only makes hidden retroactive history detectable once honest roots are seen.
- Free identities make reputation cheap; the direct penalty for double-spending is burning the conflicted token.
- New users still need to acquire tokens from existing holders after genesis.
- Users must trust the issuer's genesis process unless the complete genesis set and issuer key policy are independently audited.

## Disclaimer

This is experimental software with no warranty. Do not treat pending tokens as final until the finality buffer has elapsed, and do not treat the current implementation as production financial infrastructure.

# IND Protocol Spec

Status: experimental alpha.

## Goals

IND is a fixed-supply digital bearer-token protocol. Tokens carry their own ownership history. Nodes gossip transfers, receipts, and conflict proofs; they do not vote on ownership.

## Cryptography

- Hash: SHA3-256 over canonical JSON.
- Signature: deterministic ECDSA over secp256k1 with SHA3-256.
- Address: `x1` + 24 base58 payload characters + 6 base58 checksum characters + `x`.
  The payload is derived from SHA3-256(public key text). The checksum is the first
  4 bytes of SHA3-256(`IND-address:<version>:<payload>`) encoded as fixed-width
  base58. The current visible address length is 33 characters. Pre-upgrade
  37-character checked addresses and 30-character base58 addresses are
  legacy-compatible.
- Canonical JSON: sorted keys, compact separators, ASCII output.

## Token

A token is:

```json
{
  "type": "ind.token.v1",
  "version": 1,
  "token_id": "ind1_...",
  "genesis": {},
  "history": []
}
```

The current owner is the owner produced by validating `genesis` and every transfer in `history` in order.

## Genesis

Genesis contains:

- `type`: `ind.genesis.v1`
- `version`: `1`
- `index`: integer in `[0, 33000000000)`
- `value`: positive integer
- `owner_address`
- `issuer_public_key`
- `issued_at`
- `nonce`
- `success_commitment`
- `metadata`
- `signature`

The `token_id` is derived from the unsigned genesis payload. Nodes may pin trusted issuer keys with `IND_TRUSTED_GENESIS_ISSUER_KEYS`.

Genesis metadata must be a JSON object and cannot exceed 1024 canonical JSON bytes.
New genesis payloads include a deterministic `ind_alignment` metadata object that
commits to the 33/777/8/9 launch motif, the 09.10.2003 birthday code, and a
33-character seal.
`issued_at` is signed by the issuer. Transfers before `issued_at` are invalid, which bounds fake backdated histories by the actual genesis time.

### Lazy Genesis Manifest

A public launch does not need to pre-generate every possible bill. Instead, the issuer can publish one signed `ind.genesis_manifest.v1` supply map. The manifest contains denomination ranges:

- `start_index`
- `count`
- `value`
- `owner_address`
- `nonce_seed`

The manifest also commits to `total_token_count`, `total_value`, `issuer_public_key`, and `issued_at`. The manifest hash is SHA3-256 over the unsigned manifest. Public nodes should pin this hash with `IND_TRUSTED_GENESIS_MANIFEST_HASHES`.

A lazy genesis token carries a `manifest_ref` with the signed manifest. Verification checks the manifest signature, trusted manifest hash or issuer key, index coverage, denomination value, genesis owner, deterministic nonce, commitment, and token id. This lets the network support up to 33,000,000,000 possible bill indexes without publishing 33,000,000,000 genesis payloads.

## Transfer

A transfer contains:

- `type`: `ind.transfer.v1`
- `version`: `1`
- `token_id`
- `sequence`: previous sequence + 1
- `previous_hash`: hash of genesis for sequence 1, otherwise hash of the previous transfer
- `sender_address`
- `sender_public_key`
- `recipient_address`
- `timestamp`
- `metadata`
- `signature`

Validation requires the sender public key to match `sender_address`, the sender to be the current owner, the previous hash to match the current tip, and the signature to verify over the unsigned transfer.

Transfer timestamps are part of validation:

- timestamps must be strictly increasing inside one token history
- timestamps cannot be more than 300 seconds in the future when verified
- a token may have at most 100 transfers in the same UTC day

The daily transfer cap limits deliberate per-bill history bloat without setting a hard byte-size cap on valid bearer tokens.

Transfer metadata must be a JSON object and cannot exceed 256 canonical JSON bytes.

## Transparency Log

IND transfer history can be checked against an append-only transparency log so
an old wallet owner cannot fabricate an old-looking transfer chain after the
fact. The log does not decide ownership. Ownership still comes from genesis,
transfer signatures, receipts, and conflict proofs. The log only proves that a
signed transfer hash was publicly committed near the time the transfer claims.

The reference log uses a Certificate Transparency-style Merkle tree: leaves are
domain-separated from interior nodes, every append changes the tree root, and
clients verify inclusion and consistency proofs. The reference tree algorithm is
`CT_STYLE_SHA3_256_V1`, meaning CT-style domain separation with SHA3-256. This
is not RFC 6962 or RFC 9162 compliant, because those standards use SHA-256 and
define details for the public Certificate Transparency ecosystem. IND roots are
therefore not expected to interoperate with ordinary CT tooling. Production
deployments should prefer hardened CT-style or Sigstore Rekor-style operated
logs where possible:

- RFC 6962, used as design precedent rather than an interoperability target: https://www.rfc-editor.org/rfc/rfc6962
- Sigstore Rekor: https://docs.sigstore.dev/logging/overview/

### Log Entries

The log stores only the SHA3-256 transfer hash already committed by the IND
token history. Full token and transfer data remains peer-to-peer. A transfer
announcement submitted by a node is validated, then the operator appends only
the latest transfer hash from that announcement.

Each signed root contains:

- `log_id`: SHA3-256 of the operator public key text
- `tree_size`
- `root_hash`
- `timestamp`
- Merkle and hash algorithm identifiers
- operator public key
- operator signature over the canonical root payload

The reference operator signs roots with the same secp256k1 / SHA3-256 / base85
signature format used elsewhere in IND.

Algorithm identifiers are security-critical metadata and are checked against a
whitelist. New signed roots use `CT_STYLE_SHA3_256_V1`. The legacy identifier
`RFC6962_SHA3_256_PYMERKLE_V1` is accepted only when
`IND_LOG_ACCEPT_LEGACY_ALGORITHM_NAMES` is enabled, which is the current
default for backward compatibility. That legacy name is deprecated because it
claimed an RFC 6962 relationship the construction does not have. Unknown tree
algorithm identifiers must fail closed.

### Operator API

`log_server.py` exposes:

- `POST /v1/append`: accept a validated `ind.transfer_announcement.v1` and append the latest transfer hash
- `GET /v1/root`: latest signed root
- `GET /v1/root-at?timestamp=<seconds>`: first signed root at or after a timestamp
- `GET /v1/proof?entry_hash=<hex>&tree_size=<n>`: inclusion proof for a transfer hash against a tree size
- `GET /v1/consistency?first=<n>&second=<m>`: append-only consistency proof
- `GET /v1/roots`: recent signed roots for mirrors and auditors

Operators should publish a fresh signed root at least every 60 seconds, even
when no new transfers arrived. Roots must be mirrored outside the operator,
for example to the project website, a git repo, IPFS, and archive.org. The
reference server can stage root JSON into one or more local mirror directories;
external publishing to IPFS/archive.org is deployment work because it needs
operator credentials.

### Mirror Independence: Protocol Check vs. Operator Duty

The reference client enforces source separation at configuration time. HTTP
operator and mirror URLs are reduced to their origin: scheme, host, and
effective port. Paths, query strings, fragments, trailing slashes, and default
port spelling do not create independence. Directory mirrors are identified by
their resolved local path. Custom mirror objects must provide an `identity_id`
so the client can count distinct sources.

Strict clients require at least two independent root mirrors by default. A
mirror with the same origin as the proof-serving operator is rejected. Two
mirrors with the same origin, or the same resolved directory path, are rejected.
This prevents accidental configs where the operator and "mirror" are the same
service under different paths.

Origin-based independence is only a protocol-level sanity check. It does not
prove organizational or infrastructure independence. It does not catch:

- The same operator behind two different hostnames.
- CNAME or DNS aliases pointing at the same backend.
- Two origins served by the same CDN account or hosting provider.
- Two mirrors administered by the same person or legal entity.

Operators and users configuring mirrors must verify that the underlying mirror
infrastructure is genuinely independent. Different hostnames are not, by
themselves, enough.

### Consistency Baseline: Protocol Check vs. First Contact Trust

Clients persist observed signed roots in a local SQLite store. The reference
path is `files/transparency_observed_roots.db`, overrideable with
`IND_LOG_OBSERVED_ROOTS_DB`. The store keeps all observed roots, operator
status, and consistency-failure evidence. SQLite is opened with WAL mode and a
busy timeout so a node and a local admin tool can read/write without producing
spurious consistency failures during brief lock contention.

For each newly observed root, the client asks the operator for:

`GET /v1/consistency?first=<old_tree_size>&second=<new_tree_size>`

The proof must show that the new root is an append-only extension of the last
stored root for that `log_id`. A single proof from the last stored root to the
new root is enough after offline gaps; clients do not need proofs through every
intermediate root. Clients also check the latest mirrored roots on startup and
every 15 minutes by default via
`IND_LOG_CONSISTENCY_CHECK_INTERVAL_SECONDS`.

The baseline is hybrid. If `IND_LOG_CONSISTENCY_ANCHOR` points to a signed root
JSON file, that configured anchor is used first. Otherwise the first valid
signed root observed for the `log_id` becomes the local TOFU baseline. TOFU
baseline trust is only as strong as the network and mirrors were during first
contact. If an attacker controls first contact and can supply a valid
operator-signed split-view root, later consistency checks only prove append-only
growth from that poisoned baseline. Production deployments should pin a
configured anchor obtained out-of-band.

If a consistency proof fails, the client preserves both signed roots as
evidence, marks the operator as locally blacklisted, and refuses transparency
verification for that operator. Strict mode also fails closed if no successful
consistency check has completed within
`IND_LOG_CONSISTENCY_MAX_STALE_SECONDS`, default 3600 seconds. If the operator
is merely unreachable, the client marks it unresponsive instead of dishonest and
retries later.

### Current Roots vs. Historical Roots

The verifier treats historical roots and current roots as different evidence.
A historical root answers: "was this transfer hash publicly logged near the
transfer timestamp?" A current root answers: "what state is this log claiming
now?" A signed root from an hour ago may be valid historical evidence, but it is
not valid evidence of the current log state.

Historical transfer verification uses `GET /v1/root-at?timestamp=<seconds>` and
requires the root timestamp to be at or after the transfer timestamp, within
`IND_LOG_MAX_ROOT_LAG_SECONDS` (default 120 seconds). Historical verification
does not require wall-clock freshness.

Normal `verify_token(..., transparency_verifier=...)` validation is current
acceptance, so it verifies historical inclusion proofs and then checks a fresh
latest root from the configured mirrors. A current root must satisfy:

- `root.timestamp >= now - IND_LOG_MAX_CURRENT_ROOT_AGE_SECONDS`
- `root.timestamp <= now + IND_LOG_CURRENT_ROOT_FUTURE_SKEW_SECONDS`
- `tree_size` and `timestamp` must not move backward relative to roots already
  observed locally for that `log_id`

The defaults are 300 seconds for current-root age and 120 seconds for future
skew. Strict mode refuses `IND_LOG_MAX_CURRENT_ROOT_AGE_SECONDS` values above
600 seconds. That ceiling is tied to the expected 60-second root signing
interval, roughly 60-120 seconds of mirror propagation, 120 seconds of allowed
clock skew, and safety margin. It is intentionally not an arbitrary tuning knob
for accepting stale mirrors. Future skew has a hard ceiling of 300 seconds and
must be smaller than the staleness window; otherwise a future-dated root could
extend the replay window.

For verifying historical transfers without requiring current log state, such as
forensic analysis of old bills, call
`verify_token(..., transparency_verifier=verifier, require_current_root=False)`.
This skips wall-clock freshness checks but still enforces inclusion proof
verification against a root from the transfer's era.

### Operator Key Rotation and Revocation

Single-key operators are supported, but production operators should rotate keys.
A rotation record is a signed transition from one operator signing key to a
successor key:

```json
{
  "type": "ind.transparency_operator_key_rotation.v1",
  "version": 1,
  "log_id": "<old-key log id>",
  "old_public_key": "<old operator public key>",
  "new_public_key": "<new operator public key>",
  "new_log_id": "<new-key log id>",
  "tree_algorithm": "CT_STYLE_SHA3_256_V1",
  "signature_algorithm": "ECDSA_SECP256K1_SHA3_256_BASE85",
  "rotation_timestamp": 1700000000,
  "effective_from_tree_size": 100000,
  "overlap_until_timestamp": 1700604800,
  "reason": "scheduled",
  "signature_by_old_key": "<signature>",
  "signature_by_new_key": "<signature>"
}
```

Both signatures are required. The old key authorizes the transition; the new
key proves control of the successor identity. During the overlap window,
clients accept roots signed by either key at or after
`effective_from_tree_size`. After `overlap_until_timestamp`, current roots from
the old key are rejected, while historical roots from before the transition
remain verifiable with the old key.

For any `log_id`, observed rotation records must be strictly monotonic in
`effective_from_tree_size`. A rotation record at or before a previously observed
rotation for the same `log_id` is rejected as replay or rollback.

Emergency revocation uses a separate record:

```json
{
  "type": "ind.transparency_operator_key_revocation.v1",
  "version": 1,
  "log_id": "<old-key log id>",
  "revoked_public_key": "<old operator public key>",
  "successor_public_key": "<new operator public key>",
  "successor_log_id": "<new-key log id>",
  "rotation_record_hash": "<hash of accepted rotation record>",
  "revocation_timestamp": 1700000001,
  "reason": "compromise",
  "signature_by_successor_key": "<signature>"
}
```

A revocation record is binding only if it references a previously accepted
rotation record. Without that rule, a stolen old key could try to create a fake
emergency path. With the rule, an attacker needs both the old compromised key
and the successor key to forge a revocation clients accept.

This does not solve first-rotation compromise. If the operator's only key is
stolen before any rotation has established a successor key, this protocol cannot
cleanly recover without out-of-band governance, mirror/operator statements, or
client updates. Operators should perform a scheduled rotation early to establish
a successor key as a recovery anchor, and should keep recovery material offline
and backed up.

### Root Gossip and Equivocation Evidence

Clients gossip signed roots so split views can be detected across peers. Root
gossip is enabled by default and can be disabled with `IND_LOG_ROOT_GOSSIP=0`.

Root announcement message:

```json
{
  "type": "ind.transparency_root_announcement.v1",
  "version": 1,
  "root": { "... full ind.transparency_root.v1 signed root ..." },
  "observed_at": 1700000000
}
```

Peer-received roots are stored separately from locally fetched mirror roots.
They do not count toward `IND_LOG_MIN_MIRRORS`; they are a split-view detection
signal, not mirror-independence evidence. Valid roots from unknown operators may
be stored for future evidence, but unknown log ids are capped tightly and do not
affect strict validation for the configured operator.

Equivocation is detected whenever any stored roots for the same `log_id`
collide:

- same `tree_size`, different `root_hash`
- same `timestamp`, different `tree_size` or `root_hash`

There is no honest case where one append-only log has two different root hashes
for the same tree size. If equivocation is detected, the client stores both
signed roots forever, blacklists the operator locally, and gossips this proof:

```json
{
  "type": "ind.transparency_equivocation_proof.v1",
  "version": 1,
  "log_id": "<log_id>",
  "collision_type": "same_tree_size",
  "root_a": { "... signed root ..." },
  "root_b": { "... signed root ..." },
  "detected_at": 1700000000
}
```

Receiving peers verify both root signatures, verify both roots have the same
operator public key, verify `log_id_from_public_key(operator_public_key)` equals
the claimed `log_id`, and verify the claimed collision before storing or
forwarding evidence. The two signed roots are the proof; the reporter does not
need to be trusted.

Equivocation evidence is high priority: nodes put it at the front of the
outbound gossip queue, rebroadcast persisted evidence on startup, and send it
before ordinary root/transfer gossip subject to rate limits. Evidence-bound
roots are never pruned, even when peer-root storage caps are enforced.

### Client Verification

When strict transparency verification is enabled, a client validating a bill:

1. Verifies the normal IND signature chain.
2. For each transfer, computes the transfer hash from the peer-to-peer token.
3. Fetches signed historical roots for the transfer timestamp from at least two independent mirrors, not from the operator that serves the proof.
4. Fetches an inclusion proof from the operator for that transfer hash and mirrored tree size.
5. Recomputes the Merkle root with the proof and rejects the bill if it does not match the mirrored signed root.
6. Periodically asks the operator for consistency proofs between previously observed roots and newer roots.

The root timestamp must be at or shortly after the transfer timestamp. The
reference verifier defaults to a 120-second maximum lag because roots are
intended to be published every 60 seconds.

Nodes that submit a transfer to the operator must not trust the append response
alone. The response has to identify the appended `entry_hash`, zero-based
`leaf_index`, and current `tree_size`; duplicates are verified the same way as
new appends. The node retries inclusion-proof verification against a mirrored
signed root until `IND_LOG_SUBMISSION_VERIFY_TIMEOUT_SECONDS` expires, default
30 seconds. Longer timeouts tolerate slower root signing and mirror propagation;
shorter timeouts reject unreachable or dishonest operators faster.

### Hash Log Archive Manifests

Operators may publish the full transfer-hash log as fixed-size JSONL segment
files for independent auditors. Segments contain only:

```json
{"leaf_index":0,"entry_hash":"<transfer hash>","submitted_at":1700000000}
```

The archive is verifiable only when accompanied by a signed manifest. The
manifest represents one complete prefix of the log: leaves `0` through
`signed_root.tree_size - 1`. It is not a partial-progress marker.

Manifest fields:

- `type`: `ind.transparency_hash_log_archive_manifest.v1`
- `version`: `1`
- `archive_id`
- `log_id`
- `operator_public_key`
- `tree_algorithm`
- `hash_algorithm`: Merkle-tree hash algorithm
- `segment_hash_algorithm`: hash algorithm for exact segment file bytes
- `signature_algorithm`
- `signed_root`: full embedded `ind.transparency_root.v1`
- `signed_root_tree_size`
- `signed_root_hash`
- `signed_root_timestamp`
- `archived_entry_count`
- `segments`: ordered segment descriptors
- `manifest_timestamp`
- `signature`

Each segment descriptor contains `path`, `first_leaf_index`,
`last_leaf_index`, `entry_count`, `segment_hash`, and `byte_length`.
`segment_hash` is computed over the exact bytes of the segment file using
`segment_hash_algorithm`; this is a file-integrity hash, not the Merkle tree
hash. `hash_algorithm` and `segment_hash_algorithm` are separate fields because
they protect different operations and future archives may migrate them
independently.

The manifest top-level `signed_root_*` fields must equal the corresponding
fields in the embedded `signed_root` object. A mismatch indicates a malformed or
malicious manifest and must be rejected. The manifest signature covers the
canonical JSON payload with `signature` removed, using the same operator key as
signed roots in this version.

Auditors verify:

1. Manifest signature against `operator_public_key`.
2. Embedded signed-root signature.
3. Top-level `signed_root_*` fields match the embedded root.
4. Every segment hash and byte length matches the manifest.
5. Segment leaf indices are contiguous from `0` to `tree_size - 1`.
6. Reconstructed Merkle root from segment entries equals `signed_root_hash`.
7. If a mirror is provided, the same signed root is independently present in
   that mirror.

Archive-only verification proves "this archive cryptographically corresponds to
this signed root." Mirror cross-check additionally proves "this signed root was
actually published to the world, not just signed in private." The standalone
auditor tool supports both modes:

```bash
python operator_tools/audit_hash_log.py --manifest <manifest> --archive-base <archive-dir-or-url> --operator-public-key=<key>
python operator_tools/audit_hash_log.py --strict --manifest <manifest> --archive-base <archive-dir-or-url> --operator-public-key=<key> --mirror <mirror>
```

Old unsigned archive manifests are unverifiable and must not be treated as audit
evidence.

### Bootstrap Phases

Phase 1 is the current reference deployment: one operator. Clients verify root
signatures, inclusion proofs, and consistency proofs. Signed roots are mirrored
to independent locations. This prevents ordinary retroactive backfilling
against mirrored historical roots, but a single operator can still present
split views unless clients gossip roots.

Phase 2 adds 2-3 independent operators. Clients require inclusion proofs from
at least two operators and gossip observed roots between peers.

Phase 3 adds five or more operators and a quorum policy. Disagreement triggers
alerts and investigation of the cryptographic evidence. It is not majority
voting over ownership.

### Equivocation Evidence

Clients gossip observed signed roots. If two clients see two valid signed roots
from the same operator for the same timestamp but with different tree sizes or
root hashes, that is permanent cryptographic evidence of operator dishonesty.
The operator should be blacklisted and the signed conflicting roots preserved.

## Receipt

A receipt confirms that the current recipient saw the transfer:

- `type`: `ind.receipt.v1`
- `version`: `1`
- `token_id`
- `transfer_hash`
- `sequence`
- `recipient_address`
- `recipient_public_key`
- `received_at`
- `signature`

Receipts are attached to `ind.receipt_announcement.v1` messages. The recipient key must match the token tip owner.

Receipt timestamps cannot predate the transfer tip and cannot be more than 300 seconds in the future when verified.

## Conflict Proof

A conflict proof contains two valid token branches with different last transfer hashes but the same:

- `token_id`
- `sequence`
- `previous_hash`
- `sender_address`
- `sender_public_key`

This proves the owner signed two spends from the same token state. A valid conflict proof invalidates the token locally and should be gossiped.

## Gossip Messages

Supported message types:

- `ind.transfer_announcement.v1`
- `ind.receipt_announcement.v1`
- `ind.conflict_proof.v1`
- `ind.transparency_root_announcement.v1`
- `ind.transparency_equivocation_proof.v1`

Plain canonical JSON is accepted. Nodes may also send compressed wire messages with the prefix `indz1:`. The payload is zlib-compressed canonical JSON encoded with base85.

Compressed wire payloads are bounded by transport safety limits:

- compressed payload default maximum: 16 MiB
- decompressed payload default maximum: 64 MiB

Operators can tune these with `IND_MAX_WIRE_COMPRESSED_BYTES` and `IND_MAX_WIRE_DECOMPRESSED_BYTES`. Raising these limits allows older/heavier bills but increases DoS exposure.

## Encrypted Node Transport

The reference TCP node prefers the `INDN1` encrypted transport for peer requests. `INDN1` uses an ephemeral X25519 exchange against the node's long-term X25519 transport key, derives directional session keys with HKDF-SHA256, and encrypts framed request/response payloads with ChaCha20-Poly1305. The handshake adds one client ephemeral public key, one server static public key, and one server ephemeral public key; encrypted frames add a four-byte length prefix and a 16-byte AEAD tag.

Client nodes pin first-seen server transport keys by peer IP address. A later key change is rejected locally. This is trust-on-first-use rather than a global identity system, and it does not hide the fact that a host is speaking IND on TCP `8888`.

## Local Settlement

Receipt announcements enter `pending` status. The default finality buffer is 60 seconds and cannot be configured below 60 seconds. If no conflict appears during that window, the token becomes `settled` locally. A later valid conflict proof still invalidates the token.

Local stores expose a confidence decision for a token id:

- `unknown`: the node has no token record
- `conflict`: a valid conflict proof is known
- `wrong_owner`: the token tip owner does not match the expected recipient
- `unreceipted` or `pending`: the token is valid but not locally settled
- `settled_fresh`: the token is settled but below the caller's requested extra age
- `strong_local`: the token is settled locally with no known conflict

Wallets and merchants should treat only `strong_local` as accepted for ordinary payments.

## Storage Model

Nodes store:

- genesis once per token
- signed lazy genesis manifests once per manifest hash
- each transfer once by transfer hash
- compact state references for token tips
- compact message references for recipient inboxes

Nodes rebuild the full bearer token when a wallet needs to spend or export it. This prevents repeated local storage of the same growing history without adding checkpoint trust.

## Network Abuse Controls

The reference TCP node applies per-peer rate limits:

- 60 connections per peer per 60 seconds
- 30 gossip messages per peer per 60 seconds

Peer discovery entries are accepted only if they are globally routable IPv4 addresses. Loopback, private, multicast, unspecified, and reserved addresses are rejected. In-memory peer tracking and gossip deduplication are bounded so long-running nodes cannot be forced to keep unbounded unique peer/message records. These controls reduce spam and path traversal risk, but they are not a full peer reputation system.

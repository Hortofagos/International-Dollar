# IND V3 Protocol Spec

Status: experimental alpha.

IND is a fixed-supply digital bearer-bill protocol. Bills carry their own
ownership history, and nodes gossip transfers, conflict proofs, proof bundles,
archive segments, and transparency-root evidence. Nodes do not vote on
ownership.

## Roles

- **Wallet:** stores and spends bills owned by one user.
- **Node:** validates and relays V3 gossip it sees.
- **Transparency operator:** accepts validated transfer/checkpoint leaves and
  signs append-only Merkle roots.
- **Mirror/auditor:** republishes signed roots and detects equivocation.
- **Archive/index service:** keeps historical transfer and proof material for
  deep audit and recovery.

## Cryptography

- Hash: SHA3-256 over canonical JSON or V3 binary envelopes.
- V3 signing keys: Ed25519 `indsk3` / `indpk3` for native V3 bills.
- Shared compatibility utilities may still expose ECDSA helpers for existing
  operator/tool code, but active wire objects use V3 type strings, V3 versions,
  and V3 domain separators.
- Canonical JSON is sorted-key, compact-separator, ASCII JSON.
- V3 binary bill and transfer envelopes use the `IND3BILL` and `IND3XFER`
  magic values and include version, network id, and canonical payload bytes.

## Bill Objects

The active bill object is `ind.bill.v3` with `version: 3`. A V3 bill contains:

- `network_id`
- `token_id`
- `value`
- `genesis_ref`
- `checkpoint_core`
- `proof_bundle_ref`
- `recent_transfers`

The current owner is the owner produced by validating the checkpoint core,
the referenced proof bundle, and every recent transfer in order. Compact V3
payments are not operator-declared ownership: recipients verify the checkpoint
hash, inclusion proof, spend-map proof, mirrored signed root, and recent
transfer signatures.

## Genesis

Native genesis material is declared as `ind.genesis_manifest.v3`.
Genesis references use `ind.genesis_ref.v3` and bind:

- `network_id`
- `genesis_hash`
- `manifest_hash`
- `issuer_key_id`
- `issue_index`
- `issued_at`

V3 deployments should pin the expected manifest hash and issuer key policy.
Old manifest formats are not accepted as active runtime inputs.

Display IDs are canonical `valuexserial` strings. Serial numbers are one-based
and scoped per denomination, so `1x1` and `2x1` may both exist. Runtime
validation rejects serial `0` and any serial above these denomination caps:

| Denomination | Max serial |
|---:|---:|
| `1x` | `6,000,000,000` |
| `2x` | `5,500,000,000` |
| `5x` | `5,000,000,000` |
| `10x` | `4,500,000,000` |
| `20x` | `4,000,000,000` |
| `50x` | `2,000,000,000` |
| `100x` | `1,500,000,000` |
| `200x` | `1,000,000,000` |
| `500x` | `800,000,000` |
| `1000x` | `700,000,000` |
| `2000x` | `600,000,000` |
| `5000x` | `500,000,000` |
| `10000x` | `400,000,000` |
| `20000x` | `250,000,000` |
| `50000x` | `150,000,000` |
| `100000x` | `100,000,000` |

## Transparency

The active operator API is `/v3/*`.

- `POST /v3/append`
- `GET /v3/root`
- `GET /v3/root-at`
- `GET /v3/roots`
- `GET /v3/entries`
- `GET /v3/proof`
- `GET /v3/spend-proof`
- `GET /v3/proof-archive`
- `GET /v3/consistency`
- `GET /v3/status`

Signed roots, inclusion proofs, consistency proofs, spend-map proofs, root
announcements, equivocation proofs, policy violations, key rotations, recovery
witnesses, archive manifests, and update manifests all use V3 type strings,
version `3`, and V3 signature/hash domains.

## Gossip

Active bill gossip types:

- `ind.transfer_announcement.v3`
- `ind.proof_bundle_announcement.v3`
- `ind.archive_segment_announcement.v3`
- `ind.conflict_proof.v3`
- `ind.transparency_root_announcement.v3`
- `ind.transparency_equivocation_proof.v3`
- `ind.transparency_operator_policy_violation.v3`

Messages may be sent as canonical JSON or packed with the `indz1:` compressed
wire wrapper. The wrapper is a transport encoding, not a protocol generation.

`ind.receipt_announcement.v3` is retired. Receipt signatures do not create
ownership, are not stored by nodes, and are rejected as active gossip. Wallet
sync uses local cursors plus known bill sequences to request newer
owner-addressed BillV3 records from peers.

## Limits

- At most 10 transfers per bill per UTC day.
- Transfer timestamps must be strictly increasing and cannot be more than 300
  seconds in the future.
- Genesis metadata is capped at 1024 canonical JSON bytes.
- Transfer metadata is capped at 256 canonical JSON bytes.
- Wire compression and JSON nesting limits are enforced before validation.

## Storage And Compatibility

V3 is the only active runtime protocol. Existing stores, wallets, manifests, and
client integrations must be regenerated or explicitly upgraded outside runtime.
The runtime does not provide active old-protocol parsing, endpoints, or aliases.

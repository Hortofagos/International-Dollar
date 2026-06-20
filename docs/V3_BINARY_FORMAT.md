# IND V3 Binary Format

This document defines the launch-track V3 byte rules implemented by the native
V3 modules. Legacy JSON objects and the old JSON-in-binary-envelope form are not
valid V3 binary objects.

## Primitive Encoding

All integers are unsigned, minimal LEB128 varints. Values are bounded to
`0..2^63-1` unless an object section defines a smaller maximum.

Rules:

- `00` encodes zero.
- Non-minimal encodings are invalid, including `80 00`.
- Unterminated varints are invalid.
- Values above `2^63-1` are invalid.

Bounded bytes are encoded as:

```text
uvarint byte_length
byte_length raw bytes
```

The default byte-array maximum is 64 KiB. Object-specific fields may use a
smaller limit.

Bounded ASCII strings are `bounded-bytes` whose payload must decode as ASCII.
Addresses, public display ids, log ids, algorithms, and source formats use
bounded ASCII.

Hashes are raw 32-byte SHA3-256 digests. Ed25519 public keys are raw 32-byte
keys. Ed25519 signatures are raw 64-byte signatures.

Nullable hashes are encoded as:

```text
00                  null
01 <32 raw bytes>   present hash
```

Any other marker is invalid.

## Object Envelope

Every standalone V3 binary object uses a fixed envelope:

```text
magic                         fixed bytes
version                       uvarint, exactly 3
network_id                    uvarint
body                          fixed-order fields for the object type
```

The decoder must consume the entire byte string. Unknown magic, unsupported
versions, malformed fields, non-minimal varints, and trailing bytes are invalid.
There is no TLV section map and no canonical JSON object inside the envelope.

Initial magic values:

```text
IND3BILL    BillV3
IND3XFER    TransferV3
IND3GENR    GenesisRefV3
IND3CPNT    CheckpointCoreV3
IND3CFLP    ConflictProofV3
IND3PBRF    ProofBundleRefV3
IND3PBDL    ProofBundleV3
IND3SPMP    CompressedSparseSpendProofV3
IND3ARCH    ArchiveSegmentV3
```

`IND3RCPT` / `ReceiptV3` is retired and reserved. Active nodes and wallets do
not encode, decode, store, or relay receipts.

When an object body embeds another V3 object, the embedded value is a body unless
the layout explicitly says it is a bounded full envelope.

## Signing Preimage

V3 signatures use Ed25519 over this exact binary preimage:

```text
"IND-SIGNATURE-V3\0"
uvarint network_id
bounded-ascii object_type
uvarint object_version
uvarint signature_algorithm
bounded-ascii domain
bounded-bytes canonical_object_without_signature
```

Initial `signature_algorithm`:

```text
1 = IND_V3_ED25519_PURE_CONTEXT
```

`TransferV3` signing preimages use the full object envelope with the signature
field omitted. No JSON object is signed directly in V3.

## Core Bodies

`GenesisRefV3` body:

```text
genesis_hash                  hash
manifest_hash                 nullable hash
issuer_key_id                 nullable hash
issue_index                   uvarint
issued_at                     uvarint
```

`BaseStateV3` body, used inside archive segments:

```text
sequence                      uvarint
owner_address                 bounded ASCII, max 128 bytes
last_transfer_hash            hash
last_transfer_timestamp       uvarint
last_transfer_day             uvarint
transfers_in_last_day         uvarint
display_id                    bounded ASCII, max 64 bytes
value                         uvarint
```

`CheckpointCoreV3` body:

```text
token_id                      hash
genesis_hash                  hash
sequence                      uvarint
owner_address                 bounded ASCII, max 128 bytes
value                         uvarint
display_id                    bounded ASCII, max 64 bytes
display_id_hash               hash
last_transfer_hash            hash
last_transfer_timestamp       uvarint
last_transfer_day             uvarint
transfers_in_last_day         uvarint
previous_checkpoint_hash      nullable hash
checkpoint_hash               hash
```

`checkpoint_core_hash()` hashes a full `CheckpointCoreV3` envelope with the
`checkpoint_hash` field encoded as 32 zero bytes.

## Bill And Transfer

`TransferV3` body:

```text
token_id                      hash
sequence                      uvarint
previous_hash                 hash
sender_address                bounded ASCII, max 128 bytes
sender_public_key             32 bytes
recipient_address             bounded ASCII, max 128 bytes
timestamp                     uvarint
metadata                      bounded canonical JSON bytes
signature_algorithm           uvarint
signature                     64 bytes, omitted for signing preimage
```

`BillV3` body:

```text
token_id                      hash
value                         uvarint
genesis_ref                   GenesisRefV3 body
checkpoint_core               CheckpointCoreV3 body
proof_bundle_ref              ProofBundleRefV3 body
recent_transfer_count         uvarint
recent_transfers              TransferV3 bodies
```

`bill_hash()` and `transfer_hash()` hash the complete envelopes. Transfer
metadata is intentionally retained as a bounded canonical JSON subdocument so
wallet-facing metadata stays extensible while the surrounding protocol is
field-level binary.

## Conflicts

`ConflictProofV3` body:

```text
token_id                      hash
previous_hash                 hash
sequence                      uvarint
sender_address                bounded ASCII, max 128 bytes
spend_key                     hash
transfer_hash_a               hash
transfer_hash_b               hash
transfer_a                    TransferV3 body
transfer_b                    TransferV3 body
detected_at                   uvarint
proof_hash                    hash
```

`conflict_proof_hash()` hashes a full `ConflictProofV3` envelope with the
`proof_hash` field encoded as 32 zero bytes.

## Proof Bundles

`ProofBundleRefV3` body:

```text
log_id                        bounded ASCII, max 128 bytes
signed_root_hash              hash
tree_size                     uvarint
proof_bundle_algorithm        uvarint
proof_bundle_hash             hash
```

`CompressedSparseSpendProofV3` body:

```text
algorithm                     bounded ASCII, max 128 bytes
spend_key                     hash
tree_size                     uvarint
map_size                      uvarint
spend_claims                  bounded canonical JSON bytes
non_empty_sibling_count       uvarint
non_empty_siblings            repeated sibling bodies
```

Each non-empty sibling body is:

```text
depth                         uvarint
side                          uvarint, 0 = left, 1 = right
hash                          hash
```

`ProofBundleArchiveSegmentSourceV3` body:

```text
source_format                 bounded ASCII, max 128 bytes
archive_segment_hash          hash
source_checkpoint_hash        hash
previous_proof_bundle_hash    nullable hash
embedded_archive_marker       00 for absent, 01 for present
archive_segment               bounded full ArchiveSegmentV3 envelope, only when present
```

`ProofBundleV3` body:

```text
algorithm                     uvarint
log_id                        bounded ASCII, max 128 bytes
checkpoint_hash               hash
signed_root                   bounded canonical JSON bytes
checkpoint_inclusion_proof    bounded canonical JSON bytes
compressed_spend_map_proof    bounded full CompressedSparseSpendProofV3 envelope
source_evidence               ProofBundleArchiveSegmentSourceV3 body
created_at                    uvarint
proof_bundle_hash             hash
```

Transparency log roots and inclusion proofs remain bounded canonical JSON fields
inside the field-level proof bundle. This preserves the existing transparency
root and proof JSON formats while making the V3 object itself binary.

`proof_bundle_hash()` hashes a full `ProofBundleV3` envelope with the
`proof_bundle_hash` field encoded as 32 zero bytes.

## Archive Segments

`ArchiveSegmentV3` body:

```text
token_id                      hash
value                         uvarint
display_id                    bounded ASCII, max 64 bytes
genesis_ref                   GenesisRefV3 body
base_state                    BaseStateV3 body
start_sequence                uvarint
end_sequence                  uvarint
previous_segment_hash         nullable hash
previous_checkpoint_hash      nullable hash
checkpoint_hash               hash
transfer_count                uvarint
transfers                     TransferV3 bodies
segment_hash                  hash
```

`archive_segment_hash()` hashes a full `ArchiveSegmentV3` envelope with the
`segment_hash` field encoded as 32 zero bytes.

## V3 Gossip Payloads

Payload-bearing V3 gossip announcements carry canonical binary V3 objects as
base85 strings:

```text
payload_encoding              "indb3-base85"
payload field prefix          "indb3:"
```

The decoded bytes must parse as the expected V3 binary object. Receivers reject
malformed base85, wrong object magic, wrong network id, malformed object fields,
and trailing bytes before storing or relaying the message.

`TransferAnnouncementV3` carries:

```text
type                          "ind.transfer_announcement.v3"
version                       3
network_id                    uvarint-compatible integer in JSON envelope
payload_encoding              "indb3-base85"
bill                          full BillV3 envelope
proof_bundle                  null or full ProofBundleV3 envelope
archive_segments              list of full ArchiveSegmentV3 envelopes
announced_at                  integer timestamp
```

`CheckpointAnnouncementV3` carries:

```text
type                          "ind.checkpoint_announcement.v3"
version                       3
network_id                    uvarint-compatible integer in JSON envelope
payload_encoding              "indb3-base85"
checkpoint_core               full CheckpointCoreV3 envelope
archive_segments              non-empty list of full ArchiveSegmentV3 envelopes
announced_at                  integer timestamp
```

Checkpoint append verifies every included archive segment can be decoded, builds
a resolver from those segments, verifies the first segment derives the announced
checkpoint core, verifies the checkpoint hash, and appends a transparency entry
with `entry_kind = "checkpoint"` and the checkpoint core as the entry.

`ProofBundleAnnouncementV3` and `ArchiveSegmentAnnouncementV3` carry one full
`ProofBundleV3` or `ArchiveSegmentV3` envelope respectively.
`ReceiptAnnouncementV3` is retired and rejected as active gossip.

## Fail-Closed Requirements

Parsers must reject:

- Legacy JSON supplied as V3 binary.
- The old JSON-in-binary-envelope form.
- Unknown versions or algorithms.
- Non-minimal varints.
- Overlong byte arrays or ASCII fields.
- Invalid nullable-hash markers.
- Invalid hash, key, or signature lengths.
- Object envelopes with wrong magic or wrong network id for their context.
- Trailing bytes.

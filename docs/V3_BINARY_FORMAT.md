# IND V3 Binary Format

This document defines the launch-track V3 byte rules used by the new V3 modules.
V1/V2 JSON objects are not valid V3 binary objects.

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

Nullable hashes are encoded as:

```text
00                  null
01 <32 raw bytes>   present hash
```

Any other marker is invalid.

## Object Envelope

Every V3 object starts with fixed magic bytes, then version `3`, then
`network_id`.

Initial magic values:

```text
IND3BILL    BillV3
IND3XFER    TransferV3
IND3GENR    GenesisRefV3
IND3CPNT    CheckpointCoreV3
IND3PBRF    ProofBundleRefV3
IND3PBDL    ProofBundleV3
IND3SPMP    CompressedSparseSpendProofV3
IND3ARCH    ArchiveSegmentV3
```

Unknown magic, unknown version, trailing bytes, duplicate sections, and
out-of-order sections are invalid.

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

The signed object bytes must be the canonical object encoding without its
signature field. No JSON object is signed directly in V3.

## BillV3 Layout

```text
magic                         "IND3BILL"
version                       uvarint, exactly 3
network_id                    uvarint
token_id                      32 bytes
value                         uvarint
genesis_ref                   GenesisRefV3 body
checkpoint_core               CheckpointCoreV3 body
proof_bundle_ref              ProofBundleRefV3 body
recent_transfer_count          uvarint
recent_transfers              TransferV3 bodies
```

`CheckpointCoreV3` binds `token_id` and `genesis_hash` in addition to current
owner, value, sequence, last-transfer hash/timestamp/day counters, previous
checkpoint hash, and checkpoint hash.

`TransferV3` binds `network_id`, `token_id`, sequence, previous hash, sender
x3 address, sender `indpk3:` key, recipient x3 address, timestamp, metadata,
signature algorithm, and Ed25519 signature.

`ArchiveSegmentV3` is content-addressed by `segment_hash` and carries a
genesis ref, base state, transfer sequence, previous segment hash, previous
checkpoint hash, target checkpoint hash, and old `TransferV3` bodies.

`ReceiptV3` binds `network_id`, `token_id`, tip transfer hash, sequence,
recipient x3 address, recipient `indpk3:` key, received-at timestamp,
signature algorithm, and Ed25519 signature.

`ConflictProofV3` binds `network_id`, token id, previous hash, sequence,
sender x3 address, spend key, both transfer hashes, and the two signed
`TransferV3` bodies that spend the same predecessor.

All hashes are raw 32-byte SHA3-256 digests. All Ed25519 public keys are raw
32-byte keys. All Ed25519 signatures are raw 64-byte signatures.

## Fail-Closed Requirements

## V3 Gossip Payloads

V3 transfer, proof-bundle, and archive-segment announcements carry canonical
binary V3 objects as base85 strings:

```text
payload_encoding               "indb3-base85"
payload field prefix           "indb3:"
```

The decoded bytes must parse as the expected V3 binary object. Receivers reject
malformed base85, wrong object magic, wrong network id, and unknown envelope
fields before storing or relaying the message.

Parsers must reject:

- V1/V2 JSON supplied as V3 binary.
- Unknown versions or algorithms.
- Non-minimal varints.
- Overlong byte arrays.
- Invalid nullable-hash markers.
- Invalid key or signature lengths.
- Duplicate or out-of-order sections.
- Trailing bytes.

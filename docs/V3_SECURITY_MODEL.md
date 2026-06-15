# IND V3 Security Model

V3 is the intended public bearer-bill protocol. V1/V2 remain internal reference
formats until V3 is complete.

## Trust Boundaries

V3 bills prove current spendability with:

- Ed25519 user transfer signatures.
- Canonical binary object hashes.
- Checkpoint cores that commit to old state.
- Proof-bundle references for transparency evidence.
- Local or fetchable proof bundles when policy requires proof.

Normal compact bills are intentionally thin. They are not full offline audit
archives unless exported with proof bundles and archive segments.

## Required Rejections

V3 verification must fail closed for:

- V1/V2 objects submitted as V3.
- V3 objects submitted to V1/V2 parsers.
- Unknown object versions.
- Unknown signature algorithms.
- Non-canonical binary encodings.
- Missing proof bundles when proof is required.
- Duplicate proof items or binary sections.
- Bad Ed25519 key or signature lengths.
- Sender keys that do not derive the current owner address.

## Key Separation

V3 user transfer keys are Ed25519 only:

```text
private key: indsk3:<base85 raw 32-byte Ed25519 seed>
public key:  indpk3:<base85 raw 32-byte Ed25519 public key>
address:     x3...x
```

Existing X25519 transport keys are never signing keys. Existing V1/V2
secp256k1 keys cannot satisfy x3 addresses, and V3 Ed25519 keys cannot satisfy
x1 or legacy addresses.

## Transparency

ProofBundleV3 stores transparency evidence once by content hash. A BillV3
carries only a proof-bundle reference. If policy requires transparency and the
referenced proof bundle is unavailable or invalid, the bill is invalid for that
policy mode.

Compact verification must not trust operator roots merely because they are
embedded in the bill. The verifier must use a trusted transparency verifier,
validated archive/checkpoint history, or an explicitly pinned operator key in
non-production policy. Compressed spend proofs must also bind the expected
network id, so a proof built for another network is not reusable.

Archive-backed ProofBundleV3 verification is recursive. If an archive segment
depends on a previous segment, the verifier must resolve and verify that segment
by hash. If the produced CheckpointCoreV3 links to a previous checkpoint, the
source evidence must name the previous ProofBundleV3 hash and the verifier must
validate that bundle against the previous checkpoint hash.

Production policy must require independent mirrored roots. Development may use
a local single-operator override, but that is not production-grade.

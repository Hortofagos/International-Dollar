# Threat Model

Status: experimental alpha.

## Security Goals

- A bill cannot be transferred without the current owner's private key.
- A malformed bill, transfer, retired receipt announcement, or conflict proof is rejected.
- A double-spend from the same bill state can be proven from signatures alone.
- Nodes do not rely on IP voting or stake voting to decide ownership.

## In Scope

## Double-Spend Attempts

An attacker can sign two transfers from the same bill state to different recipients. IND cannot prevent the attempt before gossip sees both branches. Once a node already knows one branch, it rejects a later sibling branch from that same bill state. A conflict proof remains evidence that the signer double-spent, but it does not burn already accepted downstream bills.

## Network Partitions And Eclipse Attacks

An isolated node may settle a bill before hearing about a conflicting branch if it is running in local-only mode. With operator quorum enabled, settlement requires a majority of configured append-capable transparency operators to prove the same spend-map claim for the exact spend key and transfer hash. The 60-second buffer still reduces ordinary propagation risk before that finality decision. Merchants should run well-connected nodes and treat high-value transfers more conservatively.

## Delayed Gossip

Peers can withhold messages. A conflict proof received before settlement vetoes local finality. Once a branch is locally settled, later conflict proofs are ignored: they do not invalidate the settled branch, move ownership, enter local conflict storage, or get relayed as active evidence.

## Retroactive History Forgery

Without a public timestamped commitment layer, an old owner could later sign a
plausible-looking chain of transfers and claim it happened in the past. The
transparency log layer addresses this by requiring each transfer hash in a bill
history to have an inclusion proof against a mirrored signed root near the
transfer timestamp.

The log does not make ownership decisions. The reference transparency operator
rejects a conflicting spend claim for a spend key it has already accepted, so
late double-spend attempts do not enter the spend map and do not burn
downstream holders. The log still makes hidden or backfilled history detectable.

## Log Operator Equivocation

In phase 1 there is one log operator. Consistency proofs prevent that operator
from quietly rewriting one public tree into another, but they do not by
themselves stop split-view equivocation. A malicious operator could show
different signed roots to different clients unless those roots are mirrored
and gossiped.

Clients should fetch historical roots from mirrors independent of the operator
serving inclusion proofs. If two mirrors or peers produce valid signed roots
from the same operator for the same timestamp with different tree sizes or root
hashes, that is durable evidence of operator dishonesty.

If an operator signs a root whose spend map accepts two different transfers for
the same spend key, the affected bill is rejected. When the spend-map proof
contains the conflicting transfer bodies, clients store
`ind.transparency_operator_policy_violation.v3`, blacklist that operator
locally, and gossip the evidence. This detects a malicious operator
manipulating the present; it does not replace future multi-operator quorum
finality.

Mirror diversity is load-bearing. A "mirror" controlled by the same operator
or served from the same infrastructure does not give strong protection.

Signed roots also have different meanings depending on how they are used. An
old signed root can be valid historical evidence that the log contained a
transfer near its timestamp, but it must not be accepted as the current log
state. Current validation rejects stale, future-dated, or locally regressing
roots so a network attacker cannot replay an old root to hide newer entries.

The transparency Merkle construction is CT-style, not CT-compliant. It uses
SHA3-256 with CT-style leaf and node domain separation. Earlier code and docs
used a misleading RFC6962-flavored identifier; verifiers treat that name as a
deprecated compatibility alias, and unknown algorithm identifiers fail closed.

## Malicious Nodes

Nodes can lie by omission, refuse to relay messages, or serve stale peer lists. They cannot forge valid transfers or conflict proofs without private keys.

## Spam And DoS

Attackers can flood peers with invalid or repeated messages. The current implementation validates before storing, deduplicates by message hash, caps wire payload sizes, rate-limits peers, penalizes invalid gossip, and bounds in-memory dedupe/peer tracking. These are alpha-grade controls, not a full production anti-DoS layer.

One bill can have at most 10 transfers per UTC day, which limits deliberate per-bill history growth. This does not remove network-level spam risk from attackers using many bills.

Genesis and transfer metadata are capped, which prevents using bill metadata as arbitrary bulk storage.

The reference TCP node also limits per-IP connection and request rates, cheaply caps gossip decode attempts before expensive parsing, caps active handler connections, bounds encrypted request frames, bounds compressed/decompressed wire payloads, and rejects non-global IPv4/IPv6 peer discovery addresses. Peers use an X25519/ChaCha20-Poly1305 transport with first-seen key pinning by IP address. These controls reduce trivial memory, socket exhaustion, slow-client thread pinning, and local-address pollution attacks; they do not replace a real peer reputation system, authenticated peer identities, or network-layer DDoS filtering.

## Issuer And Genesis Trust

The issuer controls genesis creation. A serious release must publish the trusted issuer key policy and a full supply commitment, such as a Merkle root over the genesis set. Without this, users must trust that no extra genesis bills exist.

The stronger current path is a signed lazy genesis manifest pinned by hash. This avoids publishing every bill while still letting users verify that a bill index, denomination, owner, and nonce come from the exact launch supply map. If nodes pin only an issuer key and not the manifest hash, the issuer could sign a second supply map; public networks should pin the exact manifest hash.

## Privacy

Bill histories reveal transfer paths to anyone who receives the bill. This is closer to a traceable bearer bill than private cash. Privacy improvements require a separate design review.

The encrypted node transport protects message contents from passive observers, but it does not make IND traffic indistinguishable from other TCP traffic. A censor can still identify reachable IND nodes by port, timing, packet shape, peer lists, or active probing.

The transparency log stores only transfer hashes, not full transfer payloads.
This keeps mirrors small and avoids publishing full bill histories, but a
party that already knows a transfer can test whether that exact transfer hash
appears in a log root.

Hash-log archives are audit evidence only when their manifests are signed and
linked to an operator-signed root. Unsigned segment dumps are operational
backups, not cryptographic evidence; an operator could omit or edit entries
unless auditors can recompute the Merkle root and compare it to a mirrored
signed root.

## Key Loss And Theft

If a wallet private key is lost, the bill is lost. If a wallet private key is
stolen, the thief can spend the bill. There is no recovery authority in the
bill protocol.

Transparency operators have a separate signing-key lifecycle. Operators can
publish signed rotation records, signed by both old and successor keys, and
clients enforce a monotonic `effective_from_tree_size` so old rotation records
cannot be replayed as rollback. Revocation records must reference a previously
accepted rotation and be signed by the successor key.

This improves scheduled rotation and recovery after a successor key already
exists, but it does not solve first-rotation compromise. If an operator's only
signing key is stolen before any accepted rotation establishes a successor key,
the protocol cannot cleanly distinguish honest recovery from attacker-controlled
recovery without out-of-band governance, mirror evidence, or client updates.
Operators should rotate early and keep successor/recovery material offline.

## Out Of Scope For Alpha

- Perfect global finality without consensus.
- Anonymous payments.
- Lost-key recovery.
- Legal compliance and real-money custody.
- Production-grade peer reputation.
- Full protection against eclipse attacks at the transparency gossip layer.

## Open Hardening Work

- Expand multi-node network simulations for delayed gossip and hostile peer selection.
- Publish genesis-set test vectors.
- Add independent protocol test vectors for every message type.
- Add authenticated peer identity and longer-lived reputation.
- Add multi-operator transparency policy.
- Replace transparency-operator full spend-map rebuilds with an incremental persistent map before high-volume public operation.
- Add automated publishing from staged root JSON to website, git, IPFS, and archive.org mirrors.
- Run external cryptographic and implementation review before real value is used.

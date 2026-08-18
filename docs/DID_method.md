# DID Method Specification: did:jkain

**Status:** Draft
**Version:** 0.1

## 1. Overview

`did:jkain` is a DID method built on JKain, a hashgraph-consensus ledger with Merkle-tree-backed durable state (see Phase 8: Fjall event log, sparse Merkle tree, `.esf`/`.rsf` mirror streams).

### 1.1 Design philosophy: proof-of-current-state, not log-replay

Unlike `did:hedera` or `did:ethr`, which require replaying an ordered log of every create/update/revoke event to reconstruct the current DID document, `did:jkain` resolution is a direct key-value lookup against the current Merkle-committed state, accompanied by an inclusion proof against the latest consensus-committed state root. Resolution cost is O(1) regardless of how many times the document has been updated.

Historical audit — "what did this document look like at time T," dispute resolution, revocation history — is explicitly not consensus's responsibility. It is served by mirror nodes consuming the `.esf`/`.rsf` streams, which are independently, cryptographically self-verifying (chained by running hash, Ed25519-signed, mirror-side quorum re-derivation of the same ≥2/3 threshold used by live consensus). Pruning live chain state does not lose this capability.

### 1.2 Relationship to did:key

`did:jkain` is not redundant with `did:key`. `did:key` gives a purely self-certifying identifier (id derived from the public key, verifiable offline) but is static — no ledger backing means no rotation, no revocation, ever. Rotation with `did:key` requires minting an entirely new identity, which breaks every existing reference to it.

`did:jkain` was originally designed to layer a mutable, ledger-backed document on top of a `did:key`-style self-certifying id, giving both offline bootstrap trust and rotation. Following further analysis (§2), the method has moved to an opaque identifier instead — trading offline bootstrap-trust for identifier stability, human legibility, and simpler uniqueness guarantees. See §2.4 for the full rationale.

## 2. Identifier Format

```
did:jkain:<network>:<alias>:<uuid>
```

Example: `did:jkain:mainnet:alice:9f8c3b2a-1d4e-4f6a-8b3c-2e7a9d1f0c55`

### 2.1 Segments

| Segment | Description |
|---|---|
| `network` | Fixed literal for now: `mainnet`. Stubbed in from day one so that a future second network (e.g. `testnet`) can be added as a new value in an existing slot, not a breaking format change. |
| `alias` | Human-readable label, e.g. `alice`. **Cosmetic only — not a uniqueness or authority guarantee.** Multiple DIDs may share the same alias. |
| `uuid` | UUIDv4, generated client-side by a cryptographically secure random source (CSPRNG) at creation time. Guarantees practical global uniqueness (122 bits of entropy) without a first-come-first-served allocation policy or squatting risk. |

### 2.2 Identifier immutability

The identifier — the full `<network>:<alias>:<uuid>` string — is fixed permanently at creation and never changes for the life of the DID, including across key rotation and deactivation. Rotation is a document update; the identifier itself is never re-derived or reassigned.

### 2.3 Authority resolution rule

**The alias segment aids human readability only.** Applications MUST NOT resolve, trust, or match DIDs based on the alias alone (e.g. "trust anything starting with `alice:`"). The full identifier including the uuid suffix is the sole unit of identity. Current signing authority is never read from the identifier — it is always read from the resolved document's verification methods (§4).

### 2.4 Why not self-certifying (did:key-style)?

An earlier draft of this spec used a self-certifying identifier, `did:jkain:pubkey:<base58-ed25519-key>`, where the id was the literal encoded public key — mirroring `did:key`. This was rejected. Summary of the trade-off:

**What self-certifying identifiers buy you:** a resolver holding only the id string can verify a signature made by that key with zero network/consensus round-trip — useful for offline verification or pre-registration sanity checks.

**Why it was dropped:**
- The benefit only ever applies to the *original* creation key. The moment the key is rotated, the id becomes stale — it still decodes to a real key, but that key is no longer authoritative, and nothing in the string itself signals this. A resolver that skips document lookup after rotation gets a silently wrong answer, not an error.
- Keys are not expected to remain fixed for a DID's lifetime — device loss, routine hygiene rotation, and compromise all make rotation a near-certainty over time, not an edge case. Optimizing for the pre-first-rotation window optimizes for a state most identities will quickly leave.
- The cost is permanent regardless: the id remains an unreadable base58 blob forever, in every log, reference, and config, even long after the key it names is stale.
- `did:hedera` v1.0 attempted a related approach — embedding the controlling key directly in the identifier — and hit exactly this problem: rotating the primary key was difficult or impossible without changing the identifier itself, meaning a compromised key required abandoning the whole DID to revoke control. Hedera fixed this in HIP-1219 (v2.0): the identifier segment is now a unique identifier only, with a separate `controller` property in the document as sole source of authority — the same shape `did:jkain` has adopted here.
- `did:ethr` follows the same pattern: address (id) fixed for life, current owner/controller looked up separately via the identity registry contract, never re-derived from the address.
- `did:pkh` (used for Solana and other chains without a native DID method) has no update mechanism at all, and is explicitly documented as a starting point projects graduate away from once they need rotation.

Net: every production method that supports rotation keeps the identifier fixed and opaque with respect to current authority; every method that embeds the key in the id either can't rotate (`did:key`, `did:pkh`) or had to fix this exact bug after the fact (`did:hedera` v1→v2). `did:jkain` adopts the fixed-opaque-id pattern from the start.

## 3. Creation

A `did:jkain` document is created via a `Put` transaction targeting a new, previously-unallocated identifier.

### 3.1 Uniqueness

The executor MUST reject a creation `Put` if the target identifier already exists in state. In practice, UUID entropy makes collision negligible; this check exists as a correctness formality, not a contested-allocation mechanism (no squatting is possible, since alias collisions are permitted and uuid collisions are practically impossible).

### 3.2 Creation-time authentication

Since the identifier carries no key material and therefore proves nothing on its own, the creation transaction's payload MUST be self-signed: the `Put` value (the initial DID document) must carry a signature verifiable against the key it names as its own first verification method. This substitutes for the offline self-certification an id-embedded key would have provided, without the rotation cost described in §2.4.

## 4. Authorization Model

### 4.1 Signature source

Authorization for DID document updates is **not** derived from the JKain `Event`-level gossip signature. This is a structural requirement, not a stylistic choice:

- `NodeId` (the entity whose key signs an `Event` in gossip) is a bare `u64` — a permissioned roster slot index, not arbitrary key material. `Transaction` itself carries no signer field.
- Using event-level signing as DID authorization would mean "who owns a DID" collapses to "which roster node relayed this transaction" — incompatible with DID owners being arbitrary end users / compute actors who are not roster members.

Instead, authorization is **embedded in the `Put` value itself**: each document-update transaction carries its own independent signature, checked by the executor against the current document's verification methods (i.e., the document as it exists in state *before* this update is applied).

### 4.2 Enforcement location

This logic lives entirely in `executor/state`, not in `protocol/consensus`. Consensus remains generic and unaware of DIDs; the mirror layer verifies checkpoint quorum but does not enforce document-level authorization. The executor's `Op` handling gains a precondition — fetch the prior document value, verify the embedded signature against its current verification method(s), then decide whether to apply the `Put` — rather than applying `Op::Put`/`Op::Delete` unconditionally as it does today.

*(Open implementation detail, not yet resolved: whether this is expressed as a new `DecodedOp` variant or as a precondition inside `Op::apply` / `state.rs`.)*

### 4.3 Scope of this authorization model

This ownership-check pattern is DID-specific for now. It is the only data type in JKain today where "who is allowed to write this key" depends on prior state rather than "any validly-decoded transaction." Other planned services (e.g. content/provenance messages, working name "JCS") will need their own, simpler write-once authorization (signature check only, no prior-state lookup) when built — not this pattern. Generic KV writes remain unauthenticated; this is safe only as long as JKain stays permissioned at the roster level. This assumption breaks if/when arbitrary compute actors are allowed to write directly to chain (V3), at which point a general authorization layer — not just a DID-specific one — will be required.

## 5. Key Rotation

- The identifier never changes on rotation (§2.2).
- Rotation is expressed as a document `Put` update, authorized under §4 by a key already listed as a current verification method in the prior document.
- Post-rotation, the prior key is simply no longer listed as current in the document; no special "revoked key" state is required beyond its absence from current verification methods (full history remains available via mirror `.esf`/`.rsf` streams per §1.1).

## 6. Deactivation

Deactivation is a **soft tombstone**, not a hard delete: a `Put` writing a document body marked `deactivated: true`, authorized the same way as any other update (§4). `Op::Delete` MUST NOT be used for deactivation.

Rationale: `Op::Delete` removes the key from the live Merkle tree entirely. Since JKain has no non-membership proof scheme, an absent key is indistinguishable from "never existed" — a resolver cannot get a proof that a DID was deactivated versus never registered. A tombstone `Put` keeps the key present in the tree, so resolution remains O(1) and deterministic: a deactivated DID resolves to a provable "deactivated" document, not an ambiguous absence. This is also consistent with the mirror/history model (§1.1), where the deactivation event itself remains a permanent, auditable part of the stream.

## 7. Open Items

Not yet resolved as of this draft:

- Exact implementation shape of the §4.2 ownership-check precondition (new `DecodedOp` variant vs. inline precondition in `Op::apply`/`state.rs`).
- Full verification-method document schema (multiple keys per document, key purposes/relationships, service endpoints).
- Whether/when a second network value (e.g. `testnet`) is introduced, and whether cross-network resolution is ever supported.
- V3-layer open questions (delivery guarantees to compute actors, replica-promotion quorum/split-brain, redirect-pointer retention) are explicitly deferred until DID plus a real compute-node implementation pass forces concrete answers — tracked separately in `V3_Compute_Layer_Notes.md` (non-authoritative scratch notes).

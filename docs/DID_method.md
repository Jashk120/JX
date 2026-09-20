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

**The alias segment aids human readability only.** Applications MUST NOT resolve, trust, or match DIDs based on the alias alone (e.g. "trust anything starting with `alice:`"). The full identifier including the uuid suffix is the sole unit of identity. Current signing authority is never read from the identifier — it is always read from the resolved document's verification methods (§4, §8).

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

A `did:jkain` document is created via a `DidOp` transaction (opcode `0x03`, §4.2) with `is_creation = 1`, targeting a new, previously unallocated identifier. The op body is:

```
[network_len: u32BE][network bytes]
[alias_len: u32BE][alias bytes]
[uuid: 16 bytes]
[DidDocument v2 (§8)]
[signature: 64 bytes]
[signed_by: u8]
[is_creation: u8 (0 or 1)]
```

The signed payload is `b"jkain:did:v1" || DidId::encode() || DidDocument::encode()`. The document is stored under the reserved state key `did_state_key(id) = 0xD1 || DidId::encode()`; `DidId::encode()` itself is the raw, unprefixed identifier encoding and is unchanged by the prefix.

### 3.1 Uniqueness

The executor MUST reject a creation `DidOp` if the target identifier already exists in state (`IdentifierAlreadyExists`). In practice, UUID entropy makes collision negligible; this check exists as a correctness formality, not a contested-allocation mechanism (no squatting is possible, since alias collisions are permitted and uuid collisions are practically impossible).

### 3.2 Creation-time authentication

Since the identifier carries no key material and therefore proves nothing on its own, the creation transaction's payload MUST be self-signed: the signature must verify against the new document's own verification method at filtered index `signed_by` (Ed25519 signing methods only, §8). This substitutes for the offline self-certification an id-embedded key would have provided, without the rotation cost described in §2.4. A creation carrying `deactivated: true` is rejected; a document must exist as an active document before it can be deactivated.

### 3.3 Root actor auto-creation

A successful creation additionally writes a fresh root actor record (§9.2) under `actor_state_key(ActorId::Root(id))` in the same validated transition: `{ did_id, merkle_root = EMPTY_ROOT = SHA256(""), leaf_count = 0, control_key }`, with the control key copied from the new document's explicit `control_key`. The `DidId` is opaque and never supplies key material.

## 4. Authorization Model

### 4.1 Signature source

Authorization for DID document updates is **not** derived from the JKain `Event`-level gossip signature. This is a structural requirement, not a stylistic choice:

- `NodeId` (the entity whose key signs an `Event` in gossip) is a bare `u64` — a permissioned roster slot index, not arbitrary key material. `Transaction` itself carries no signer field.
- Using event-level signing as DID authorization would mean "who owns a DID" collapses to "which roster node relayed this transaction" — incompatible with DID owners being arbitrary end users / compute actors who are not roster members.

Instead, authorization is **embedded in each operation itself**: every DID and actor transaction carries its own independent signature, checked by the executor against current state *before* the update is applied. The domain tags use the lowercase-colon convention `jkain:<op>:v1`:

| Op | Signed payload |
|---|---|
| `DidOp` (`0x03`) | `b"jkain:did:v1" \|\| DidId::encode() \|\| DidDocument::encode()` |
| `SubActorOp` (`0x04`) | `b"jkain:subactor:v1" \|\| actor_id_len:u32BE \|\| actor_id_bytes \|\| control_key:32B \|\| operating_key:32B` (`new_root` and both proofs are unsigned op input, §9.4) |
| `RebindOp` (`0x05`) | `b"jkain:rebind:v1" \|\| actor_id_len:u32BE \|\| actor_id_bytes \|\| old_operating_key:32B \|\| new_operating_key:32B` (the old key comes from state, §9.5) |

A `DidOp` update is authorized by the *prior* document's verification method at `signed_by`; a `SubActorOp` is authorized by the root DID document's signing method at `signed_by`. In both cases `signed_by` indexes the FILTERED, in-document order of Ed25519 signing methods only (§8): never the document's separate `control_key`, never an X25519 agreement method. `RebindOp` has no `signed_by` field; it is authorized by the root actor record's control key (§9.5).

### 4.2 Enforcement location

This logic lives entirely in `executor/state`, not in `protocol/consensus`. Consensus remains generic and unaware of DIDs; the mirror layer verifies checkpoint quorum but does not enforce document-level authorization.

(Resolved: the former open item is settled. Each operation type is a dedicated `DecodedOp` variant decoded from its opcode byte, and every validated transition writes through the same `State::Put` path so Merkle proofs cover DID and actor keys:)

| opcode | meaning | fields |
|--------|----------|--------------|
| `0x00` | `Put` | key, value |
| `0x01` | `Delete` | key |
| `0x02` | `MembershipOp` | decoded by `crypto::MembershipOp::decode`; side channel, never touches `State` |
| `0x03` | `DidOp` | decoded by `DidOp::decode` (§3) |
| `0x04` | `SubActorOp` | decoded by `SubActorOp::decode` (§9.4) |
| `0x05` | `RebindOp` | decoded by `RebindOp::decode` (§9.5) |

Any other opcode byte, a truncated payload, or trailing bytes decodes to a deterministic `ExecutorError`, identical on every node. Post-decode semantic failures travel on a generalized operation-error channel (`OpError`) that carries DID (`DidError`) and actor (`ActorError`) failures distinctly.

### 4.3 Scope of this authorization model

This ownership-check pattern covers DID and actor operations: the only data types in JKain today where "who is allowed to write this key" depends on prior state rather than "any validly-decoded transaction." Other planned services (e.g. content/provenance messages, working name "JCS") will need their own, simpler write-once authorization (signature check only, no prior-state lookup) when built — not this pattern. Generic KV writes remain unauthenticated, with one exception: the reserved state-key prefixes `0xD1` (DID records) and `0xA1` (actor records) are rejected at decode in all four generic `Put`/`Delete` arms (`Op::decode` and `DecodedOp::decode`, covering `Delete` as well so no tombstone back door remains), surfacing `ReservedKeyPrefix(u8)`. Only the executor's validated DID/actor transitions can populate those keys. This is safe only as long as JKain stays permissioned at the roster level. This assumption breaks if/when arbitrary compute actors are allowed to write directly to chain (V3), at which point a general authorization layer — not just a DID/actor-specific one — will be required.

## 5. Key Rotation

- The identifier never changes on rotation (§2.2).
- Rotation is expressed as a `DidOp` update (`is_creation = 0`), authorized under §4 by a key already listed as a current Ed25519 signing method in the prior document (at filtered index `signed_by`).
- Post-rotation, the prior key is simply no longer listed as current in the document; no special "revoked key" state is required beyond its absence from current verification methods (full history remains available via mirror `.esf`/`.rsf` streams per §1.1).
- Rotation atomically replaces the root actor record's control key with the new document's `control_key` while preserving its membership commitment (`merkle_root`, `leaf_count`); if the root record is absent or undecodable, a fresh empty one is recreated deterministically rather than failing. The DID document and its root record are therefore never stranded apart.

## 6. Deactivation

Deactivation is a **soft tombstone**, not a hard delete: a `DidOp` writing a document body with a nonzero `deactivated` byte, authorized the same way as any other update (§4). `Op::Delete` MUST NOT be used for deactivation.

Rationale: `Op::Delete` removes the key from the live Merkle tree entirely. Since JKain has no non-membership proof scheme, an absent key is indistinguishable from "never existed" — a resolver cannot get a proof that a DID was deactivated versus never registered. A tombstone `Put` keeps the key present in the tree, so resolution remains O(1) and deterministic: a deactivated DID resolves to a provable "deactivated" document, not an ambiguous absence. This is also consistent with the mirror/history model (§1.1), where the deactivation event itself remains a permanent, auditable part of the stream.

A deactivation writes the document only and leaves the root actor record untouched (retained, not removed). A deactivated DID rejects every further update (`AlreadyDeactivated`) and rejects all `SubActorOp` and `RebindOp` operations against it (`RootDeactivated`).

## 7. Open Items

Resolved since the previous draft:

- The §4.2 implementation shape is settled: dedicated `DecodedOp` variants (`Did`, `SubActor`, `Rebind`) decoded from opcodes `0x03`/`0x04`/`0x05`, writing through the shared `State::Put` path.
- The verification-method document schema is specified (§8): versioned v2 documents with an explicit Ed25519 `control_key` plus type-tagged Ed25519 signing and X25519 agreement methods.
- The actor document and reserved-key rules are specified (§9): canonical `ActorId`s, root/sub-actor records, the `0xD1`/`0xA1` reserved prefixes with generic-KV rejection, and the RFC-6962 membership commitment.

Explicitly deferred:

- Sub-actor removal/recreation. No removal operation exists in Phase A; the membership log is append-only. Replay caveat for a later phase: once removal/recreation ships, a recreated `(tag, index)` slot could replay an old signed `SubActorOp` against the new empty slot. Revisit when removal is designed.
- Phase-C location/resolution using the X25519 agreement key (`LocationOp` plus the off-chain DID-to-location resolution protocol).
- The on-chain manifest (out of scope for the actor layer plan).
- Whether/when a second network value (e.g. `testnet`) is introduced, and whether cross-network resolution is ever supported.
- V3-layer open questions (delivery guarantees to compute actors, replica-promotion quorum/split-brain, redirect-pointer retention) remain deferred until DID plus a real compute-node implementation pass forces concrete answers — tracked separately in `V3_Compute_Layer_Notes.md` (non-authoritative scratch notes).

Future phases only (none of these exist on chain; they MUST NOT be treated as implemented):

- Phase B (financial actors): `AccountOp`, `TransferOp`.
- Phase C (location): `LocationOp`.
- Phase D (compute-node execution and local storage).
- Phase E (audited actor-to-org path): `AuditProofOp` plus a proof-verifier path.

## 8. Document Encoding (v2)

A `DidDocument` is a versioned v2 record: an explicit 32-byte Ed25519 `control_key` plus type-tagged verification methods plus a deactivated flag. Binary encoding:

```
[version: u8 = 0x02]
[control_key: 32 bytes, Ed25519]
[num_methods: u8, 1..=5 total methods]
[num_methods x (type: u8, key: 32 bytes)]
[deactivated: u8, nonzero = true]
```

Method types: `0x01` is an Ed25519 signing method (`ed25519_dalek::VerifyingKey`); `0x02` is an X25519 agreement method (`x25519_dalek::PublicKey`) used for key agreement such as E2E-encrypted resolution/messaging. At least one method must be Ed25519 signing; the 1..=5 limit counts TOTAL methods. The `control_key` is independent of the method list: it participates in the canonical encoding (and thus in every `DidOp` signature) and doubles as the root actor's recovery/rebind authority (§9.2, §9.5), but it is never addressable by `signed_by`.

Decode rejects deterministically: a version byte other than `0x02` (`UnsupportedDidDocumentVersion`); zero or more than five methods (`Truncated`); an unknown method type (`UnknownVerificationMethodType`); zero Ed25519 signing methods (`NoSigningMethod`); any truncated field, including a truncated control key or a missing deactivated flag (`Truncated`); and an invalid Ed25519 point in the control key or a signing method (`Truncated`). X25519 agreement keys undergo no curve validation; any 32 bytes decode.

`signed_by` indexes the FILTERED, in-document order of Ed25519 signing methods only, skipping X25519 agreement methods. The document's `control_key` and every agreement method are never reachable through it.

## 9. Actor Layer

A DID is the person-level identity. Creating one implicitly creates a **root actor**: an index holding a Merkle commitment to its sub-actor set, never the list itself. Sub-actors are app-scoped identities carrying a descriptive tag, each with an immutable `control_key` and a mutable, rebindable `operating_key` (the day-to-day signer).

### 9.1 Actor identity and state keys

Canonical `ActorId`:

```
ActorId::Root(did)                    = 0x00 || DidId::encode()
ActorId::Sub { root_did, tag, index } = 0x01 || DidId::encode() || tag_code:u8 || index:u32BE
```

Tags are informational, never a permission gate: `0 = defi`, `1 = messenger`, `2 = game`, `3 = generic`. The same codes double as the HD path segment (§10). Decode rejects an unknown variant byte (`UnknownActorIdVariant`), a `tag_code > 3` (`UnknownActorTag`), and an `index >= 0x8000_0000` (`ActorIndexOutOfRange`): only u31 indices are valid, so an on-chain `ActorId` can never name an index the derivation path cannot produce. A sub-actor slot `(root_did, tag, index)` is unique per root; a mint targeting an occupied slot is rejected as a replay (`SubActorAlreadyExists`, §9.4).

State keys: `did_state_key(id) = 0xD1 || DidId::encode()`; `actor_state_key(id) = 0xA1 || ActorId::encode()`. The `0xD1`/`0xA1` prefixes are reserved: generic `Put`/`Delete` targeting either prefix is rejected at decode (`ReservedKeyPrefix`), so only validated DID/actor transitions populate these keys (§4.3).

### 9.2 Root actor record

`RootActor = { did_id, merkle_root, leaf_count, control_key }`, encoding `did.encode() || merkle_root:32B || leaf_count:u64BE || control_key:32B` (`DidId::encode` is self-delimiting, so no length prefixes). A fresh record holds `merkle_root = EMPTY_ROOT = SHA256("")` and `leaf_count = 0`. Lifecycle: creation writes a fresh record (§3.3); rotation replaces only the control key, preserving the commitment (§5); deactivation retains the record but rejects actor operations (§6).

### 9.3 Membership commitment (RFC-6962 log)

The root's commitment is an append-only RFC-6962 binary Merkle log over sub-actor leaves. It is NOT the state sparse Merkle tree: different domain separation, different empty value, no shared code.

A leaf commits the sub-actor's immutable `control_key` only:

```
leaf preimage = b"jkain:subactor-leaf:v1" || actor_id_len:u32BE || actor_id_bytes || control_key:32B
leaf          = SHA256(0x00 || leaf preimage)
```

The leaf tag differs from every signed-payload tag, so a leaf preimage is never replayable as a signature preimage (and vice versa). The mutable operating key lives only in the sub-actor state record; rebinds deliberately stay outside the commitment (§9.5).

Tree rules: `node_hash(left, right) = SHA256(0x01 || left || right)`; `MTH([]) = EMPTY_ROOT = SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (not the state SMT's `SHA256(0x00)`); a single leaf yields itself; otherwise the list splits at the largest power of two strictly below `n`. Invariant: `leaf_count == 0` if and only if the stored root equals `EMPTY_ROOT`.

Proofs (hashes raw, back-to-back, never individually prefixed; a `node_count` disagreeing with the algorithm-derived count for the claimed sizes is a hard reject):

```
consistency_proof = old_leaf_count:u64BE || new_leaf_count:u64BE || node_count:u32BE || node_count x 32B (RFC-6962 2.1.2 order)
inclusion_proof   = leaf_index:u64BE      || leaf_count:u64BE      || node_count:u32BE || node_count x 32B (RFC-6962 2.1.1 order)
```

The bootstrap from `EMPTY_ROOT` (`old_leaf_count == 0`) carries an empty consistency proof (`node_count = 0`); the executor still derives and validates the resulting root against `EMPTY_ROOT`.

### 9.4 Sub-actor mint (`SubActorOp`, `0x04`)

Body:

```
[root_did.encode()]
[tag:u8][index:u32BE]
[control_key: 32B][operating_key: 32B][new_root: 32B]
[consistency_proof.encode()][inclusion_proof.encode()]
[signature: 64B][signed_by:u8]
```

Both proofs are self-delimiting (`node_count`-framed) and read with cursor decoding. Decode rejects an unknown tag, `index >= 0x8000_0000`, invalid Ed25519 points, truncation, and trailing bytes. The op carries `new_root` plus both proofs but the executor trusts nothing: it reads the authoritative `(old_root, old_leaf_count)` from the root record in state.

Apply order:

1. Reject if the sub-actor state key is already present (`SubActorAlreadyExists`; replay short-circuit, before any tree work).
2. Load the root DID document from state (absent or undecodable yields `UnknownRootDid`); reject if deactivated (`RootDeactivated`).
3. Load the root actor record from state (`UnknownRootActor`); read authoritative `old_root`/`old_leaf_count`, never from the op.
4. Verify the signature against the root document's signing method at filtered `signed_by` (`UnknownSigner` / `InvalidSignature`).
5. Recompute the leaf from the op's own signed fields (`ActorId::Sub` plus `control_key`); verify the inclusion proof folds it to `op.new_root` at `leaf_index == old_leaf_count` (else `InclusionProofInvalid`).
6. Verify the consistency proof folds `old_root` to `op.new_root` for the single-leaf append (else `ConsistencyProofInvalid`).
7. Both pass: write the sub-actor record (`actor_id.encode() || control_key:32B || operating_key:32B`) and the updated root (`new_root`, `leaf_count + 1`); either fails: reject, root unchanged.

There is no removal operation in Phase A; the log only appends.

### 9.5 Operating-key rebind (`RebindOp`, `0x05`)

Sub-actors only. Body:

```
[actor_id.encode()]
[new_operating_key: 32B]
[proof_of_possession: 64B][authorizing_signature: 64B]
```

Both signatures cover exactly `b"jkain:rebind:v1" || actor_id_len:u32BE || actor_id_bytes || old_operating_key:32B || new_operating_key:32B`, where the old operating key comes from state at apply time, not from the op. The new operating key supplies proof of possession; the root actor record's control key (the mirror of the DID document's `control_key`, kept in sync by atomic rotation, §5) supplies authorization. There is no `signed_by` field.

Apply order: the actor ID must be a sub-actor (`ExpectedSubActorId` otherwise); the sub-actor record must exist (`UnknownSubActor`); the root DID document must exist and be active (`UnknownRootDid` / `RootDeactivated`); the root record must exist (`UnknownRootActor`); the proof of possession must verify against the new key (`InvalidProofOfPossession`); the authorization signature must verify against the root record's control key (`InvalidAuthorization`). Success rewrites only the mutable sub-actor record (control key preserved, operating key replaced) and never touches the root record or the membership commitment.

The sub-actor's own committed `control_key` authorizes nothing in Phase A: there is no self-rebind, so the committed control key is inert until a future phase grants it a role.

## 10. HD Key Derivation

Wallets derive keys with SLIP-0010 `ed25519` hardened-only derivation, implemented in `protocol/crypto` (`derive.rs`), never in `executor/state`. A wallet holds one stable master seed and derives domain-separated keys from it; the seed and every derived private key stay off chain and MUST never enter consensus state.

Canonical paths (every level hardened; callers pass non-hardened elements `< 0x8000_0000`, hardened internally):

```
did_control_key   = m/19019'/0'/generation'
actor_control_key = m/19019'/1'/tag_code'/index'
```

`tag_code` is `0 = defi, 1 = messenger, 2 = game, 3 = generic` (the same mapping as the on-chain tag, §9.1); values above 3 and indices at or above `0x8000_0000` are rejected, matching the on-chain `ActorId` rule. DID-control rotation increments its generation; actor paths remain stable across rotation.

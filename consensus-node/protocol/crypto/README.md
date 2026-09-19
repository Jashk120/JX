# crypto

Cryptographic building blocks for the JKain hashgraph.

Sits on top of `primitives` and provides the traits and machinery that make
event authenticity and membership deterministic and verifiable. Any value
that needs to be hashed, signed, or checked against the member set goes
through this crate.

## Contents

- `Hashable` — hashing abstraction backed by SHA-256.
- `CanonicalEncode` — deterministic byte encoding; the *only* input that
  may be fed into a hash function for consensus-critical types. Kept
  separate from hashing and signing so the concerns stay independent.
- `Signable` / `Verifiable` / `VerifiedEvent` — Ed25519 signing flow.
  `Event::sign` produces a signature; `Event::verify` checks it against a
  `MembershipRegistry` and, on success, returns a `VerifiedEvent`. A
  `VerifiedEvent` has no public constructor, so functions that require one
  (e.g. `Hashgraph::insert`) cannot be called with an unchecked event.
- `MembershipRegistry` — maps each `NodeId` to its Ed25519 verifying key,
  with a deterministic `NodeId`-sorted iteration order so every honest
  node derives the same member indexing independently.
- `MembershipOp` / `RosterHistory` — the membership-change wire format
  (`Add` carries the node id, verifying key, gossip address, and an optional
  reconnect address; `Remove` carries just the node id) and the round-indexed
  sequence of registry snapshots that activates changes at their agreed
  round.
- `derive` — SLIP-0010 `ed25519` hardened-only hierarchical deterministic
  key derivation. `derive_ed25519` derives a signing key from a seed along a
  fully hardened path (every element is hardened internally; elements
  `>= 0x8000_0000` and empty paths are rejected). `did_control_key`
  derives the canonical DID-control path `m/19019'/0'/generation'`, and
  `actor_control_key` derives the canonical actor-control path
  `m/19019'/1'/tag_code'/index'` (`0 = defi, 1 = messenger, 2 = game,
  3 = generic`). Library-side only: derived private material must never
  enter consensus state.

## Design

- Encoding, hashing, and signing are three separate traits: each type
  implements only what it needs, and each concern can evolve alone.
- No stake/weights: membership is one-member-one-vote, matching the
  `2n/3` supermajority idiom used by the consensus crate.

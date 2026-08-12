//! Phase 4 — the reconnect client.
//!
//! A node that has fallen behind (its peers can no longer serve the events
//! it needs via delta-sync) opens a TLS connection to a peer's dedicated
//! reconnect port, sends a [`ReconnectRequest`], and receives a
//! [`ReconnectResponse`]. The peer is trusted for *transport* only: the
//! cryptographic quorum proof lives inside the [`SignedCheckpoint`] itself,
//! and [`verify_signed_checkpoint`] checks it before the response is
//! returned.

use std::collections::HashSet;
use std::net::SocketAddr;

use consensus::SignedCheckpoint;

use crate::error::{
    GossipError,
    Result,
};
use crate::peer::PeerInfo;
use crate::proto::{
    Frame,
    ReconnectRequest,
    ReconnectResponse,
};
use crate::tls::TlsIdentity;
use crate::transport::{
    SyncTransport,
    TcpTransport,
};

/// Opens a TLS connection to `reconnect_addr` (the teacher's dedicated
/// reconnect port), sends a [`ReconnectRequest`], receives a
/// [`ReconnectResponse`], and verifies the >2/3 quorum proof before
/// returning. On any validation failure, returns
/// `Err(GossipError::Reconnect(..))`.
pub async fn fetch_checkpoint(
    identity: &TlsIdentity,
    peer: &PeerInfo,
    reconnect_addr: SocketAddr,
    node_id: primitives::NodeId,
) -> Result<ReconnectResponse> {
    // The TLS pinning and certificate checks come from `peer`; only the
    // destination address differs from the gossip port.
    let mut target = peer.clone();
    target.addr = reconnect_addr;

    let mut transport = TcpTransport::new(identity.clone());
    transport.connect(&target).await?;
    transport.send_frame(&Frame::Reconnect(ReconnectRequest { from: node_id })).await?;

    let response = match transport.recv_frame().await? {
        Frame::ReconnectResponse(response) => response,
        other => {
            return Err(GossipError::UnexpectedFrame {
                expected: "ReconnectResponse",
                got: frame_name(&other),
            });
        }
    };

    if verify_signed_checkpoint(&response.signed_checkpoint) {
        Ok(response)
    } else {
        Err(GossipError::Reconnect("checkpoint failed quorum verification".into()))
    }
}

/// Verifies the >2/3 quorum proof embedded in `checkpoint`:
///
/// 1. Recompute [`consensus::CheckpointPayload::signing_bytes`] from the
///    embedded payload.
/// 2. For each [`consensus::CheckpointSig`], look up the signer's key in
///    `checkpoint.payload.roster_snapshot` — the payload is self-describing,
///    so no external roster lookup is needed.
/// 3. Count distinct *valid* signers; reject if `signers * 3 <= total * 2`.
///
/// A signature is a no-op (not evidence against the checkpoint) if its round
/// disagrees with the payload, its signer is not in the snapshot roster, or
/// its Ed25519 signature does not verify — exactly like a duplicate signer.
/// Only the count of distinct, valid signatures determines acceptance, so a
/// quorum'd checkpoint is not rejected just because an extra stale or forged
/// signature was appended.
pub fn verify_signed_checkpoint(checkpoint: &SignedCheckpoint) -> bool {
    let total = checkpoint.payload.roster_snapshot.len();
    let signing_bytes = checkpoint.payload.signing_bytes();
    let mut valid = 0usize;
    let mut seen = HashSet::new();
    for sig in &checkpoint.sigs {
        if sig.round != checkpoint.payload.round {
            continue;
        }
        if !seen.insert(sig.signer) {
            continue;
        }
        let Ok(key) = checkpoint.payload.roster_snapshot.key_for(&sig.signer) else {
            continue;
        };
        let signature = ed25519_dalek::Signature::from_bytes(sig.sig.as_bytes());
        if key.verify_strict(&signing_bytes, &signature).is_ok() {
            valid += 1;
        }
    }
    valid * 3 > total * 2
}

fn frame_name(frame: &Frame) -> &'static str {
    match frame {
        Frame::SyncRequest(_) => "SyncRequest",
        Frame::SyncResponse(_) => "SyncResponse",
        Frame::Event(_) => "Event",
        Frame::CheckpointSig(_) => "CheckpointSig",
        Frame::Reconnect(_) => "Reconnect",
        Frame::ReconnectResponse(_) => "ReconnectResponse",
        Frame::Behind => "Behind",
    }
}

#[cfg(test)]
mod tests {
    use consensus::{
        CheckpointPayload,
        CheckpointSig,
    };
    use ed25519_dalek::{
        Signer,
        SigningKey,
    };
    use primitives::{
        NodeId,
        Signature,
    };

    use super::*;

    struct Cluster {
        registry: crypto::MembershipRegistry,
        keys: Vec<(u64, SigningKey)>,
    }

    impl Cluster {
        fn of(ids: &[u64]) -> Self {
            let mut registry = crypto::MembershipRegistry::new();
            let keys: Vec<(u64, SigningKey)> = ids
                .iter()
                .map(|&id| {
                    let key = SigningKey::from_bytes(&[id as u8; 32]);
                    registry.register(NodeId::new(id), key.verifying_key());
                    (id, key)
                })
                .collect();
            Self { registry, keys }
        }

        fn real_sig(&self, round: u64, signer: u64) -> CheckpointSig {
            let signing_bytes = self.signing_bytes(round);
            let key = &self.keys.iter().find(|(id, _)| *id == signer).unwrap().1;
            let sig = key.sign(&signing_bytes);
            CheckpointSig {
                round,
                signer: NodeId::new(signer),
                sig: Signature::new(sig.to_bytes()),
            }
        }

        fn signing_bytes(&self, round: u64) -> [u8; 72] {
            let payload = CheckpointPayload::new(round, [7u8; 32], self.registry.clone());
            payload.signing_bytes()
        }

        fn checkpoint(&self, round: u64, signers: &[u64]) -> SignedCheckpoint {
            let payload = CheckpointPayload::new(round, [7u8; 32], self.registry.clone());
            let sigs = signers.iter().map(|&s| self.real_sig(round, s)).collect();
            SignedCheckpoint { payload, sigs }
        }
    }

    #[test]
    fn quorum_passes_at_three_of_four() {
        let cluster = Cluster::of(&[1, 2, 3, 4]);
        let checkpoint = cluster.checkpoint(3, &[1, 2, 3]);
        assert!(verify_signed_checkpoint(&checkpoint));
    }

    #[test]
    fn quorum_fails_at_two_of_four() {
        let cluster = Cluster::of(&[1, 2, 3, 4]);
        let checkpoint = cluster.checkpoint(3, &[1, 2]);
        assert!(!verify_signed_checkpoint(&checkpoint));
    }

    #[test]
    fn forged_signature_is_not_counted_toward_quorum() {
        let cluster = Cluster::of(&[1, 2, 3, 4]);
        let mut checkpoint = cluster.checkpoint(3, &[1, 2]);
        // A forged third signature: wrong bytes, so it must not tip quorum.
        checkpoint.sigs.push(CheckpointSig {
            round: 3,
            signer: NodeId::new(3),
            sig: Signature::new([0x42; 64]),
        });
        assert!(!verify_signed_checkpoint(&checkpoint));
    }

    #[test]
    fn signer_not_in_roster_is_not_counted() {
        let cluster = Cluster::of(&[1, 2, 3, 4]);
        // Two valid signers + a rogue not in the roster: still below quorum.
        let mut checkpoint = cluster.checkpoint(3, &[1, 2]);
        let rogue_key = SigningKey::from_bytes(&[5u8; 32]);
        let rogue_sig = rogue_key.sign(&cluster.signing_bytes(3));
        checkpoint.sigs.push(CheckpointSig {
            round: 3,
            signer: NodeId::new(5),
            sig: Signature::new(rogue_sig.to_bytes()),
        });
        assert!(!verify_signed_checkpoint(&checkpoint));

        // A rogue signature appended to a genuine quorum must not reject it.
        let mut checkpoint = cluster.checkpoint(3, &[1, 2, 3]);
        let rogue_key = SigningKey::from_bytes(&[6u8; 32]);
        let rogue_sig = rogue_key.sign(&cluster.signing_bytes(3));
        checkpoint.sigs.push(CheckpointSig {
            round: 3,
            signer: NodeId::new(6),
            sig: Signature::new(rogue_sig.to_bytes()),
        });
        assert!(verify_signed_checkpoint(&checkpoint));
    }

    #[test]
    fn duplicate_signer_counts_once() {
        let cluster = Cluster::of(&[1, 2, 3, 4]);
        let mut checkpoint = cluster.checkpoint(3, &[1, 2]);
        checkpoint.sigs.push(cluster.real_sig(3, 2));
        // Still only two distinct valid signers: below quorum.
        assert!(!verify_signed_checkpoint(&checkpoint));
    }

    #[test]
    fn wrong_round_sig_is_not_counted() {
        let cluster = Cluster::of(&[1, 2, 3, 4]);
        // A stale sig over a different round appended to a genuine quorum.
        let mut checkpoint = cluster.checkpoint(3, &[1, 2, 3]);
        checkpoint.sigs.push(cluster.real_sig(4, 4));
        assert!(verify_signed_checkpoint(&checkpoint));
    }
}

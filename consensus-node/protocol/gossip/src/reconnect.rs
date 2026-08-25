//! Phase 4 — the reconnect client.
//!
//! A node that has fallen behind (its peers can no longer serve the events
//! it needs via delta-sync) opens a TLS connection to a peer's dedicated
//! reconnect port, sends a [`ReconnectRequest`], and receives a
//! [`ReconnectResponse`]. The peer is trusted for *transport* only: the
//! cryptographic quorum proof lives inside the [`SignedCheckpoint`] itself,
//! and [`verify_signed_checkpoint`] checks it before the response is
//! returned.

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
///
/// `trusted_roster_hash` anchors the checkpoint's `roster_snapshot` against
/// a roster the caller already trusts (typically the node's last-known
/// registry). If the served roster hash does not match, the checkpoint is
/// rejected even if the signatures are internally consistent — a malicious
/// peer cannot substitute an arbitrary roster. There is no `None` path;
/// callers must supply a trusted hash and fail-closed if none is available.
pub async fn fetch_checkpoint(
    identity: &TlsIdentity,
    peer: &PeerInfo,
    reconnect_addr: SocketAddr,
    node_id: primitives::NodeId,
    trusted_roster_hash: [u8; 32],
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

    if verify_signed_checkpoint(&response.signed_checkpoint, trusted_roster_hash) {
        Ok(response)
    } else {
        Err(GossipError::Reconnect("checkpoint failed quorum verification".into()))
    }
}

/// Verifies the >2/3 BLS aggregate proof embedded in `checkpoint`.
///
/// The checkpoint's `roster_hash` is compared against `expected_roster_hash`
/// first; a mismatch rejects before any BLS verification.
pub fn verify_signed_checkpoint(
    checkpoint: &SignedCheckpoint,
    expected_roster_hash: [u8; 32],
) -> bool {
    if checkpoint.payload.roster_hash != expected_roster_hash {
        return false;
    }
    checkpoint.verify()
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
        compute_records_root,
    };
    use crypto::Hashable;
    use primitives::NodeId;

    use super::*;

    struct Cluster {
        registry: crypto::MembershipRegistry,
        bls_ids: Vec<(u64, crypto::BlsIdentity)>,
    }

    impl Cluster {
        fn of(ids: &[u64]) -> Self {
            let mut registry = crypto::MembershipRegistry::new();
            let bls_ids: Vec<(u64, crypto::BlsIdentity)> = ids
                .iter()
                .map(|&id| {
                    let bls = crypto::BlsIdentity::from_ikm(&[id as u8; 32]).expect("bls");
                    let ed = ed25519_dalek::SigningKey::from_bytes(&[id as u8; 32]);
                    registry.register(NodeId::new(id), ed.verifying_key(), bls.public.to_bytes());
                    (id, bls)
                })
                .collect();
            Self { registry, bls_ids }
        }

        #[allow(dead_code)]
        fn signing_bytes(&self, round: u64) -> [u8; 104] {
            let rr = compute_records_root(&[]);
            let payload = CheckpointPayload::new(round, rr, [7u8; 32], self.registry.clone());
            payload.signing_bytes()
        }

        fn checkpoint(&self, round: u64, signers: &[u64]) -> SignedCheckpoint {
            let rr = compute_records_root(&[]);
            let payload = CheckpointPayload::new(round, rr, [7u8; 32], self.registry.clone());
            let mut sigs: Vec<&blst::min_pk::Signature> = Vec::new();
            let mut sig_owned = Vec::new();
            for &s in signers {
                let bls = self.bls_ids.iter().find(|(id, _)| *id == s).unwrap();
                sig_owned.push(bls.1.sign(&payload.signing_bytes()));
            }
            for sig in &sig_owned {
                sigs.push(sig);
            }
            let _refs: Vec<&blst::min_pk::Signature> = sigs.to_vec();
            let mut sorted_signers: Vec<NodeId> =
                signers.iter().map(|&id| NodeId::new(id)).collect();
            sorted_signers.sort();
            // Need to sort sigs according to sorted_signers order for determinism
            let mut pairs: Vec<(NodeId, blst::min_pk::Signature)> =
                signers.iter().zip(sig_owned).map(|(&id, sig)| (NodeId::new(id), sig)).collect();
            pairs.sort_by_key(|(id, _)| *id);
            let sorted_refs: Vec<&blst::min_pk::Signature> = pairs.iter().map(|(_, s)| s).collect();
            let agg = crypto::bls::aggregate(&sorted_refs).expect("aggregate");
            SignedCheckpoint { payload, aggregate_sig: agg, signers: sorted_signers }
        }
    }

    #[test]
    fn quorum_passes_at_three_of_four() {
        let cluster = Cluster::of(&[1, 2, 3, 4]);
        let checkpoint = cluster.checkpoint(3, &[1, 2, 3]);
        assert!(verify_signed_checkpoint(&checkpoint, checkpoint.payload.roster_hash));
    }

    #[test]
    fn quorum_fails_at_two_of_four() {
        let cluster = Cluster::of(&[1, 2, 3, 4]);
        let checkpoint = cluster.checkpoint(3, &[1, 2]);
        assert!(!verify_signed_checkpoint(&checkpoint, checkpoint.payload.roster_hash));
    }

    #[test]
    fn forged_signature_fails_verify() {
        let cluster = Cluster::of(&[1, 2, 3, 4]);
        let rr = compute_records_root(&[]);
        let payload = CheckpointPayload::new(3, rr, [7u8; 32], cluster.registry.clone());
        // Two honest sigs
        let s1 = cluster
            .bls_ids
            .iter()
            .find(|(id, _)| *id == 1)
            .unwrap()
            .1
            .sign(&payload.signing_bytes());
        let s2 = cluster
            .bls_ids
            .iter()
            .find(|(id, _)| *id == 2)
            .unwrap()
            .1
            .sign(&payload.signing_bytes());
        // Forge third sig with wrong key for signer 3
        let forger = crypto::BlsIdentity::from_ikm(&[0xEEu8; 32]).expect("forger");
        let s3 = forger.sign(&payload.signing_bytes());
        let agg = crypto::bls::aggregate(&[&s1, &s2, &s3]).expect("agg");
        let checkpoint = SignedCheckpoint {
            payload,
            aggregate_sig: agg,
            signers: vec![NodeId::new(1), NodeId::new(2), NodeId::new(3)],
        };
        assert!(!verify_signed_checkpoint(&checkpoint, checkpoint.payload.roster_hash));
    }

    #[test]
    fn signer_not_in_roster_fails() {
        let cluster = Cluster::of(&[1, 2, 3, 4]);
        let rr = compute_records_root(&[]);
        let payload = CheckpointPayload::new(3, rr, [7u8; 32], cluster.registry.clone());
        let s1 = cluster
            .bls_ids
            .iter()
            .find(|(id, _)| *id == 1)
            .unwrap()
            .1
            .sign(&payload.signing_bytes());
        let s2 = cluster
            .bls_ids
            .iter()
            .find(|(id, _)| *id == 2)
            .unwrap()
            .1
            .sign(&payload.signing_bytes());
        let rogue = crypto::BlsIdentity::from_ikm(&[5u8; 32]).expect("rogue");
        let s3 = rogue.sign(&payload.signing_bytes());
        let agg = crypto::bls::aggregate(&[&s1, &s2, &s3]).expect("agg");
        let checkpoint = SignedCheckpoint {
            payload: payload.clone(),
            aggregate_sig: agg,
            signers: vec![NodeId::new(1), NodeId::new(2), NodeId::new(5)],
        };
        assert!(!verify_signed_checkpoint(&checkpoint, checkpoint.payload.roster_hash));

        // Even a genuine quorum with an extra rogue signer should fail because
        // aggregate includes the rogue and signer not in roster.
        let s3_honest = cluster
            .bls_ids
            .iter()
            .find(|(id, _)| *id == 3)
            .unwrap()
            .1
            .sign(&payload.signing_bytes());
        let rogue2 = crypto::BlsIdentity::from_ikm(&[6u8; 32]).expect("rogue2");
        let s4 = rogue2.sign(&payload.signing_bytes());
        let agg2 = crypto::bls::aggregate(&[&s1, &s2, &s3_honest, &s4]).expect("agg2");
        let checkpoint2 = SignedCheckpoint {
            payload,
            aggregate_sig: agg2,
            signers: vec![NodeId::new(1), NodeId::new(2), NodeId::new(3), NodeId::new(6)],
        };
        assert!(!verify_signed_checkpoint(&checkpoint2, checkpoint2.payload.roster_hash));
    }

    #[test]
    fn duplicate_signer_fails() {
        let cluster = Cluster::of(&[1, 2, 3, 4]);
        let rr = compute_records_root(&[]);
        let payload = CheckpointPayload::new(3, rr, [7u8; 32], cluster.registry.clone());
        let s1 = cluster
            .bls_ids
            .iter()
            .find(|(id, _)| *id == 1)
            .unwrap()
            .1
            .sign(&payload.signing_bytes());
        let s2 = cluster
            .bls_ids
            .iter()
            .find(|(id, _)| *id == 2)
            .unwrap()
            .1
            .sign(&payload.signing_bytes());
        // Duplicate signer 2
        let agg = crypto::bls::aggregate(&[&s1, &s2, &s2]).expect("agg dup");
        let checkpoint = SignedCheckpoint {
            payload,
            aggregate_sig: agg,
            signers: vec![NodeId::new(1), NodeId::new(2), NodeId::new(2)],
        };
        assert!(!verify_signed_checkpoint(&checkpoint, checkpoint.payload.roster_hash));
    }

    #[test]
    fn roster_hash_mismatch_rejects_even_with_valid_quorum() {
        let cluster = Cluster::of(&[1, 2, 3, 4]);
        let checkpoint = cluster.checkpoint(3, &[1, 2, 3]);
        let wrong_hash = checkpoint.payload.roster_hash;
        let mut altered = wrong_hash;
        altered[0] ^= 0xff;
        assert!(!verify_signed_checkpoint(&checkpoint, altered));
        assert!(verify_signed_checkpoint(&checkpoint, wrong_hash));
    }

    #[test]
    fn fabricated_roster_with_attacker_quorum_rejected_by_trusted_hash() {
        let legitimate = Cluster::of(&[1, 2, 3, 4]);
        let trusted_hash = legitimate.registry.hash();
        let attacker = Cluster::of(&[99, 98, 97]);
        let checkpoint = attacker.checkpoint(5, &[99, 98, 97]);
        assert!(
            !verify_signed_checkpoint(&checkpoint, trusted_hash),
            "fabricated roster with attacker quorum must be rejected against a trusted hash"
        );
    }

    #[test]
    fn fabricated_roster_passes_when_trusted_hash_matches() {
        let attacker = Cluster::of(&[99, 98, 97]);
        let checkpoint = attacker.checkpoint(5, &[99, 98, 97]);
        let attacker_hash = checkpoint.payload.roster_hash;
        assert!(
            verify_signed_checkpoint(&checkpoint, attacker_hash),
            "fabricated roster passes when its own hash is the trust anchor"
        );
    }
}

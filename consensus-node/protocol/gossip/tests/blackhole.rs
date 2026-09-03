#![allow(dead_code, clippy::useless_vec)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool,
    Ordering,
};
use std::time::Duration;

use common::*;
use gossip::{
    FanoutMode,
    GossipNode,
    PeerInfo,
    SyncTiming,
    TlsIdentity,
};
use primitives::NodeId;
use tokio::net::TcpListener;
use tokio::time::{
    sleep,
    timeout,
};

/// Spawns a blackholed gossip listener: every accepted `TcpStream` is held
/// open forever without reading or writing, so a TLS `connect` on it hangs
/// until the caller's timeout fires. Returns the bound address and a handle
/// that can be aborted when the test finishes.
async fn spawn_blackholed_listener() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("blackhole bind");
    let addr = listener.local_addr().expect("blackhole addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _stream = stream;
                sleep(Duration::from_secs(60)).await;
            });
        }
    });
    (addr, handle)
}

#[tokio::test]
async fn blackholed_peer_does_not_livelock_serial_driver() {
    let (blackhole_addr, blackhole_handle) = spawn_blackholed_listener().await;
    let blackhole_peer = PeerInfo::new(NodeId::new(99), blackhole_addr, [0u8; 32]);
    let sync_timeout = Duration::from_millis(80);
    let sync_interval = Duration::from_millis(25);
    let key = ed25519_dalek::SigningKey::from_bytes(&consensus_seed(10));
    let identity = TlsIdentity::from_seed(tls_seed(10), 10).expect("identity");
    let registry = registry_for(&[
        (10, key.clone()),
        (99, ed25519_dalek::SigningKey::from_bytes(&[99u8; 32])),
    ]);
    let listener = bind_ephemeral().await;
    let node = Arc::new(GossipNode::new(
        NodeId::new(10),
        key,
        registry,
        identity,
        vec![blackhole_peer],
        SyncTiming::new(sync_interval, sync_timeout),
        temp_state_db(),
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let n = node.clone();
    let s = stop.clone();
    let handle = tokio::spawn(async move {
        let _ = n.run_until_stopped(listener, s).await;
    });
    sleep(Duration::from_millis(500)).await;
    let metrics = node.gossip_metrics_snapshot().await;
    assert!(metrics.sync_attempts > 0, "driver must have attempted syncs");
    assert!(metrics.sync_failures > 0, "blackholed peer must be counted as failure");
    stop.store(true, Ordering::Release);
    timeout(Duration::from_secs(2), handle)
        .await
        .expect("driver stops promptly despite blackholed peer")
        .expect("join ok");
    blackhole_handle.abort();
}

#[tokio::test]
async fn blackholed_peer_does_not_livelock_fanout_driver() {
    let (blackhole_addr, blackhole_handle) = spawn_blackholed_listener().await;
    let keys = vec![
        (1, ed25519_dalek::SigningKey::from_bytes(&consensus_seed(1))),
        (2, ed25519_dalek::SigningKey::from_bytes(&consensus_seed(2))),
    ];
    let identities = [
        TlsIdentity::from_seed(tls_seed(1), 1).expect("identity"),
        TlsIdentity::from_seed(tls_seed(2), 2).expect("identity"),
    ];
    let listener_honest = bind_ephemeral().await;
    let addr_honest = listener_honest.local_addr().expect("addr");
    let listener_observer = bind_ephemeral().await;
    let addr_observer = listener_observer.local_addr().expect("addr");
    let honest = Arc::new(GossipNode::new(
        NodeId::new(1),
        keys[0].1.clone(),
        registry_for(&keys),
        identities[0].clone(),
        vec![PeerInfo::new(NodeId::new(2), addr_observer, identities[1].spki_fingerprint())],
        SyncTiming::new(Duration::from_millis(25), Duration::from_millis(100)),
        temp_state_db(),
    ));
    let blackhole_peer = PeerInfo::new(NodeId::new(99), blackhole_addr, [0u8; 32]);
    let honest_peer = PeerInfo::new(NodeId::new(1), addr_honest, identities[0].spki_fingerprint());
    let mut observer = GossipNode::new(
        NodeId::new(2),
        keys[1].1.clone(),
        registry_for(&keys),
        identities[1].clone(),
        vec![honest_peer, blackhole_peer],
        SyncTiming::new(Duration::from_millis(25), Duration::from_millis(100)),
        temp_state_db(),
    );
    observer.set_fanout(FanoutMode::Fixed(2));
    let observer = Arc::new(observer);
    let stop_h = Arc::new(AtomicBool::new(false));
    let stop_o = Arc::new(AtomicBool::new(false));
    let h = honest.clone();
    let sh = stop_h.clone();
    let ho = tokio::spawn(async move {
        let _ = h.run_until_stopped(listener_honest, sh).await;
    });
    let o = observer.clone();
    let so = stop_o.clone();
    let oo = tokio::spawn(async move {
        let _ = o.run_until_stopped(listener_observer, so).await;
    });
    timeout(Duration::from_secs(5), async {
        loop {
            sleep(Duration::from_millis(50)).await;
            let m = observer.gossip_metrics_snapshot().await;
            if m.sync_success > 0 && m.sync_failures > 0 {
                break;
            }
        }
    })
    .await
    .expect("observer makes at least one successful sync with honest peer despite blackholed peer");

    let m = observer.gossip_metrics_snapshot().await;
    assert!(m.sync_success > 0, "fanout driver must succeed with honest peer");
    assert!(m.sync_failures > 0, "blackholed peer must be counted as failure");
    stop_h.store(true, Ordering::Release);
    stop_o.store(true, Ordering::Release);
    timeout(Duration::from_secs(2), ho).await.expect("honest stops").expect("join");
    timeout(Duration::from_secs(2), oo).await.expect("observer stops").expect("join");
    blackhole_handle.abort();
}

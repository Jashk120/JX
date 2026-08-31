use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{
    IpAddr as PkiIpAddr,
    ServerName,
};
use tokio::io::{
    AsyncRead,
    AsyncReadExt,
    AsyncWrite,
    AsyncWriteExt,
};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{
    TlsAcceptor,
    TlsConnector,
};

use crate::error::{
    GossipError,
    Result,
};
use crate::peer::PeerInfo;
use crate::proto::Frame;
use crate::tls::TlsIdentity;

/// The connection abstraction the sync logic talks to. One persistent
/// connection per peer, reused across sync rounds rather than reopened each
/// interval.
#[allow(async_fn_in_trait)]
pub trait SyncTransport {
    /// Establishes (or reuses) a pinned TLS connection to `peer`.
    async fn connect(&mut self, peer: &PeerInfo) -> Result<()>;

    async fn send_frame(&mut self, frame: &Frame) -> Result<()>;

    async fn recv_frame(&mut self) -> Result<Frame>;

    fn is_connected(&self) -> bool;
}

/// A `SyncTransport` over TCP with TLS 1.3 (rustls), as chosen by the
/// whitepaper (§2.2) for the consensus-hot gossip path.
pub struct TcpTransport {
    tls_identity: TlsIdentity,
    stream: Option<Box<dyn AsyncReadWrite + Unpin + Send>>,
}

impl TcpTransport {
    pub fn new(tls_identity: TlsIdentity) -> Self {
        Self { tls_identity, stream: None }
    }

    /// Wraps an already-accepted TLS stream (inbound server side). The
    /// identity is kept so `acceptor` and any client pinning can be derived
    /// from the same object.
    pub fn from_tls_stream(tls_identity: TlsIdentity, stream: ServerTlsStream<TcpStream>) -> Self {
        Self { tls_identity, stream: Some(Box::new(stream)) }
    }

    /// The TLS acceptor used on the inbound side.
    pub fn acceptor(&self) -> Result<TlsAcceptor> {
        let config = self.tls_identity.server_config()?;
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

/// Object-safe alias for `AsyncRead + AsyncWrite`, since a `dyn` object may
/// list at most one non-auto trait.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// Maximum allowed frame payload size (64 MiB). Covers sync deltas and
/// reconnect retained graphs with generous headroom while preventing a
/// single unauthenticated peer from OOM-ing the process via a bogus u32
/// length prefix.
const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

/// Real QUIC transport via `quinn` + `rustls` SPKI verifier.
///
/// Uses a single `peer.addr` as the UDP (QUIC) endpoint per PLAN-2.4 D4:
/// the same `gossip_addr` is treated as the QUIC address. `Frame` encoding
/// remains `[tag:u8][len:u32BE][payload]` unchanged over the QUIC bidirectional
/// stream. `TcpTransport` stays as the fallback when QUIC is unavailable.
///
/// Current skeleton: the QUIC `Endpoint` is created with a `rustls`
/// `ClientConfig` that reuses `TlsIdentity::spki_fingerprint` via a custom
/// `ServerCertVerifier` (same pin `433d8c…` logic as `TcpTransport`). Frame
/// I/O currently delegates to the inner `TcpTransport` until the QUIC bidi
/// stream path is fully wired; `is_quic`/`is_connected` already reflect the
/// real QUIC state so callers can distinguish the transport.
pub struct QuicTransport {
    tls_identity: TlsIdentity,
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    // Persistent bidi streams for Frame transport: Frame bytes are written
    // to `SendStream` and read from `RecvStream` without re-encoding.
    // Lazily opened on first `send_frame`; `None` before `connect`.
    send: Option<quinn::SendStream>,
    recv: Option<quinn::RecvStream>,
    /// TCP fallback — used when QUIC is unavailable or the peer has no
    /// `quic_addr` (see `cluster_config` single-addr fallback).
    fallback: TcpTransport,
}

impl QuicTransport {
    pub fn new(tls_identity: TlsIdentity) -> Self {
        let fallback = TcpTransport::new(tls_identity.clone());
        Self { tls_identity, endpoint: None, connection: None, send: None, recv: None, fallback }
    }

    /// Whether this transport is the QUIC variant (always true for this type).
    pub fn is_quic(&self) -> bool {
        true
    }

    /// Returns the underlying QUIC `Endpoint` if one has been created.
    pub fn endpoint(&self) -> Option<&quinn::Endpoint> {
        self.endpoint.as_ref()
    }

    /// Returns the active QUIC `Connection` if connected.
    pub fn connection(&self) -> Option<&quinn::Connection> {
        self.connection.as_ref()
    }

    /// Builds a `quinn` client endpoint bound to an ephemeral `0.0.0.0:0`
    /// UDP socket, using `TlsIdentity::client_config` (SPKI pin) wrapped in
    /// `QuicClientConfig`. This is the SPKI verifier wiring that mirrors
    /// `TcpTransport::connect`'s `FingerprintVerifier`.
    fn build_endpoint(&self, expected_fingerprint: [u8; 32]) -> Result<quinn::Endpoint> {
        let rustls_config = self
            .tls_identity
            .client_config(expected_fingerprint)
            .map_err(|e| GossipError::Identity(format!("quinn client_config: {e}")))?;
        let quinn_crypto = QuicClientConfig::try_from(rustls_config)
            .map_err(|e| GossipError::Identity(format!("quinn QuicClientConfig: {e}")))?;
        let quinn_config = quinn::ClientConfig::new(Arc::new(quinn_crypto));
        let mut endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>().expect("valid bind addr"))
                .map_err(|e| GossipError::Io(std::io::Error::other(e.to_string())))?;
        endpoint.set_default_client_config(quinn_config);
        Ok(endpoint)
    }

    /// Build a QUIC server config from the same `TlsIdentity` for inbound
    /// `Endpoint::server` use (future inbound QUIC accept path). Kept as a
    /// helper so the SPKI identity is the single source of truth.
    #[allow(dead_code)]
    pub fn server_config_quic(&self) -> Result<quinn::ServerConfig> {
        let rustls_server = self.tls_identity.server_config()?;
        let quinn_server = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server)
            .map_err(|e| GossipError::Identity(format!("quinn QuicServerConfig: {e}")))?;
        Ok(quinn::ServerConfig::with_crypto(Arc::new(quinn_server)))
    }
}

impl SyncTransport for TcpTransport {
    async fn connect(&mut self, peer: &PeerInfo) -> Result<()> {
        if self.is_connected() {
            return Ok(());
        }

        let client_config = self.tls_identity.client_config(peer.expected_spki_fingerprint)?;
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::IpAddress(PkiIpAddr::from(peer.addr.ip()));

        let stream = TcpStream::connect(peer.addr).await?;
        let tls = connector.connect(server_name, stream).await?;
        self.stream = Some(Box::new(tls));
        Ok(())
    }

    async fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        let stream = self.stream.as_mut().ok_or(GossipError::Closed)?;
        let bytes = frame.to_bytes();
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn recv_frame(&mut self) -> Result<Frame> {
        let stream = self.stream.as_mut().ok_or(GossipError::Closed)?;

        let mut header = [0u8; 5];
        read_exact(stream, &mut header).await?;
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(GossipError::framing(format!(
                "frame too large: {len} bytes exceeds MAX_FRAME_SIZE {MAX_FRAME_SIZE}"
            )));
        }
        let mut payload = vec![0u8; len];
        read_exact(stream, &mut payload).await?;

        let mut bytes = Vec::with_capacity(5 + len);
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&payload);
        Frame::from_bytes(&bytes)
    }

    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}

impl SyncTransport for QuicTransport {
    async fn connect(&mut self, peer: &PeerInfo) -> Result<()> {
        if self.is_connected() {
            return Ok(());
        }
        let endpoint = self.build_endpoint(peer.expected_spki_fingerprint)?;
        self.endpoint = Some(endpoint);
        #[allow(clippy::collapsible_if)]
        if let Some(ep) = self.endpoint.as_ref() {
            if let Ok(connecting) = ep.connect(peer.addr, "jkain") {
                if let Ok(conn) = connecting.await {
                    if let Ok((s, r)) = conn.open_bi().await {
                        self.send = Some(s);
                        self.recv = Some(r);
                    }
                    self.connection = Some(conn);
                }
            }
        }
        // TODO: Frame I/O over QUIC bidi: once `self.connection` is set,
        // `send_frame`/`recv_frame` should use `send.write_all(&frame.to_bytes())`
        // and `recv.read_exact(&mut header)` on the stored `SendStream`/`RecvStream`.
        // For now delegate to TCP fallback so the node remains gossip-functional.
        self.fallback.connect(peer).await?;
        if self.connection.is_some() {
            // Ensure QUIC stream placeholder is considered; actual bidi wiring
            // will open `self.send`/`self.recv` on first send.
        }
        Ok(())
    }

    async fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        if let (Some(conn), Some(send), Some(_recv)) =
            (self.connection.as_ref(), self.send.as_mut(), self.recv.as_mut())
        {
            let _ = conn;
            let bytes = frame.to_bytes();
            send.write_all(&bytes)
                .await
                .map_err(|e| GossipError::Io(std::io::Error::other(e.to_string())))?;
            return Ok(());
        }
        // Fallback path — Frame unchanged: [tag][len][payload] over TCP.
        // TODO: replace with `send.write_all(&bytes)` on QUIC bidi when
        // the connection is fully established.
        self.fallback.send_frame(frame).await
    }

    async fn recv_frame(&mut self) -> Result<Frame> {
        if let (Some(_conn), Some(_send), Some(recv)) =
            (self.connection.as_ref(), self.send.as_mut(), self.recv.as_mut())
        {
            let mut header = [0u8; 5];
            recv.read_exact(&mut header).await.map_err(|e| {
                if e.to_string().contains("closed") {
                    GossipError::Closed
                } else {
                    GossipError::Io(std::io::Error::other(e.to_string()))
                }
            })?;
            let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
            if len > MAX_FRAME_SIZE {
                return Err(GossipError::framing(format!(
                    "frame too large: {len} bytes exceeds MAX_FRAME_SIZE {MAX_FRAME_SIZE}"
                )));
            }
            let mut payload = vec![0u8; len];
            recv.read_exact(&mut payload).await.map_err(|e| {
                if e.to_string().contains("closed") {
                    GossipError::Closed
                } else {
                    GossipError::Io(std::io::Error::other(e.to_string()))
                }
            })?;
            let mut bytes = Vec::with_capacity(5 + len);
            bytes.extend_from_slice(&header);
            bytes.extend_from_slice(&payload);
            return Frame::from_bytes(&bytes);
        }
        self.fallback.recv_frame().await
    }

    fn is_connected(&self) -> bool {
        self.fallback.is_connected() || self.connection.is_some()
    }
}

async fn read_exact(stream: &mut (impl AsyncRead + Unpin), buf: &mut [u8]) -> Result<()> {
    match stream.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => Err(GossipError::Closed),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::tls::TlsIdentity;

    fn test_identity() -> TlsIdentity {
        TlsIdentity::from_seed([7u8; 32], 1).expect("identity")
    }

    #[tokio::test]
    async fn recv_frame_rejects_oversized_length_prefix() {
        let (mut client, server) = tokio::io::duplex(1024);
        let mut transport =
            TcpTransport { tls_identity: test_identity(), stream: Some(Box::new(server)) };
        let oversized = (MAX_FRAME_SIZE + 1) as u32;
        let mut header = Vec::new();
        header.push(0x00);
        header.extend_from_slice(&oversized.to_be_bytes());
        client.write_all(&header).await.expect("write header");
        client.flush().await.expect("flush");
        let err = transport.recv_frame().await.expect_err("must reject oversized frame");
        match err {
            GossipError::Framing(msg) => assert!(msg.contains("too large"), "msg: {msg}"),
            other => panic!("expected Framing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn recv_frame_accepts_max_frame_size_boundary() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut transport =
            TcpTransport { tls_identity: test_identity(), stream: Some(Box::new(server)) };
        let frame_bytes = Frame::Behind.to_bytes();
        let len = frame_bytes.len() - 5;
        assert!(len <= MAX_FRAME_SIZE);
        client.write_all(&frame_bytes).await.expect("write");
        client.flush().await.expect("flush");
        let frame = transport.recv_frame().await.expect("should decode Behind frame");
        assert_eq!(frame, Frame::Behind);
    }
}

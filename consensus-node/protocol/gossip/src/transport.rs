// cfg(any(test,feature="tcp-fallback"))
#[cfg(any(test, feature = "tcp-fallback", debug_assertions))]
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::QuicClientConfig;
#[cfg(any(test, feature = "tcp-fallback", debug_assertions))]
use rustls::pki_types::{
    IpAddr as PkiIpAddr,
    ServerName,
};
use tokio::io::{
    AsyncRead,
    AsyncWrite,
};
#[cfg(any(test, feature = "tcp-fallback", debug_assertions))]
use tokio::io::{
    AsyncReadExt,
    AsyncWriteExt,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
#[cfg(any(test, feature = "tcp-fallback", debug_assertions))]
use tokio_rustls::TlsConnector;
use tokio_rustls::server::TlsStream as ServerTlsStream;

use crate::error::{
    GossipError,
    Result,
};
use crate::peer::PeerInfo;
use crate::proto::Frame;
use crate::tls::TlsIdentity;

#[allow(async_fn_in_trait)]
pub trait SyncTransport {
    async fn connect(&mut self, peer: &PeerInfo) -> Result<()>;
    async fn send_frame(&mut self, frame: &Frame) -> Result<()>;
    async fn recv_frame(&mut self) -> Result<Frame>;
    fn is_connected(&self) -> bool;
}

#[cfg(any(test, feature = "tcp-fallback", debug_assertions))]
pub struct TcpTransport {
    tls_identity: TlsIdentity,
    stream: Option<Box<dyn AsyncReadWrite + Unpin + Send>>,
}

#[cfg(any(test, feature = "tcp-fallback", debug_assertions))]
impl TcpTransport {
    pub fn new(tls_identity: TlsIdentity) -> Self {
        Self { tls_identity, stream: None }
    }
    pub fn from_tls_stream(tls_identity: TlsIdentity, stream: ServerTlsStream<TcpStream>) -> Self {
        Self { tls_identity, stream: Some(Box::new(stream)) }
    }
    pub fn acceptor(&self) -> Result<TlsAcceptor> {
        let config = self.tls_identity.server_config()?;
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// Maximum wire frame size (64 MiB). The length prefix is validated
/// before any allocation in `recv_frame` (`len > MAX_FRAME_SIZE` rejects
/// with a framing error), so a peer cannot force unbounded allocation.
/// Kept at 64 MiB to accommodate `ReconnectResponse` which carries the full
/// signed checkpoint plus retained graph; reducing to 4 MiB would break
/// reconnect of large retained windows. Per-sync byte budgets are enforced
/// at the application layer via `MAX_PENDING_TRANSACTIONS`.
const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

pub struct QuicTransport {
    tls_identity: TlsIdentity,
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
}

impl QuicTransport {
    pub fn new(tls_identity: TlsIdentity) -> Self {
        Self { tls_identity, endpoint: None, connection: None }
    }
    pub fn is_quic(&self) -> bool {
        true
    }
    pub fn endpoint(&self) -> Option<&quinn::Endpoint> {
        self.endpoint.as_ref()
    }
    pub fn connection(&self) -> Option<&quinn::Connection> {
        self.connection.as_ref()
    }
    fn build_endpoint(&self, expected_fingerprint: [u8; 32]) -> Result<quinn::Endpoint> {
        let rustls_config = self
            .tls_identity
            .client_config(expected_fingerprint)
            .map_err(|e| GossipError::Identity(format!("quinn client_config: {e}")))?;
        let quinn_crypto = QuicClientConfig::try_from(rustls_config)
            .map_err(|e| GossipError::Identity(format!("quinn QuicClientConfig: {e}")))?;
        let mut quinn_config = quinn::ClientConfig::new(Arc::new(quinn_crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(128));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        quinn_config.transport_config(Arc::new(transport));
        let mut endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>().expect("valid bind addr"))
                .map_err(|e| GossipError::Io(std::io::Error::other(e.to_string())))?;
        endpoint.set_default_client_config(quinn_config);
        Ok(endpoint)
    }
    #[allow(dead_code)]
    pub fn server_config_quic(&self) -> Result<quinn::ServerConfig> {
        let rustls_server = self.tls_identity.server_config()?;
        let quinn_server = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_server)
            .map_err(|e| GossipError::Identity(format!("quinn QuicServerConfig: {e}")))?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quinn_server));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(128));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        server_config.transport = Arc::new(transport);
        Ok(server_config)
    }
    pub fn acceptor(&self) -> Result<TlsAcceptor> {
        let config = self.tls_identity.server_config()?;
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
    pub fn from_tls_stream(tls_identity: TlsIdentity, _stream: ServerTlsStream<TcpStream>) -> Self {
        Self { tls_identity, endpoint: None, connection: None }
    }
}

#[cfg(any(test, feature = "tcp-fallback", debug_assertions))]
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
        let bytes = frame.to_bytes()?;
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
        let connecting = endpoint
            .connect(peer.addr, "jkain")
            .map_err(|e| GossipError::Io(std::io::Error::other(e.to_string())))?;
        let connection =
            connecting.await.map_err(|e| GossipError::Io(std::io::Error::other(e.to_string())))?;
        self.endpoint = Some(endpoint);
        self.connection = Some(connection);
        Ok(())
    }
    async fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        // M-2: one bidi stream per frame is kept for now for wire-format
        // compatibility with the TCP fallback. Stream reuse per peer would
        // avoid churn; budget is set via TransportConfig::max_concurrent_bidi_streams.
        let conn = self.connection.as_ref().ok_or(GossipError::Closed)?.clone();
        let (mut send, _recv) = conn
            .open_bi()
            .await
            .map_err(|e| GossipError::Io(std::io::Error::other(e.to_string())))?;
        let bytes = frame.to_bytes()?;
        send.write_all(&bytes)
            .await
            .map_err(|e| GossipError::Io(std::io::Error::other(e.to_string())))?;
        send.finish().map_err(|e| GossipError::Io(std::io::Error::other(e.to_string())))?;
        Ok(())
    }
    async fn recv_frame(&mut self) -> Result<Frame> {
        let conn = self.connection.as_ref().ok_or(GossipError::Closed)?.clone();
        let (_send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| GossipError::Io(std::io::Error::other(e.to_string())))?;
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
        Frame::from_bytes(&bytes)
    }
    fn is_connected(&self) -> bool {
        self.connection.as_ref().is_some_and(|c| c.close_reason().is_none())
    }
}

#[cfg(any(test, feature = "tcp-fallback", debug_assertions))]
pub type DefaultTransport = TcpTransport;
#[cfg(not(any(test, feature = "tcp-fallback", debug_assertions)))]
pub type DefaultTransport = QuicTransport;

#[cfg(not(any(test, feature = "tcp-fallback", debug_assertions)))]
pub type TcpTransport = QuicTransport;

#[cfg(any(test, feature = "tcp-fallback", debug_assertions))]
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
        let frame_bytes = Frame::Behind.to_bytes().expect("Behind frame must encode");
        let len = frame_bytes.len() - 5;
        assert!(len <= MAX_FRAME_SIZE);
        client.write_all(&frame_bytes).await.expect("write");
        client.flush().await.expect("flush");
        let frame = transport.recv_frame().await.expect("should decode Behind frame");
        assert_eq!(frame, Frame::Behind);
    }
}

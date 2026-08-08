use std::io::ErrorKind;
use std::sync::Arc;

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

async fn read_exact(stream: &mut (impl AsyncRead + Unpin), buf: &mut [u8]) -> Result<()> {
    match stream.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => Err(GossipError::Closed),
        Err(e) => Err(e.into()),
    }
}

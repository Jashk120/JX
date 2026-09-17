use std::io::ErrorKind;
#[allow(unused_imports)]
use std::net::SocketAddr;
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

#[allow(async_fn_in_trait)]
pub trait SyncTransport {
    async fn connect(&mut self, peer: &PeerInfo) -> Result<()>;
    async fn send_frame(&mut self, frame: &Frame) -> Result<()>;
    async fn recv_frame(&mut self) -> Result<Frame>;
    fn is_connected(&self) -> bool;
}

pub struct TcpTransport {
    tls_identity: TlsIdentity,
    stream: Option<Box<dyn AsyncReadWrite + Unpin + Send>>,
}

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
pub(crate) const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

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

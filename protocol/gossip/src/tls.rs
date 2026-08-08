use std::sync::Arc;

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use rcgen::{
    CertificateParams,
    DistinguishedName,
    DnType,
    IsCa,
    KeyPair,
    SanType,
};
use rustls::client::danger::{
    HandshakeSignatureValid,
    ServerCertVerified,
    ServerCertVerifier,
};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    CertificateDer,
    PrivateKeyDer,
    PrivatePkcs8KeyDer,
    ServerName,
    UnixTime,
};
use rustls::{
    ClientConfig,
    DigitallySignedStruct,
    Error,
    ServerConfig,
    SignatureScheme,
};
use sha2::{
    Digest,
    Sha256,
};
use x509_parser::parse_x509_certificate;

use crate::error::GossipError;

/// A node's TLS identity.
///
/// The raw Ed25519 seed is the durable secret (persisted like the consensus
/// signing key); the X.509 certificate is regenerated from it on every
/// startup and is disposable. The SPKI fingerprint is what peers pin to,
/// and since it is derived purely from the key, it is stable across cert
/// regenerations.
#[derive(Clone)]
pub struct TlsIdentity {
    cert_der: CertificateDer<'static>,
    key_pkcs8: Vec<u8>,
    spki_fingerprint: [u8; 32],
}

impl TlsIdentity {
    /// Builds a TLS identity from a 32-byte Ed25519 seed, wrapping it in a
    /// fresh self-signed certificate with a `node-{node_id}` SAN.
    pub fn from_seed(seed: [u8; 32], node_id: u64) -> crate::Result<Self> {
        let signing_key = SigningKey::from_bytes(&seed);
        let pkcs8 = signing_key
            .to_pkcs8_der()
            .map_err(|e| GossipError::Identity(format!("key to PKCS#8: {e}")))?;
        let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec()),
            &rcgen::PKCS_ED25519,
        )
        .map_err(|e| GossipError::Identity(format!("pkcs8 to rcgen keypair: {e}")))?;

        let mut params = CertificateParams::new(Vec::new())
            .map_err(|e| GossipError::Identity(format!("cert params: {e}")))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("node-{node_id}"));
        params.distinguished_name = dn;
        let san = format!("node-{node_id}")
            .try_into()
            .map_err(|e: rcgen::Error| GossipError::Identity(format!("san: {e}")))?;
        params.subject_alt_names = vec![SanType::DnsName(san)];
        params.is_ca = IsCa::NoCa;

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| GossipError::Identity(format!("self-sign: {e}")))?;

        let cert_der = cert.der().clone();
        let key_pkcs8 = key_pair.serialize_der();
        let spki_fingerprint = Self::spki_fingerprint_of(&cert_der)?;

        Ok(Self { cert_der, key_pkcs8, spki_fingerprint })
    }

    pub fn spki_fingerprint(&self) -> [u8; 32] {
        self.spki_fingerprint
    }

    /// SHA-256 of the certificate's subject public key info (SPKI) DER.
    pub fn spki_fingerprint_of(cert: &CertificateDer<'_>) -> crate::Result<[u8; 32]> {
        let (_, parsed) = parse_x509_certificate(cert.as_ref())
            .map_err(|e| GossipError::CertificateVerification(format!("parse cert: {e}")))?;
        let spki = parsed.public_key().raw;
        Ok(Sha256::digest(spki).into())
    }

    /// A server config that presents this identity to connecting clients.
    pub fn server_config(&self) -> crate::Result<ServerConfig> {
        let provider = rustls::crypto::ring::default_provider();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pkcs8.clone()));
        ServerConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .map_err(|e| GossipError::Identity(format!("protocol versions: {e}")))?
            .with_no_client_auth()
            .with_single_cert(vec![self.cert_der.clone()], key_der)
            .map_err(|e| GossipError::Identity(format!("single cert: {e}")))
    }

    /// A client config that pins the server to `expected_fingerprint`'s
    /// SPKI, independent of any certificate chain.
    pub fn client_config(&self, expected_fingerprint: [u8; 32]) -> crate::Result<ClientConfig> {
        let provider = rustls::crypto::ring::default_provider();
        let verifier = Arc::new(FingerprintVerifier {
            expected: expected_fingerprint,
            algorithms: provider.signature_verification_algorithms,
        });
        Ok(ClientConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .map_err(|e| GossipError::Identity(format!("protocol versions: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth())
    }
}

/// A `ServerCertVerifier` that accepts a server only if its end-entity
/// cert's SPKI fingerprint matches the pinned value. All chain/signature
/// checks still run; the pin is the decisive criterion.
#[derive(Debug)]
struct FingerprintVerifier {
    expected: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let actual = TlsIdentity::spki_fingerprint_of(end_entity)
            .map_err(|_| Error::General("cannot parse server certificate".into()))?;
        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("server certificate SPKI fingerprint mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(seed_byte: u8) -> TlsIdentity {
        TlsIdentity::from_seed([seed_byte; 32], 1).expect("identity builds")
    }

    #[test]
    fn fingerprint_is_stable_across_regeneration() {
        let a = test_identity(7);
        let b = test_identity(7);
        assert_eq!(a.spki_fingerprint(), b.spki_fingerprint());
    }

    #[test]
    fn different_seeds_give_different_fingerprints() {
        let a = test_identity(1);
        let b = test_identity(2);
        assert_ne!(a.spki_fingerprint(), b.spki_fingerprint());
    }

    #[test]
    fn fingerprint_matches_own_cert() {
        let identity = test_identity(9);
        let computed = TlsIdentity::spki_fingerprint_of(&identity.cert_der).unwrap();
        assert_eq!(computed, identity.spki_fingerprint());
    }

    #[test]
    fn server_and_client_configs_build() {
        let identity = test_identity(3);
        assert!(identity.server_config().is_ok());
        assert!(identity.client_config(identity.spki_fingerprint()).is_ok());
    }
}

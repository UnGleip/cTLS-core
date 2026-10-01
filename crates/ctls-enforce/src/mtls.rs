//! Internal mTLS for the local admin channel (localhost only) — Phase 1
//! hardening: no admin endpoint is reachable without a client certificate
//! issued by the internal CA, and clients pin the server leaf's SPKI.
//!
//! - One internal CA is generated on first use; its private key is *sealed*
//!   with the Vault master key (TPM/DPAPI-backed) — no raw key material on
//!   disk. The public CA cert lives next to it as `ca.crt.der`.
//! - Leaf certificates are short-lived (gateway leaf: 1 day, status client
//!   leaf: 1 hour) and re-issued per run.
//! - The gateway writes the served leaf's SPKI pin to
//!   `internal-ca/admin.spki.sha256`; `ctls gateway status` pins against it.

use crate::ensure_crypto_provider;
use ctls_core::spki_sha256_hex;
use ctls_vault::Vault;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum MtlsError {
    #[error("vault: {0}")]
    Vault(String),
    #[error("internal ca: {0}")]
    Ca(String),
    #[error("tls config: {0}")]
    Tls(String),
    #[error("pin: {0}")]
    Pin(String),
    #[error("handshake: {0}")]
    Handshake(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

const CA_DIR: &str = "internal-ca";
const CA_CERT_FILE: &str = "ca.crt.der";
const CA_KEY_FILE: &str = "ca.key.sealed";
const PIN_FILE: &str = "admin.spki.sha256";
const CA_COMMON_NAME: &str = "cTLS Internal CA";

fn ca_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(CA_DIR)
}

fn pin_path(data_dir: &Path) -> PathBuf {
    ca_dir(data_dir).join(PIN_FILE)
}

/// Fixed CA parameters — identical at creation time and on every reload, so
/// the issuer DN used for new leaves always matches the stored CA cert.
fn ca_params() -> Result<rcgen::CertificateParams, MtlsError> {
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new())
        .map_err(|e| MtlsError::Ca(e.to_string()))?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, CA_COMMON_NAME);
    p.distinguished_name = dn;
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    p.not_before = rcgen::date_time_ymd(2024, 1, 1);
    p.not_after = rcgen::date_time_ymd(2044, 1, 1);
    p.use_authority_key_identifier_extension = false;
    Ok(p)
}

fn leaf_params(cn: &str, ttl: Duration) -> Result<rcgen::CertificateParams, MtlsError> {
    let mut p = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|e| MtlsError::Ca(e.to_string()))?;
    p.subject_alt_names
        .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    p.distinguished_name = dn;
    p.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::minutes(5);
    p.not_after = now + time::Duration::seconds(ttl.as_secs() as i64);
    p.use_authority_key_identifier_extension = true;
    Ok(p)
}

/// A short-lived leaf identity (cert + PKCS#8 key).
pub struct LeafId {
    pub cert_der: Vec<u8>,
    pub key_pkcs8: Vec<u8>,
}

/// The local internal CA used to secure the admin channel.
pub struct InternalCa {
    ca_key: rcgen::KeyPair,
    ca_der: Vec<u8>,
    data_dir: PathBuf,
}

impl InternalCa {
    /// Load the internal CA from `data_dir`, generating it on first use.
    /// The CA private key is sealed with the Vault master key.
    pub fn load_or_generate(data_dir: &Path, vault: &Vault) -> Result<Self, MtlsError> {
        let dir = ca_dir(data_dir);
        std::fs::create_dir_all(&dir)?;
        harden_dir(&dir)?;
        let sealed_path = dir.join(CA_KEY_FILE);
        let cert_path = dir.join(CA_CERT_FILE);

        if sealed_path.exists() && cert_path.exists() {
            let sealed = std::fs::read(&sealed_path)?;
            let key_pkcs8 = Zeroizing::new(
                vault
                    .unseal(&sealed)
                    .map_err(|e| MtlsError::Vault(e.to_string()))?,
            );
            let ca_key = rcgen::KeyPair::try_from(key_pkcs8.as_slice())
                .map_err(|e| MtlsError::Ca(format!("load sealed CA key: {e}")))?;
            let ca_der = std::fs::read(&cert_path)?;
            return Ok(Self {
                ca_key,
                ca_der,
                data_dir: data_dir.to_path_buf(),
            });
        }

        // First use (or partial state): generate and seal.
        let ca_key = rcgen::KeyPair::generate().map_err(|e| MtlsError::Ca(e.to_string()))?;
        let cert = ca_params()?
            .self_signed(&ca_key)
            .map_err(|e| MtlsError::Ca(e.to_string()))?;
        let ca_der = cert.der().to_vec();
        let key_der = Zeroizing::new(ca_key.serialize_der());
        let sealed = vault
            .seal(&key_der)
            .map_err(|e| MtlsError::Vault(e.to_string()))?;
        std::fs::write(&sealed_path, sealed)?;
        harden_file(&sealed_path)?;
        std::fs::write(&cert_path, &ca_der)?;
        Ok(Self {
            ca_key,
            ca_der,
            data_dir: data_dir.to_path_buf(),
        })
    }

    pub fn ca_der(&self) -> &[u8] {
        &self.ca_der
    }

    /// Issue a short-lived localhost leaf (usable as client *and* server).
    pub fn issue_leaf(&self, cn: &str, ttl: Duration) -> Result<LeafId, MtlsError> {
        let issuer = rcgen::Issuer::new(ca_params()?, &self.ca_key);
        let key = rcgen::KeyPair::generate().map_err(|e| MtlsError::Ca(e.to_string()))?;
        let cert = leaf_params(cn, ttl)?
            .signed_by(&key, &issuer)
            .map_err(|e| MtlsError::Ca(e.to_string()))?;
        Ok(LeafId {
            cert_der: cert.der().to_vec(),
            key_pkcs8: key.serialize_der(),
        })
    }

    /// Record the SPKI pin of the leaf the gateway is about to serve.
    /// Clients (`ctls gateway status`) pin against this file.
    pub fn write_pin_file(&self, leaf_cert_der: &[u8]) -> Result<String, MtlsError> {
        let pin = spki_sha256_hex(leaf_cert_der).map_err(|e| MtlsError::Ca(e.to_string()))?;
        std::fs::write(pin_path(&self.data_dir), format!("{pin}\n"))?;
        Ok(pin)
    }

    pub fn read_pin_file(data_dir: &Path) -> Result<String, MtlsError> {
        let raw = std::fs::read_to_string(pin_path(data_dir)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                MtlsError::Pin(
                    "pin file missing — is `ctls gateway` running on this data dir?".into(),
                )
            } else {
                MtlsError::Io(e)
            }
        })?;
        Ok(raw.trim().to_string())
    }

    /// Shortened pin for human display (first 16 hex chars).
    pub fn pin_summary(data_dir: &Path) -> Result<String, MtlsError> {
        let pin = Self::read_pin_file(data_dir)?;
        Ok(format!("{}..", &pin[..16.min(pin.len())]))
    }

    fn root_store(&self) -> Result<RootCertStore, MtlsError> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.ca_der.clone()))
            .map_err(|e| MtlsError::Tls(e.to_string()))?;
        Ok(roots)
    }
}

/// The admin endpoint's TLS server side: built once when the gateway starts.
pub struct AdminChannel {
    pub listen: String,
    acceptor: TlsAcceptor,
    status_json: Arc<String>,
}

impl AdminChannel {
    /// Issue the gateway's admin leaf, write its SPKI pin and build the
    /// mTLS server config (clients must present a cert from the internal CA).
    pub fn prepare(
        listen: &str,
        data_dir: &Path,
        vault: &Vault,
        status_json: String,
    ) -> Result<Self, MtlsError> {
        ensure_crypto_provider();
        let ca = InternalCa::load_or_generate(data_dir, vault)?;
        let leaf = ca.issue_leaf("ctls-gateway-admin", Duration::from_secs(24 * 3600))?;
        ca.write_pin_file(&leaf.cert_der)?;

        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(ca.root_store()?))
            .build()
            .map_err(|e| MtlsError::Tls(format!("client verifier: {e}")))?;
        let server_config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![CertificateDer::from(leaf.cert_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key_pkcs8)),
            )
            .map_err(|e| MtlsError::Tls(e.to_string()))?;
        Ok(Self {
            listen: listen.to_string(),
            acceptor: TlsAcceptor::from(Arc::new(server_config)),
            status_json: Arc::new(status_json),
        })
    }

    /// Accept one admin connection (called from the gateway accept loop).
    pub async fn handle(&self, sock: TcpStream) -> Result<(), MtlsError> {
        let tls = self
            .acceptor
            .accept(sock)
            .await
            .map_err(|e| MtlsError::Handshake(e.to_string()))?;
        respond(tls, &self.status_json).await
    }
}

/// Minimal HTTP/1.1 responder: `GET /status` → the pre-built JSON, else 404.
async fn respond<S>(
    mut tls: tokio_rustls::server::TlsStream<S>,
    status_json: &str,
) -> Result<(), MtlsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .map_err(|_| MtlsError::Handshake("admin request timeout".into()))??;
    let req = String::from_utf8_lossy(&buf[..n]);
    let (status_line, body) = if req.starts_with("GET /status ") || req.starts_with("GET /status\r")
    {
        ("200 OK", status_json.to_string())
    } else {
        ("404 Not Found", "{}".to_string())
    };
    let resp = format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(resp.as_bytes()).await?;
    let _ = tls.shutdown().await;
    Ok(())
}

/// Client side of the admin channel: mTLS + SPKI pin check. Returns the raw
/// JSON body from `GET /status`.
pub async fn fetch_admin_status(
    addr: &str,
    data_dir: &Path,
    vault: &Vault,
) -> Result<String, MtlsError> {
    ensure_crypto_provider();
    let timeout = Duration::from_secs(10);
    tokio::time::timeout(timeout, fetch_inner(addr, data_dir, vault))
        .await
        .map_err(|_| MtlsError::Handshake("admin status request timed out".into()))?
}

async fn fetch_inner(addr: &str, data_dir: &Path, vault: &Vault) -> Result<String, MtlsError> {
    let expected_pin = InternalCa::read_pin_file(data_dir)?;
    let ca = InternalCa::load_or_generate(data_dir, vault)?;
    let client_leaf = ca.issue_leaf("ctls-status-client", Duration::from_secs(3600))?;

    let config = ClientConfig::builder()
        .with_root_certificates(ca.root_store()?)
        .with_client_auth_cert(
            vec![CertificateDer::from(client_leaf.cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_leaf.key_pkcs8)),
        )
        .map_err(|e| MtlsError::Tls(e.to_string()))?;
    let connector = TlsConnector::from(Arc::new(config));

    let sock = TcpStream::connect(addr).await?;
    let server_name =
        ServerName::try_from("localhost").map_err(|e| MtlsError::Tls(e.to_string()))?;
    let mut tls = connector
        .connect(server_name, sock)
        .await
        .map_err(|e| MtlsError::Handshake(e.to_string()))?;

    // Pin the served leaf's SPKI — a different gateway identity is refused.
    let peer = tls
        .get_ref()
        .1
        .peer_certificates()
        .ok_or_else(|| MtlsError::Pin("no peer certificate".into()))?;
    let actual_pin = spki_sha256_hex(
        peer.first()
            .ok_or_else(|| MtlsError::Pin("empty chain".into()))?
            .as_ref(),
    )
    .map_err(|e| MtlsError::Ca(e.to_string()))?;
    if !actual_pin.eq_ignore_ascii_case(&expected_pin) {
        return Err(MtlsError::Pin(format!(
            "server SPKI pin mismatch (expected {expected_pin}, got {actual_pin})"
        )));
    }

    tls.write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut body = Vec::new();
    tls.read_to_end(&mut body).await?;
    let text = String::from_utf8_lossy(&body);
    let json = text
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| MtlsError::Handshake("malformed HTTP response".into()))?;
    Ok(json.to_string())
}

#[cfg(unix)]
fn harden_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(unix)]
fn harden_file(file: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn harden_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn harden_file(_file: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ctls_vault::Vault;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ctls_mtls_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ca_generation_is_stable_across_loads() {
        let dir = temp_dir("ca");
        let vault = Vault::open(dir.join("vault.db")).unwrap();
        let ca1 = InternalCa::load_or_generate(&dir, &vault).unwrap();
        let ca2 = InternalCa::load_or_generate(&dir, &vault).unwrap();
        assert_eq!(ca1.ca_der(), ca2.ca_der());
        // sealed key exists, raw key does not
        assert!(dir.join(CA_DIR).join(CA_KEY_FILE).exists());
        assert!(!dir.join(CA_DIR).join("ca.key").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn issued_leaf_parses_and_pins() {
        let dir = temp_dir("leaf");
        let vault = Vault::open(dir.join("vault.db")).unwrap();
        let ca = InternalCa::load_or_generate(&dir, &vault).unwrap();
        let leaf = ca.issue_leaf("localhost", Duration::from_secs(60)).unwrap();
        let rec = ctls_core::parse_der_bytes(&leaf.cert_der).unwrap();
        assert!(rec.subject.contains("localhost"), "{}", rec.subject);
        let pin1 = ca.write_pin_file(&leaf.cert_der).unwrap();
        let pin2 = InternalCa::read_pin_file(&dir).unwrap();
        assert_eq!(pin1, pin2);
        assert_eq!(pin1.len(), 64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Full admin handshake: mTLS server (client cert required) + pinned
    /// client over a real localhost socket.
    #[tokio::test]
    async fn admin_status_roundtrip_with_pin() {
        let dir = temp_dir("roundtrip");
        let vault = Vault::open(dir.join("vault.db")).unwrap();
        let status = r#"{"status":"running","allowed":3}"#.to_string();
        let channel = AdminChannel::prepare("127.0.0.1:0", &dir, &vault, status.clone()).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            channel.handle(sock).await.unwrap();
        });

        let body = fetch_admin_status(&addr.to_string(), &dir, &vault)
            .await
            .unwrap();
        assert_eq!(body, status);
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tampered SPKI pin file must make the client refuse the server
    /// even though the handshake itself is valid.
    #[tokio::test]
    async fn pin_mismatch_is_rejected() {
        let dir = temp_dir("pinbad");
        let vault = Vault::open(dir.join("vault.db")).unwrap();
        let channel = AdminChannel::prepare("127.0.0.1:0", &dir, &vault, "{}".to_string()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = channel.handle(sock).await;
        });
        std::fs::write(
            pin_path(&dir),
            "0000000000000000000000000000000000000000000000000000000000000000\n",
        )
        .unwrap();
        let err = fetch_admin_status(&addr.to_string(), &dir, &vault)
            .await
            .unwrap_err();
        assert!(
            matches!(err, MtlsError::Pin(_)),
            "expected pin error, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A client without a certificate must be rejected (mutual TLS).
    #[tokio::test]
    async fn client_without_cert_is_rejected() {
        let dir = temp_dir("nocert");
        let vault = Vault::open(dir.join("vault.db")).unwrap();
        let status = "{}".to_string();
        let channel = AdminChannel::prepare("127.0.0.1:0", &dir, &vault, status).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            channel.handle(sock).await
        });

        let ca = InternalCa::load_or_generate(&dir, &vault).unwrap();
        let config = ClientConfig::builder()
            .with_root_certificates(ca.root_store().unwrap())
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let sock = TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();
        // In TLS 1.3 the client may finish its side before the server rejects
        // the missing certificate — the authoritative check is the server.
        if let Ok(mut tls) = connector.connect(server_name, sock).await {
            let mut buf = [0u8; 64];
            let _ = tls.read(&mut buf).await;
        }
        let server_result = server.await.unwrap();
        assert!(
            server_result.is_err(),
            "server must reject a cert-less client"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! ctls-enforce — local TLS verify-proxy (splice mode) + helpers.
//!
//! Design:
//! - HTTP CONNECT proxy on 127.0.0.1
//! - For each CONNECT: open a *separate* rustls client connection to target
//!   and validate its chain and hostname against allowed Vault roots.
//! - If allowed: raw TCP splice between app and a *fresh* connection to target
//!   (bytes are never decrypted — no MITM of content).
//! - If denied: close both sides.
//!
//! The data connection can present a different certificate, so preflight
//! cannot enforce trust for the application's actual handshake.

pub mod mtls;

use ctls_vault::Vault;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault: {0}")]
    Vault(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("denied: {0}")]
    Denied(String),
    #[error("mtls: {0}")]
    Mtls(#[from] mtls::MtlsError),
}

/// Localhost admin endpoint configuration (mTLS-protected).
#[derive(Clone)]
pub struct AdminConfig {
    pub listen: String,
    pub data_dir: std::path::PathBuf,
}

pub struct GatewayConfig {
    pub listen: String,
    pub admin: Option<AdminConfig>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:18080".into(),
            admin: None,
        }
    }
}

#[derive(Clone)]
struct VaultTrust {
    roots: Arc<rustls::RootCertStore>,
}

pub struct Gateway {
    cfg: GatewayConfig,
    trust: VaultTrust,
    admin: Option<Arc<mtls::AdminChannel>>,
}

impl Gateway {
    pub fn from_vault(vault: &Vault, cfg: GatewayConfig) -> Result<Self, GatewayError> {
        let fingerprints = vault
            .allowed_fingerprints()
            .map_err(|e| GatewayError::Vault(e.to_string()))?;
        let mut roots = rustls::RootCertStore::empty();
        for fingerprint in &fingerprints {
            let der = vault
                .get_der_by_sha1(fingerprint)
                .map_err(|e| GatewayError::Vault(e.to_string()))?;
            roots
                .add(rustls::pki_types::CertificateDer::from(der))
                .map_err(|e| GatewayError::Tls(format!("invalid allowed CA {fingerprint}: {e}")))?;
        }

        let admin = match &cfg.admin {
            Some(a) => {
                let allowed = fingerprints.len();
                let quarantined = vault
                    .quarantined_fingerprints()
                    .map_err(|e| GatewayError::Vault(e.to_string()))?
                    .len();
                let total = vault
                    .count()
                    .map_err(|e| GatewayError::Vault(e.to_string()))?;
                let status_json = format!(
                    "{{\"status\":\"running\",\"proxy_listen\":\"{}\",\"admin_listen\":\"{}\",\"mtls\":\"internal-ca-v1\",\"allowed\":{},\"quarantined\":{},\"total\":{},\"key_backend\":\"{}\"}}",
                    cfg.listen,
                    a.listen,
                    allowed,
                    quarantined,
                    total,
                    vault.key_backend_name(),
                );
                Some(Arc::new(mtls::AdminChannel::prepare(
                    &a.listen,
                    &a.data_dir,
                    vault,
                    status_json,
                )?))
            }
            None => None,
        };

        Ok(Self {
            cfg,
            trust: VaultTrust {
                roots: Arc::new(roots),
            },
            admin,
        })
    }

    pub fn listen_addr(&self) -> &str {
        &self.cfg.listen
    }

    pub fn admin_addr(&self) -> Option<&str> {
        self.admin.as_ref().map(|a| a.listen.as_str())
    }

    pub async fn run(self) -> Result<(), GatewayError> {
        self.run_with_shutdown(std::future::pending::<()>()).await
    }

    pub async fn run_with_shutdown<F>(self, shutdown: F) -> Result<(), GatewayError>
    where
        F: std::future::Future<Output = ()>,
    {
        ensure_crypto_provider();
        let listener = TcpListener::bind(&self.cfg.listen).await?;
        let admin_listener = match &self.admin {
            Some(a) => Some(TcpListener::bind(&a.listen).await?),
            None => None,
        };
        let admin = self.admin;
        let trust = Arc::new(self.trust);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                accepted = listener.accept() => {
                    let (sock, _) = accepted?;
                    let trust = trust.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(sock, trust).await {
                            eprintln!("[gateway] connection error: {e}");
                        }
                    });
                }
                accepted = async {
                    match &admin_listener {
                        Some(l) => l.accept().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match accepted {
                        Ok((sock, _)) => {
                            if let Some(channel) = admin.clone() {
                                tokio::spawn(async move {
                                    if let Err(e) = channel.handle(sock).await {
                                        eprintln!("[gateway] admin connection error: {e}");
                                    }
                                });
                            }
                        }
                        Err(e) => eprintln!("[gateway] admin accept error: {e}"),
                    }
                }
            }
        }
    }
}

/// Feature unification may enable both `ring` and `aws-lc-rs` (reqwest +
/// tokio-rustls), so rustls cannot auto-select a provider. Pick `ring` once.
fn ensure_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

async fn handle_client(mut client: TcpStream, trust: Arc<VaultTrust>) -> Result<(), GatewayError> {
    // Read HTTP CONNECT request headers (preserve any bytes after the header
    // terminator — clients often pipeline the TLS ClientHello).
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];
    let header_end = loop {
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > 16 * 1024 {
            return Ok(());
        }
    };
    let text = String::from_utf8_lossy(&buf[..header_end]);
    let first = text.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") || target.is_empty() {
        let _ = client
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            .await;
        return Ok(());
    }
    // Bytes after `\r\n\r\n` belong to the tunneled stream.
    let preamble = buf[header_end + 4..].to_vec();

    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(443)),
        None => (target.to_string(), 443u16),
    };

    // 1) Verification connection: grab peer cert chain against Vault
    match verify_server(&host, port, &trust).await {
        Ok(()) => {}
        Err(e) => {
            let msg = format!(
                "HTTP/1.1 502 cTLS denied: {}\r\nConnection: close\r\n\r\n",
                e
            );
            let _ = client.write_all(msg.as_bytes()).await;
            let _ = client.shutdown().await;
            return Ok(());
        }
    }

    // 2) Splice: open real data connection and pipe raw bytes both ways
    let server = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            let msg = format!(
                "HTTP/1.1 502 cTLS upstream connect failed: {e}\r\nConnection: close\r\n\r\n"
            );
            let _ = client.write_all(msg.as_bytes()).await;
            let _ = client.shutdown().await;
            return Ok(());
        }
    };
    let _ = client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await;

    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();

    // Replay any bytes that arrived immediately after the CONNECT headers.
    if !preamble.is_empty() && sw.write_all(&preamble).await.is_err() {
        return Ok(());
    }

    let c2s = tokio::spawn(async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = sw.shutdown().await;
    });
    let s2c = tokio::spawn(async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match sr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if cw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = cw.shutdown().await;
    });
    let _ = c2s.await;
    let _ = s2c.await;
    Ok(())
}

/// Validate a preflight TLS connection with hostname and certificate chain
/// checks against the explicitly allowed CA certificates in the Vault.
async fn verify_server(host: &str, port: u16, trust: &VaultTrust) -> Result<(), GatewayError> {
    use rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    ensure_crypto_provider();

    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(trust.roots.clone())
            .with_no_client_auth(),
    );
    let connector = TlsConnector::from(config);

    let sock = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    .map_err(|_| GatewayError::Tls("preflight connection timed out".into()))??;

    let server_name =
        ServerName::try_from(host.to_string()).map_err(|e| GatewayError::Tls(e.to_string()))?;

    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        connector.connect(server_name, sock),
    )
    .await
    .map_err(|_| GatewayError::Tls("preflight handshake timed out".into()))?
    .map_err(|e| GatewayError::Denied(format!("certificate verification failed: {e}")))?;
    Ok(())
}

/// Helper: enable Windows system proxy for WinINET apps (best-effort).
#[cfg(windows)]
pub fn enable_system_proxy(proxy: &str) -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu
        .create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        .map_err(|e| e.to_string())?;
    key.0
        .set_value("ProxyEnable", &1u32)
        .map_err(|e| e.to_string())?;
    let proxy_s = proxy.to_string();
    key.0
        .set_value("ProxyServer", &proxy_s)
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(windows)]
pub fn disable_system_proxy() -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu
        .open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            winreg::enums::KEY_WRITE,
        )
        .map_err(|e| e.to_string())?;
    key.set_value("ProxyEnable", &0u32)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Non-Windows: system proxy is configured by the desktop environment;
/// tell the user instead of silently doing nothing.
#[cfg(not(windows))]
pub fn enable_system_proxy(_proxy: &str) -> Result<(), String> {
    Err("system proxy toggle is Windows-only; export http_proxy/https_proxy instead".into())
}

#[cfg(not(windows))]
pub fn disable_system_proxy() -> Result<(), String> {
    // nothing was enabled by cTLS on this platform
    Ok(())
}

#[cfg(test)]
mod gateway_tests {
    use super::*;
    use ctls_core::CaRecord;

    #[test]
    fn invalid_allowed_certificate_fails_gateway_startup() {
        let dir = std::env::temp_dir().join(format!("ctls_gateway_invalid_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vault = Vault::open(dir.join("vault.db")).unwrap();
        let rec = CaRecord {
            subject: "CN=invalid".into(),
            issuer: "CN=invalid".into(),
            serial_hex: "01".into(),
            sha1_fingerprint: "aabb".into(),
            sha256_fingerprint: "ccdd".into(),
            not_before: "2024-01-01T00:00:00Z".into(),
            not_after: "2034-01-01T00:00:00Z".into(),
            is_ca: true,
            self_signed: true,
            signature_algorithm: "unknown".into(),
            public_key_algorithm: "unknown".into(),
            public_key_bits: 0,
            store_name: "test".into(),
            store_location: "local".into(),
            der_len: 3,
        };
        vault
            .add_with_status(&rec, b"bad", "SAFE", "test", Some("ALLOW"))
            .unwrap();
        assert!(Gateway::from_vault(&vault, GatewayConfig::default()).is_err());
        drop(vault);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

use ctls_core::{normalize_fingerprint, parse_der_ca, CaRecord};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::io::Read;

const MAX_DOWNLOAD_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(String),
    #[error("fingerprint mismatch: expected {expected}, got {actual}")]
    FingerprintMismatch { expected: String, actual: String },
    #[error("no certificates found on page")]
    Empty,
    #[error("url not allowed: {0}")]
    UrlNotAllowed(String),
    #[error("redirect blocked: {0}")]
    RedirectBlocked(String),
    #[error("download exceeds {MAX_DOWNLOAD_BYTES} bytes")]
    TooLarge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoCert {
    pub name: String,
    pub url: String,
    pub sha1_declared: String,
}

pub const RCA_BASE: &str = "https://rca.gov.ir";
pub const RCA_REPOSITORY_PAGE: &str = "https://rca.gov.ir/portal/?65";

/// Hosts always allowed for certificate downloads.
pub const DEFAULT_ALLOWED_HOSTS: &[&str] = &["rca.gov.ir", "www.rca.gov.ir"];

/// SSRF / open-redirect guard: https only + host allowlist.
pub fn validate_download_url(url: &str, extra_allowed: &[String]) -> Result<(), RepoError> {
    let parsed = reqwest::Url::parse(url).map_err(|e| RepoError::UrlNotAllowed(e.to_string()))?;
    if parsed.scheme() != "https" {
        return Err(RepoError::UrlNotAllowed(format!(
            "only https allowed, got {}",
            parsed.scheme()
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.port().is_some() {
        return Err(RepoError::UrlNotAllowed(
            "credentials and custom ports are not allowed".into(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| RepoError::UrlNotAllowed("missing host".into()))?
        .to_ascii_lowercase();
    let allowed = DEFAULT_ALLOWED_HOSTS
        .iter()
        .any(|h| host == *h || host.ends_with(&format!(".{h}")))
        || extra_allowed.iter().any(|h| {
            let h = h.to_ascii_lowercase();
            host == h || host.ends_with(&format!(".{h}"))
        });
    if !allowed {
        return Err(RepoError::UrlNotAllowed(host));
    }
    Ok(())
}

pub struct RcaClient {
    http: reqwest::blocking::Client,
    extra_allowed: Vec<String>,
}

impl RcaClient {
    pub fn new() -> Result<Self, RepoError> {
        Self::with_allowed_hosts(Vec::new())
    }

    /// Extra hosts (e.g. CCADB) on top of the default rca.gov.ir allowlist.
    pub fn with_allowed_hosts(extra_allowed_hosts: Vec<String>) -> Result<Self, RepoError> {
        let allowed: std::collections::HashSet<String> = extra_allowed_hosts
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .chain(DEFAULT_ALLOWED_HOSTS.iter().map(|s| s.to_string()))
            .collect();
        let redirect = reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() > 3 {
                return attempt.error("too many redirects");
            }
            let url = attempt.url();
            let host_ok = url.host_str().map(|h| {
                let h = h.to_ascii_lowercase();
                allowed.contains(&h) || allowed.iter().any(|a| h.ends_with(&format!(".{a}")))
            }) == Some(true);
            if url.scheme() != "https"
                || !host_ok
                || !url.username().is_empty()
                || url.password().is_some()
                || url.port().is_some()
            {
                attempt.error("redirect to non-allowed host/scheme")
            } else {
                attempt.follow()
            }
        });
        let http = reqwest::blocking::Client::builder()
            .user_agent("cTLS/0.1 (+certificate-vault)")
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .redirect(redirect)
            .build()?;
        Ok(Self {
            http,
            extra_allowed: extra_allowed_hosts,
        })
    }

    pub fn fetch_repository_page(&self) -> Result<String, RepoError> {
        let bytes = self.read_limited(self.http.get(RCA_REPOSITORY_PAGE).send()?)?;
        String::from_utf8(bytes).map_err(|e| RepoError::Parse(e.to_string()))
    }

    pub fn parse_repository_page(&self, html: &str) -> Result<Vec<RepoCert>, RepoError> {
        let document = Html::parse_document(html);
        let a_sel = Selector::parse("a").map_err(|e| RepoError::Parse(e.to_string()))?;
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for a in document.select(&a_sel) {
            let href = match a.value().attr("href") {
                Some(h) if h.contains("/Repository/") => h.to_string(),
                _ => continue,
            };
            let is_cert = href.ends_with(".crt")
                || href.ends_with(".p7b")
                || href.ends_with(".cer")
                || href.ends_with(".pem");
            if !is_cert {
                continue;
            }
            let name = a.text().collect::<String>().trim().to_string();
            let url = if href.starts_with("http") {
                href.clone()
            } else {
                format!("{RCA_BASE}/portal/{href}")
            };
            if seen.insert(url.clone()) {
                out.push(RepoCert {
                    name,
                    url,
                    sha1_declared: String::new(),
                });
            }
        }

        if out.is_empty() {
            return Err(RepoError::Empty);
        }
        Ok(out)
    }

    pub fn download(&self, url: &str) -> Result<Vec<u8>, RepoError> {
        validate_download_url(url, &self.extra_allowed)?;
        self.read_limited(self.http.get(url).send()?)
    }

    fn read_limited(
        &self,
        mut response: reqwest::blocking::Response,
    ) -> Result<Vec<u8>, RepoError> {
        response.error_for_status_ref()?;
        if response
            .content_length()
            .is_some_and(|n| n > MAX_DOWNLOAD_BYTES)
        {
            return Err(RepoError::TooLarge);
        }
        let mut bytes = Vec::new();
        response
            .by_ref()
            .take(MAX_DOWNLOAD_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
            return Err(RepoError::TooLarge);
        }
        Ok(bytes)
    }

    /// Download a cert (.crt/.pem/.p7b) and optionally verify SHA-1.
    /// Bundle files: first parseable certificate is returned.
    pub fn download_and_verify(
        &self,
        url: &str,
        expected_sha1: Option<&str>,
    ) -> Result<(CaRecord, Vec<u8>), RepoError> {
        let bytes = self.download(url)?;
        let ders =
            ctls_core::load_certificates(&bytes).map_err(|e| RepoError::Parse(e.to_string()))?;
        let mut last_err = RepoError::Parse("no parseable certificate".into());
        for der in ders {
            match parse_der_ca(&der, "repo", "rca.gov.ir") {
                Ok(rec) => {
                    if let Some(exp) = expected_sha1 {
                        let exp_n = normalize_fingerprint(exp);
                        let act_n = normalize_fingerprint(&rec.sha1_fingerprint);
                        if exp_n != act_n {
                            return Err(RepoError::FingerprintMismatch {
                                expected: exp_n,
                                actual: act_n,
                            });
                        }
                    }
                    return Ok((rec, der));
                }
                Err(e) => last_err = RepoError::Parse(e.to_string()),
            }
        }
        Err(last_err)
    }

    /// Parse SHA-1 table pairs from the repository HTML (name -> sha1) when present.
    pub fn parse_declared_fingerprints(&self, html: &str) -> Vec<(String, String)> {
        let document = Html::parse_document(html);
        let rows = Selector::parse("tr").ok();
        let Some(rows) = rows else { return vec![] };
        let mut out = Vec::new();
        for row in document.select(&rows) {
            let cells: Vec<String> = row
                .text()
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();
            for c in &cells {
                let hex = normalize_fingerprint(c);
                if hex.len() == 40 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    if let Some(name) = cells.first() {
                        if name != c {
                            out.push((name.clone(), hex));
                        }
                    }
                }
            }
        }
        out
    }
}

/// First certificate DER from PEM/DER bytes (compat wrapper).
pub fn pem_to_der(bytes: &[u8]) -> Option<Vec<u8>> {
    ctls_core::load_certificates(bytes).ok()?.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_roundtrip() {
        let pem = "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n";
        assert_eq!(pem_to_der(pem.as_bytes()).unwrap(), b"hello");
    }

    #[test]
    fn bundle_pem_splits() {
        let pem = "-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n\
                   -----BEGIN CERTIFICATE-----\nYg==\n-----END CERTIFICATE-----\n";
        let v = ctls_core::load_certificates(pem.as_bytes()).unwrap();
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn url_allowlist() {
        assert!(validate_download_url("https://rca.gov.ir/x.crt", &[]).is_ok());
        assert!(validate_download_url("http://rca.gov.ir/x.crt", &[]).is_err());
        assert!(validate_download_url("https://evil.example/x.crt", &[]).is_err());
        assert!(validate_download_url("https://rca.gov.ir:8443/x.crt", &[]).is_err());
        assert!(validate_download_url("https://user:pass@rca.gov.ir/x.crt", &[]).is_err());
        assert!(
            validate_download_url("https://evil.example/x.crt", &["evil.example".into()]).is_ok()
        );
    }

    #[test]
    fn parse_page_finds_repository_links() {
        let html = r#"
        <a href="APP_Client/UserFiles/Document/Repository/ریشه/Islamic Republic of Iran Root CA-G3.crt">دانلود</a>
        <a href="APP_Client/UserFiles/Document/Repository/irica.crl">دانلود CRL</a>
        "#;
        let client = RcaClient::new().unwrap();
        let certs = client.parse_repository_page(html).unwrap();
        assert!(certs.iter().any(|c| c.url.ends_with(".crt")));
        assert!(!certs.iter().any(|c| c.url.ends_with(".crl")));
    }
}

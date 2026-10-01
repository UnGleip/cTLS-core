//! Download the CCADB official-root list and keep a local cache.
//!
//! Sources (all `https`, official CCADB endpoints):
//! - `AllIncludedRootCertsCSV` — all roots in the CCADB (SHA-256 column)
//! - `MozillaTLSServerAuthenticationCSV` — roots trusted for TLS server auth
//!
//! Output: `<data_dir>/official-ca.json` (schema: [`OfficialCaCache`]),
//! written atomically. Stale-if-error: when downloads fail but a cache
//! exists, the old cache is kept and the report is marked `stale`.

use ctls_core::{normalize_fingerprint, OfficialCaCache};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::time::Duration;

/// All roots present in the CCADB (SHA-256 fingerprints).
pub const SOURCE_ALL_ROOTS: &str =
    "https://ccadb.my.salesforce-sites.com/ccadb/AllIncludedRootCertsCSV";
/// Roots trusted by Mozilla for TLS server authentication.
pub const SOURCE_MOZILLA_TLS: &str =
    "https://ccadb.my.salesforce-sites.com/ccadb/Report?Name=MozillaTLSServerAuthenticationCSV";

/// Default sources, in preference order.
pub fn default_sources() -> Vec<String> {
    vec![SOURCE_ALL_ROOTS.into(), SOURCE_MOZILLA_TLS.into()]
}

/// Default freshness window for `--sync`-on-scan: 7 days.
pub const DEFAULT_MAX_AGE_DAYS: u64 = 7;
const MAX_CSV_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("network: {0}")]
    Network(String),
    #[error("http {status} from {url}")]
    Http { status: u16, url: String },
    #[error("csv parse: {0}")]
    Csv(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("no data: all sources failed and no local cache exists")]
    NoData,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SyncReport {
    /// `true` when a fresh snapshot was downloaded and written.
    pub refreshed: bool,
    /// `true` when downloads failed and an older cache was reused.
    pub stale: bool,
    /// Number of SHA-256 fingerprints in the cache after this call.
    pub count: usize,
    pub updated_at: String,
    /// Sources that succeeded (empty when serving from cache).
    pub sources: Vec<String>,
    /// Per-source extracted fingerprint counts.
    pub source_counts: Vec<(String, usize)>,
    pub warnings: Vec<String>,
}

/// Sync with default sources.
pub fn sync(data_dir: &Path, force: bool, max_age_days: u64) -> Result<SyncReport, SyncError> {
    sync_with(data_dir, &default_sources(), force, max_age_days)
}

/// Sync from explicit `sources` (used by tests with `file://`-like fixtures
/// is intentionally NOT supported — tests inject via [`sync_from_texts`]).
pub fn sync_with(
    data_dir: &Path,
    sources: &[String],
    force: bool,
    max_age_days: u64,
) -> Result<SyncReport, SyncError> {
    if !force {
        if let Some(cache) = OfficialCaCache::load_from(data_dir) {
            if !cache.is_stale(max_age_days) {
                return Ok(SyncReport {
                    refreshed: false,
                    stale: false,
                    count: cache.sha256.len(),
                    updated_at: cache.updated_at.clone(),
                    sources: cache.sources.clone(),
                    source_counts: Vec::new(),
                    warnings: vec![format!(
                        "cache is fresh (< {max_age_days} days); use --force to refresh"
                    )],
                });
            }
        }
    }

    let mut merged: BTreeSet<String> = BTreeSet::new();
    let mut ok_sources: Vec<String> = Vec::new();
    let mut source_counts: Vec<(String, usize)> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    for url in sources {
        match download(url) {
            Ok(text) => match extract_sha256(&text) {
                Ok(set) => {
                    source_counts.push((url.clone(), set.len()));
                    merged.extend(set);
                    ok_sources.push(url.clone());
                }
                Err(e) => warnings.push(format!("{url}: {e}")),
            },
            Err(e) => warnings.push(format!("{url}: {e}")),
        }
    }

    if ok_sources.is_empty() {
        // stale-if-error: keep serving the old snapshot
        if let Some(cache) = OfficialCaCache::load_from(data_dir) {
            warnings.push("downloads failed — using stale local cache".into());
            return Ok(SyncReport {
                refreshed: false,
                stale: true,
                count: cache.sha256.len(),
                updated_at: cache.updated_at.clone(),
                sources: cache.sources.clone(),
                source_counts,
                warnings,
            });
        }
        return Err(SyncError::NoData);
    }

    let cache = OfficialCaCache::new(ok_sources.clone(), merged);
    cache.save(data_dir)?;

    Ok(SyncReport {
        refreshed: true,
        stale: false,
        count: cache.sha256.len(),
        updated_at: cache.updated_at.clone(),
        sources: ok_sources,
        source_counts,
        warnings,
    })
}

/// Build a snapshot from already-downloaded CSV texts (test/fixture path).
pub fn sync_from_texts(
    data_dir: &Path,
    source_labels: &[String],
    texts: &[String],
) -> Result<SyncReport, SyncError> {
    let mut merged: BTreeSet<String> = BTreeSet::new();
    let mut source_counts = Vec::new();
    for (label, text) in source_labels.iter().zip(texts.iter()) {
        let set = extract_sha256(text)?;
        source_counts.push((label.clone(), set.len()));
        merged.extend(set);
    }
    let cache = OfficialCaCache::new(source_labels.to_vec(), merged);
    cache.save(data_dir)?;
    Ok(SyncReport {
        refreshed: true,
        stale: false,
        count: cache.sha256.len(),
        updated_at: cache.updated_at.clone(),
        sources: source_labels.to_vec(),
        source_counts,
        warnings: Vec::new(),
    })
}

fn download(url: &str) -> Result<String, SyncError> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent(concat!("cTLS-sync/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| SyncError::Network(e.to_string()))?;
    let resp = client
        .get(url)
        .send()
        .map_err(|e| SyncError::Network(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(SyncError::Http {
            status: status.as_u16(),
            url: url.to_string(),
        });
    }
    if resp.content_length().is_some_and(|n| n > MAX_CSV_BYTES) {
        return Err(SyncError::Network("CCADB response exceeds 32 MiB".into()));
    }
    let mut bytes = Vec::new();
    resp.take(MAX_CSV_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CSV_BYTES {
        return Err(SyncError::Network("CCADB response exceeds 32 MiB".into()));
    }
    let mut text = String::from_utf8(bytes).map_err(|e| SyncError::Csv(e.to_string()))?;
    // strip UTF-8 BOM (Salesforce exports often include one)
    if text.starts_with('\u{feff}') {
        text.remove(0);
    }
    Ok(text)
}

/// Header matching: normalize to lowercase alphanumerics, then pick the
/// column that looks like a SHA-256 fingerprint column.
fn find_sha256_column(headers: &[String]) -> Option<usize> {
    headers.iter().position(|h| {
        let n: String = h
            .to_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        (n.contains("sha256") || n.contains("sha256fingerprint")) && n.contains("fingerprint")
    })
}

/// Extract normalized SHA-256 fingerprints from a CCADB CSV export.
/// Handles quoted multi-line PEM cells (the Mozilla report embeds PEMs).
pub fn extract_sha256(csv_text: &str) -> Result<BTreeSet<String>, SyncError> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .trim(csv::Trim::All)
        .from_reader(csv_text.as_bytes());

    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| SyncError::Csv(e.to_string()))?
        .iter()
        .map(|s| s.to_string())
        .collect();

    let col = find_sha256_column(&headers).ok_or_else(|| {
        SyncError::Csv(format!(
            "no SHA-256 fingerprint column in header: {headers:?}"
        ))
    })?;

    let mut out = BTreeSet::new();
    for rec in reader.records() {
        let rec = rec.map_err(|e| SyncError::Csv(e.to_string()))?;
        let Some(field) = rec.get(col) else { continue };
        let fp = normalize_fingerprint(field);
        // SHA-256 = 64 hex chars; reject anything else (incl. stray SHA-1/40)
        if fp.len() == 64 && fp.chars().all(|c| c.is_ascii_hexdigit()) {
            out.insert(fp);
        }
    }
    if out.is_empty() {
        return Err(SyncError::Csv("no fingerprints extracted".into()));
    }
    Ok(out)
}

/// Column stats helper for diagnostics (which SHA columns a file has).
pub fn csv_columns(csv_text: &str) -> BTreeMap<String, usize> {
    let mut map = BTreeMap::new();
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_reader(csv_text.as_bytes());
    let headers: Vec<String> = match reader.headers() {
        Ok(h) => h.iter().map(|s| s.to_string()).collect(),
        Err(_) => return map,
    };
    for h in &headers {
        map.insert(h.clone(), 0);
    }
    for rec in reader.records().flatten() {
        for (i, field) in rec.iter().enumerate() {
            if !field.trim().is_empty() {
                if let Some(h) = headers.get(i) {
                    *map.entry(h.clone()).or_insert(0) += 1;
                }
            }
        }
    }
    map
}

/// Read a local file as if it were downloaded (offline/CI).
pub fn download_file(path: &Path) -> Result<String, SyncError> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.read_to_end(&mut bytes)?;
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if text.starts_with('\u{feff}') {
        text.remove(0);
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
CCADB Record,Subject Name,SHA-256 Fingerprint,PEM
\"DigiNotar Root CA\",\"CN=DigiNotar Root CA\",\"f0 81 61 16 6c 09 1e 82 cc b6 57 e6 6a 0c 1a 22 6c 0e e1 1a\",\"-----BEGIN CERTIFICATE-----
MIID
-----END CERTIFICATE-----\"
\"ISRG Root X1\",\"CN=ISRG Root X1\",\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"-----BEGIN CERTIFICATE-----
BBBB
-----END CERTIFICATE-----\"
";

    #[test]
    fn extracts_quoted_multiline_csv() {
        let set = extract_sha256(FIXTURE).unwrap();
        // sha1-looking value (40 hex after normalize → 40 chars) rejected;
        // the 64-hex sha256 kept
        assert!(set.contains(&"a".repeat(64)));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn rejects_missing_column() {
        let err = extract_sha256("a,b\n1,2\n").unwrap_err();
        assert!(matches!(err, SyncError::Csv(_)));
    }

    #[test]
    fn sync_from_texts_writes_cache() {
        let dir = std::env::temp_dir().join(format!("ctls-sync-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let report = sync_from_texts(&dir, &["fixture.csv".into()], &[FIXTURE.into()]).unwrap();
        assert!(report.refreshed);
        assert_eq!(report.count, 1);

        let cache = OfficialCaCache::load_from(&dir).unwrap();
        assert_eq!(cache.sha256.len(), 1);
        assert!(!cache.is_stale(7));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_if_error_keeps_old_cache() {
        let dir = std::env::temp_dir().join(format!("ctls-sync-stale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        sync_from_texts(&dir, &["f".into()], &[FIXTURE.into()]).unwrap();

        // unreachable host → download fails → stale cache served
        let report = sync_with(
            &dir,
            &["https://ccadb.invalid/x.csv".into()],
            true, // force
            DEFAULT_MAX_AGE_DAYS,
        )
        .unwrap();
        assert!(!report.refreshed);
        assert!(report.stale);
        assert_eq!(report.count, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fresh_cache_short_circuits() {
        let dir = std::env::temp_dir().join(format!("ctls-sync-fresh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        sync_from_texts(&dir, &["f".into()], &[FIXTURE.into()]).unwrap();

        let report = sync_with(
            &dir,
            &["https://ccadb.invalid/x.csv".into()],
            false,
            DEFAULT_MAX_AGE_DAYS,
        )
        .unwrap();
        assert!(!report.refreshed);
        assert!(!report.stale);
        assert_eq!(report.count, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

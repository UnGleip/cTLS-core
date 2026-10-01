//! On-disk cache of the CCADB "official root" set.
//!
//! Written by `ctls-sync` (`official-ca.json` in the data dir), read by
//! `ctls-scanner` to classify a certificate as official vs third-party.
//! Kept in `ctls-core` so both crates share one schema without a
//! sync↔scanner dependency.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Cache file name inside the data dir (`%USERPROFILE%\.ctls` / `$HOME/.ctls`).
pub const OFFICIAL_CACHE_FILE: &str = "official-ca.json";
/// Bump when the JSON shape changes.
pub const OFFICIAL_CACHE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfficialCaCache {
    pub version: u32,
    /// Human-readable RFC-3339 timestamp (for `ctls sync --status`).
    pub updated_at: String,
    /// Seconds since epoch (authoritative for staleness checks).
    pub updated_at_unix: u64,
    /// Source URLs that fed this snapshot (successful ones only).
    pub sources: Vec<String>,
    /// Normalized (lowercase, no separators) SHA-256 fingerprints.
    pub sha256: BTreeSet<String>,
}

impl OfficialCaCache {
    pub fn new(sources: Vec<String>, sha256: BTreeSet<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            version: OFFICIAL_CACHE_VERSION,
            updated_at: unix_to_iso(now),
            updated_at_unix: now,
            sources,
            sha256,
        }
    }

    pub fn cache_path(data_dir: &Path) -> PathBuf {
        data_dir.join(OFFICIAL_CACHE_FILE)
    }

    /// Load from the data dir; `None` when missing/corrupt.
    pub fn load_from(data_dir: &Path) -> Option<Self> {
        let bytes = std::fs::read(Self::cache_path(data_dir)).ok()?;
        serde_json::from_slice::<Self>(&bytes).ok()
    }

    /// `true` when older than `max_age_days` (or clock skew).
    pub fn is_stale(&self, max_age_days: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(self.updated_at_unix) > max_age_days * 86_400
    }

    /// Atomic write: temp file + rename (never a half-written cache).
    pub fn save(&self, data_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(data_dir)?;
        let path = Self::cache_path(data_dir);
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

pub fn unix_to_iso(unix: u64) -> String {
    let dt = time::OffsetDateTime::from_unix_timestamp(unix as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    dt.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| unix.to_string())
}

/// Load normalized SHA-256 set for classification (`None` → empty).
pub fn official_sha256_set(data_dir: &Path) -> BTreeSet<String> {
    OfficialCaCache::load_from(data_dir)
        .map(|c| c.sha256)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_staleness() {
        let dir = std::env::temp_dir().join(format!("ctls-official-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let cache = OfficialCaCache::new(
            vec!["https://example.invalid/x.csv".into()],
            ["aabb".repeat(16)].into_iter().collect(),
        );
        assert_eq!(cache.sha256.len(), 1);
        cache.save(&dir).unwrap();

        let loaded = OfficialCaCache::load_from(&dir).expect("cache loads");
        assert_eq!(loaded.sha256, cache.sha256);
        assert!(!loaded.is_stale(7));
        assert!(loaded.is_stale(0) || loaded.updated_at_unix > 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_cache_is_none() {
        let dir = std::env::temp_dir().join(format!("ctls-official-none-{}", std::process::id()));
        assert!(OfficialCaCache::load_from(&dir).is_none());
    }
}

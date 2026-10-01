//! Vault drift detection: snapshot the vault to `drift-baseline.json`, then
//! diff current state against it. Any added / removed / status-changed entry
//! is drift — `ctls drift check` exits with code 2 so scripts can alert.

use ctls_vault::VaultEntry;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const BASELINE_FILE: &str = "drift-baseline.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaselineEntry {
    pub sha1: String,
    pub subject: String,
    pub status: String,
    pub trust_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Baseline {
    pub version: u32,
    pub created_at: String,
    pub entries: Vec<BaselineEntry>,
}

#[derive(Debug, Default)]
pub struct DriftReport {
    /// (sha1, subject) — present now, missing from baseline.
    pub added: Vec<(String, String)>,
    /// (sha1, subject) — present in baseline, missing now.
    pub removed: Vec<(String, String)>,
    /// (sha1, subject, baseline status, current status).
    pub status_changed: Vec<(String, String, String, String)>,
}

impl DriftReport {
    pub fn is_drift(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty() || !self.status_changed.is_empty()
    }

    pub fn print(&self) {
        for (sha1, subject) in &self.added {
            println!("[added]          {sha1} | {subject}");
        }
        for (sha1, subject) in &self.removed {
            println!("[removed]        {sha1} | {subject}");
        }
        for (sha1, subject, old, new) in &self.status_changed {
            println!("[status-changed] {sha1} {old} -> {new} | {subject}");
        }
    }
}

fn normalize_sha1(s: &str) -> String {
    ctls_core::normalize_fingerprint(s)
}

/// Build a sorted, deterministic baseline from current vault entries.
pub fn baseline_from_entries(entries: &[VaultEntry], created_at: &str) -> Baseline {
    let mut list: Vec<BaselineEntry> = entries
        .iter()
        .map(|e| BaselineEntry {
            sha1: normalize_sha1(&e.sha1_fingerprint),
            subject: e.subject.clone(),
            status: e.status.to_ascii_uppercase(),
            trust_level: e.trust_level.to_ascii_uppercase(),
        })
        .collect();
    list.sort_by(|a, b| a.sha1.cmp(&b.sha1));
    Baseline {
        version: 1,
        created_at: created_at.to_string(),
        entries: list,
    }
}

/// Diff current vault entries against a baseline.
pub fn diff(base: &Baseline, current: &[VaultEntry]) -> DriftReport {
    use std::collections::BTreeMap;

    let now: BTreeMap<String, &VaultEntry> = current
        .iter()
        .map(|e| (normalize_sha1(&e.sha1_fingerprint), e))
        .collect();
    let base_map: BTreeMap<String, &BaselineEntry> =
        base.entries.iter().map(|e| (e.sha1.clone(), e)).collect();

    let mut report = DriftReport::default();
    for (sha1, e) in &now {
        match base_map.get(sha1) {
            None => report.added.push((sha1.clone(), e.subject.clone())),
            Some(b) => {
                let cur = e.status.to_ascii_uppercase();
                if cur != b.status {
                    report.status_changed.push((
                        sha1.clone(),
                        e.subject.clone(),
                        b.status.clone(),
                        cur,
                    ));
                }
            }
        }
    }
    for (sha1, b) in &base_map {
        if !now.contains_key(sha1) {
            report.removed.push((sha1.clone(), b.subject.clone()));
        }
    }
    report
}

pub fn read(path: &Path) -> anyhow::Result<Baseline> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

pub fn write(path: &Path, baseline: &Baseline) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(baseline)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sha1: &str, subject: &str, status: &str) -> VaultEntry {
        VaultEntry {
            id: 1,
            subject: subject.to_string(),
            issuer: "CN=test".into(),
            sha1_fingerprint: sha1.to_string(),
            sha256_fingerprint: "00".into(),
            not_before: String::new(),
            not_after: String::new(),
            is_ca: true,
            self_signed: true,
            trust_level: "SAFE".into(),
            source: "test".into(),
            added_at: "2026-01-01T00:00:00Z".into(),
            der_len: 0,
            status: status.to_string(),
        }
    }

    #[test]
    fn no_drift_when_identical() {
        let entries = vec![
            entry("AA:BB", "CN=One", "ALLOW"),
            entry("CC:DD", "CN=Two", "QUARANTINE"),
        ];
        let base = baseline_from_entries(&entries, "2026-01-01T00:00:00Z");
        let report = diff(&base, &entries);
        assert!(!report.is_drift());
        assert!(report.added.is_empty());
        assert!(report.removed.is_empty());
        assert!(report.status_changed.is_empty());
    }

    #[test]
    fn detects_added_removed_and_status_change() {
        let before = vec![
            entry("AA:BB", "CN=One", "ALLOW"),
            entry("CC:DD", "CN=Two", "ALLOW"),
            entry("EE:FF", "CN=Three", "ALLOW"),
        ];
        let base = baseline_from_entries(&before, "2026-01-01T00:00:00Z");
        // now: One unchanged, Two downgraded, Three removed, Four added
        let now = vec![
            entry("AA:BB", "CN=One", "ALLOW"),
            entry("CC:DD", "CN=Two", "BLOCK"),
            entry("11:22", "CN=Four", "PENDING"),
        ];
        let report = diff(&base, &now);
        assert!(report.is_drift());
        assert_eq!(report.added.len(), 1);
        assert_eq!(report.added[0].1, "CN=Four");
        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.removed[0].1, "CN=Three");
        assert_eq!(report.status_changed.len(), 1);
        assert_eq!(report.status_changed[0].2, "ALLOW");
        assert_eq!(report.status_changed[0].3, "BLOCK");
    }

    #[test]
    fn baseline_is_sorted_and_normalized() {
        let entries = vec![
            entry("AA:BB", "CN=Zed", "allow"),
            entry("00:11", "CN=Aed", "QUARANTINE"),
        ];
        let base = baseline_from_entries(&entries, "now");
        assert_eq!(base.version, 1);
        // sha1 is normalized: lowercase hex, no separators
        assert_eq!(base.entries[0].sha1, "0011");
        assert_eq!(base.entries[1].sha1, "aabb");
        assert_eq!(base.entries[1].status, "ALLOW");
    }

    #[test]
    fn roundtrip_write_read() {
        let dir = std::env::temp_dir().join(format!("ctls_drift_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(BASELINE_FILE);
        let entries = vec![entry("AA:BB", "CN=One", "ALLOW")];
        let base = baseline_from_entries(&entries, "2026-01-01T00:00:00Z");
        write(&path, &base).unwrap();
        let back = read(&path).unwrap();
        assert_eq!(base, back);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

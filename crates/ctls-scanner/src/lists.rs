use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

pub fn normalize(fp: &str) -> String {
    ctls_core::normalize_fingerprint(fp)
}

/// Name fragments that mark a CA as known-bad regardless of fingerprint
/// (catches re-issued/renamed certs from compromised CAs).
pub const NAME_BLOCK_RULES: &[&str] = &["diginotar", "superfish"];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FingerprintLists {
    /// SHA-1 fingerprints explicitly allowed (builtin + `allowlist.json`).
    pub allowed: BTreeSet<String>,
    /// SHA-1 fingerprints explicitly blocked (builtin + `blocklist.json`).
    pub blocked: BTreeSet<String>,
    /// SHA-256 fingerprints of CCADB official roots (from `official-ca.json`).
    pub official_sha256: BTreeSet<String>,
}

impl FingerprintLists {
    /// Builtin + user JSON files + official CCADB cache (if synced).
    ///
    /// `<data_dir>/allowlist.json`, `<data_dir>/blocklist.json`,
    /// `<data_dir>/official-ca.json` — missing files are skipped silently.
    pub fn load_for_data_dir(data_dir: &Path) -> Self {
        let allow = data_dir.join("allowlist.json");
        let block = data_dir.join("blocklist.json");
        let mut lists = Self::from_json_files(&allow.to_string_lossy(), &block.to_string_lossy());
        lists.official_sha256 = ctls_core::official_sha256_set(data_dir);
        lists
    }

    pub fn from_json_files(allow_path: &str, block_path: &str) -> Self {
        let mut allowed = Self::builtin().allowed;
        allowed.extend(load_list(allow_path));
        let mut blocked = Self::builtin().blocked;
        blocked.extend(load_list(block_path));
        Self {
            allowed,
            blocked,
            official_sha256: BTreeSet::new(),
        }
    }

    pub fn builtin() -> Self {
        Self {
            allowed: [
                // Islamic Republic of Iran Root CA-G3 (rca.gov.ir SHA-1)
                "59356ea42299d6a10af3244ee0821f49edaf5dcb",
                // IRI ROOT CA (G2)
                "b8e2ad3bba97b51c00c997260817f7174a9867",
                // Well-known public roots (common set)
                "a9993e364706816aba3e25717850c26c9cd0d89d", // placeholder-like; real set grows via allowlist.json
                "cabd2a79a1076a31f21d253635cb039d4329a5e8", // ISRG Root X1
                "e58c1cc4913b38634be106ee3ad8e6b9dd9814a4", // GTS Root R1
                "8da7f965ec5efc37910f1c6e59fdc1cc6a6ede16", // Amazon Root CA 1
                "f6108407d6f8bb67980cc2e244c2ebae1cef63be", // Amazon Root CA 4
            ]
            .into_iter()
            .map(normalize)
            .collect(),
            blocked: [
                // DigiNotar Root CA (compromised 2011, distrusted everywhere)
                "f08161166c091e82ccb657e66a0c1a226c0ee11a",
            ]
            .into_iter()
            .map(normalize)
            .collect(),
            official_sha256: BTreeSet::new(),
        }
    }

    /// Add the official SHA-256 set (from `official-ca.json` / `ctls sync`).
    pub fn with_official<I, S>(mut self, fingerprints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.official_sha256
            .extend(fingerprints.into_iter().map(|f| normalize(&f.into())));
        self
    }

    /// `true` when subject or issuer matches a known-bad CA name rule.
    pub fn name_blocked(&self, subject: &str, issuer: &str) -> bool {
        let s = subject.to_lowercase();
        let i = issuer.to_lowercase();
        NAME_BLOCK_RULES
            .iter()
            .any(|rule| s.contains(rule) || i.contains(rule))
    }
}

fn load_list(path: &str) -> BTreeSet<String> {
    let Ok(raw) = std::fs::read(path) else {
        return BTreeSet::new();
    };
    // strip UTF-8 BOM if present
    let bytes = if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &raw[3..]
    } else {
        &raw[..]
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return BTreeSet::new();
    };
    serde_json::from_str::<Vec<String>>(text)
        .map(|v| v.iter().map(|x| normalize(x)).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_has_diginotar_blocked() {
        let l = FingerprintLists::builtin();
        assert!(l
            .blocked
            .contains(&normalize("f08161166c091e82ccb657e66a0c1a226c0ee11a")));
    }

    #[test]
    fn name_rules_match_subject_or_issuer() {
        let l = FingerprintLists::builtin();
        assert!(l.name_blocked("CN=DigiNotar Root CA", "CN=DigiNotar Root CA"));
        assert!(l.name_blocked("CN=Good", "CN=Superfish CA"));
        assert!(!l.name_blocked("CN=ISRG Root X1", "CN=ISRG Root X1"));
    }

    #[test]
    fn with_official_normalizes() {
        let l =
            FingerprintLists::builtin().with_official(["AA:BB".to_string(), "ccdd".to_string()]);
        assert!(l.official_sha256.contains("aabb"));
        assert!(l.official_sha256.contains("ccdd"));
    }
}

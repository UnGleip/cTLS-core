use crate::heuristics;
use crate::lists::FingerprintLists;
use ctls_core::{normalize_fingerprint, CaRecord, TrustLevel};
use serde::{Deserialize, Serialize};

/// Where a certificate came from / how it got into the store — independent
/// of the verdict ([`TrustLevel`]): e.g. an official root can still be
/// user-blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CaClassification {
    /// In the CCADB official root set (`ctls sync`).
    OfficialRoot,
    /// In cTLS curated/builtin allowlist but not in CCADB (e.g. national root).
    Curated,
    /// Self-signed or vendor-installed root not in any public list —
    /// typical of VPN/antivirus/corporate software roots.
    ThirdParty,
    /// Issued (non-self-signed) cert with no provenance info.
    #[default]
    Unknown,
}

impl CaClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            CaClassification::OfficialRoot => "OFFICIAL",
            CaClassification::Curated => "CURATED",
            CaClassification::ThirdParty => "THIRD-PARTY",
            CaClassification::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub level: TrustLevel,
    pub classification: CaClassification,
    pub reasons: Vec<String>,
}

/// Classify provenance (independent of the trust verdict).
pub fn classify(rec: &CaRecord, lists: &FingerprintLists) -> CaClassification {
    let sha256 = normalize_fingerprint(&rec.sha256_fingerprint);
    let sha1 = normalize_fingerprint(&rec.sha1_fingerprint);
    if lists.official_sha256.contains(&sha256) {
        CaClassification::OfficialRoot
    } else if lists.allowed.contains(&sha1) {
        CaClassification::Curated
    } else if rec.self_signed {
        CaClassification::ThirdParty
    } else {
        CaClassification::Unknown
    }
}

/// Full scan: hard rules (blacklist/name) → official/allow lists →
/// heuristics. Classification is computed first so a blocked official root
/// still shows `OFFICIAL`.
pub fn scan_record(rec: &CaRecord, lists: &FingerprintLists) -> ScanResult {
    let classification = classify(rec, lists);
    let mut reasons: Vec<String> = Vec::new();
    let sha1 = normalize_fingerprint(&rec.sha1_fingerprint);

    // 1. hard block — user blacklist, then known-bad CA names
    if lists.blocked.contains(&sha1) {
        reasons.push("fingerprint in blacklist".into());
        return ScanResult {
            level: TrustLevel::Blocked,
            classification,
            reasons,
        };
    }
    if lists.name_blocked(&rec.subject, &rec.issuer) {
        reasons.push("subject/issuer matches known-bad CA name rule".into());
        return ScanResult {
            level: TrustLevel::Blocked,
            classification,
            reasons,
        };
    }

    // Validity is mandatory even for a previously curated/official root.
    let validity_reasons: Vec<String> = [heuristics::expired(rec), heuristics::not_yet_valid(rec)]
        .into_iter()
        .flatten()
        .map(str::to_string)
        .collect();
    if !validity_reasons.is_empty() {
        return ScanResult {
            level: TrustLevel::Suspicious,
            classification,
            reasons: validity_reasons,
        };
    }

    // 2. positive lists
    let sha256 = normalize_fingerprint(&rec.sha256_fingerprint);
    if lists.official_sha256.contains(&sha256) {
        reasons.push("in CCADB official root set".into());
        return ScanResult {
            level: TrustLevel::Safe,
            classification,
            reasons,
        };
    }
    if lists.allowed.contains(&sha1) {
        reasons.push("fingerprint in allowlist".into());
        return ScanResult {
            level: TrustLevel::Safe,
            classification,
            reasons,
        };
    }

    // 3. heuristics (AV-style, cheap)
    let heuristic_reasons = heuristics::collect_reasons(rec);
    if !heuristic_reasons.is_empty() {
        // any weak-crypto / provenance / recency signal → suspicious
        return ScanResult {
            level: TrustLevel::Suspicious,
            classification,
            reasons: heuristic_reasons,
        };
    }

    // 4. clean but unlisted
    if rec.self_signed {
        reasons.push("unknown self-signed root".into());
        ScanResult {
            level: TrustLevel::Suspicious,
            classification,
            reasons,
        }
    } else {
        reasons.push("not in official or allow lists".into());
        ScanResult {
            level: TrustLevel::Unknown,
            classification,
            reasons,
        }
    }
}

/// How aggressive the scan should be. Profiles only change the *verdict
/// string*: hard blocks and official/allow hits are never adjusted, and the
/// vault status mapping (fail-safe → Quarantine) treats Suspicious and
/// Unknown identically, so profiles can never promote anything to Allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanProfile {
    /// Unknown → Suspicious (anything unproven is treated as suspect).
    Strict,
    #[default]
    Default,
    /// Suspicious (heuristic-only findings) → Unknown (report-only
    /// downgrade; hard blocks stay blocked).
    Lenient,
}

impl ScanProfile {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "strict" => Some(ScanProfile::Strict),
            "default" => Some(ScanProfile::Default),
            "lenient" => Some(ScanProfile::Lenient),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ScanProfile::Strict => "strict",
            ScanProfile::Default => "default",
            ScanProfile::Lenient => "lenient",
        }
    }
}

/// [`scan_record`] + profile adjustment.
pub fn scan_record_profiled(
    rec: &CaRecord,
    lists: &FingerprintLists,
    profile: ScanProfile,
) -> ScanResult {
    let mut res = scan_record(rec, lists);
    match profile {
        ScanProfile::Default => {}
        ScanProfile::Strict => {
            if res.level == TrustLevel::Unknown {
                res.level = TrustLevel::Suspicious;
                res.reasons
                    .push("profile=strict: unknown treated as suspicious".into());
            }
        }
        ScanProfile::Lenient => {
            if res.level == TrustLevel::Suspicious {
                res.level = TrustLevel::Unknown;
                res.reasons
                    .push("profile=lenient: heuristic suspicion downgraded".into());
            }
        }
    }
    res
}

#[cfg(test)]
pub(crate) mod test_util {
    use ctls_core::CaRecord;

    pub fn sample_record() -> CaRecord {
        CaRecord {
            subject: "CN=Test Root".into(),
            issuer: "CN=Test Root".into(),
            serial_hex: "01".into(),
            sha1_fingerprint: "aa".repeat(20),
            sha256_fingerprint: "bb".repeat(32),
            not_before: "2020-01-01T00:00:00Z".into(),
            not_after: "2030-01-01T00:00:00Z".into(),
            is_ca: true,
            self_signed: true,
            signature_algorithm: "sha256WithRSAEncryption".into(),
            public_key_algorithm: "rsaEncryption".into(),
            public_key_bits: 2048,
            store_name: "Root".into(),
            store_location: "LocalMachine".into(),
            der_len: 100,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::test_util::sample_record;

    #[test]
    fn official_root_is_safe() {
        let lists =
            FingerprintLists::builtin().with_official([sample_record().sha256_fingerprint.clone()]);
        let res = scan_record(&sample_record(), &lists);
        assert_eq!(res.level, TrustLevel::Safe);
        assert_eq!(res.classification, CaClassification::OfficialRoot);
    }

    #[test]
    fn official_root_with_invalid_dates_is_not_safe() {
        let mut rec = sample_record();
        let lists = FingerprintLists::builtin().with_official([rec.sha256_fingerprint.clone()]);
        rec.not_after = "2001-01-01T00:00:00Z".into();
        let expired = scan_record(&rec, &lists);
        assert_eq!(expired.level, TrustLevel::Suspicious);
        assert_eq!(expired.classification, CaClassification::OfficialRoot);
        rec.not_after = "3001-01-01T00:00:00Z".into();
        rec.not_before = "2999-01-01T00:00:00Z".into();
        assert_eq!(scan_record(&rec, &lists).level, TrustLevel::Suspicious);
    }

    #[test]
    fn unknown_self_signed_is_suspicious_third_party() {
        let lists = FingerprintLists::builtin();
        let res = scan_record(&sample_record(), &lists);
        assert_eq!(res.level, TrustLevel::Suspicious);
        assert_eq!(res.classification, CaClassification::ThirdParty);
    }

    #[test]
    fn blocked_fingerprint_wins() {
        let mut lists = FingerprintLists::builtin();
        lists
            .blocked
            .insert(sample_record().sha1_fingerprint.clone());
        let res = scan_record(&sample_record(), &lists);
        assert_eq!(res.level, TrustLevel::Blocked);
        // classification still reflects provenance
        assert_eq!(res.classification, CaClassification::ThirdParty);
    }

    #[test]
    fn diginotar_name_blocked_even_without_fingerprint() {
        let lists = FingerprintLists::builtin();
        let mut rec = sample_record();
        rec.subject = "CN=DigiNotar Root CA".into();
        rec.issuer = "CN=DigiNotar Root CA".into();
        let res = scan_record(&rec, &lists);
        assert_eq!(res.level, TrustLevel::Blocked);
    }

    #[test]
    fn issued_cert_without_provenance_is_unknown() {
        let mut rec = sample_record();
        rec.self_signed = false;
        let lists = FingerprintLists::builtin();
        let res = scan_record(&rec, &lists);
        assert_eq!(res.level, TrustLevel::Unknown);
        assert_eq!(res.classification, CaClassification::Unknown);
    }

    #[test]
    fn profile_strict_upgrades_unknown() {
        let mut rec = sample_record();
        rec.self_signed = false;
        let lists = FingerprintLists::builtin();
        let res = scan_record_profiled(&rec, &lists, ScanProfile::Strict);
        assert_eq!(res.level, TrustLevel::Suspicious);
        assert!(res.reasons.iter().any(|r| r.contains("profile=strict")));
    }

    #[test]
    fn profile_lenient_downgrades_heuristic_suspicion() {
        // unknown self-signed root → Suspicious by default
        let lists = FingerprintLists::builtin();
        let res = scan_record_profiled(&sample_record(), &lists, ScanProfile::Lenient);
        assert_eq!(res.level, TrustLevel::Unknown);
        assert!(res.reasons.iter().any(|r| r.contains("profile=lenient")));
    }

    #[test]
    fn profile_never_touches_hard_blocks_or_official() {
        let mut lists = FingerprintLists::builtin();
        lists
            .blocked
            .insert(sample_record().sha1_fingerprint.clone());
        for p in [
            ScanProfile::Strict,
            ScanProfile::Default,
            ScanProfile::Lenient,
        ] {
            let res = scan_record_profiled(&sample_record(), &lists, p);
            assert_eq!(res.level, TrustLevel::Blocked, "profile={p:?}");
        }
        let lists =
            FingerprintLists::builtin().with_official([sample_record().sha256_fingerprint.clone()]);
        for p in [
            ScanProfile::Strict,
            ScanProfile::Default,
            ScanProfile::Lenient,
        ] {
            let res = scan_record_profiled(&sample_record(), &lists, p);
            assert_eq!(res.level, TrustLevel::Safe, "profile={p:?}");
        }
    }

    #[test]
    fn profile_parse() {
        assert_eq!(ScanProfile::parse("STRICT"), Some(ScanProfile::Strict));
        assert_eq!(ScanProfile::parse(" lenient "), Some(ScanProfile::Lenient));
        assert_eq!(ScanProfile::parse("paranoid"), None);
        assert_eq!(ScanProfile::default(), ScanProfile::Default);
    }
}

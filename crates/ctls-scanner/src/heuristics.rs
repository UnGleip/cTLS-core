//! AV-style lightweight heuristics for CA certificates.
//!
//! Deliberately cheap (no chain building, no revocation): fingerprint and
//! name rules first, then weak-crypto / provenance / recency signals. The
//! heavy lifting of "is this root actually trusted" is delegated to the
//! official CCADB set (`ctls sync`) and the curated allowlist.

use ctls_core::CaRecord;
use std::time::Duration;

/// Certificates issued this recently (days) while self-signed are treated
/// as suspicious — public roots are old; fresh self-signed roots in a store
/// usually mean somebody installed one.
const RECENT_SELF_SIGNED_DAYS: u64 = 180;

/// SHA-1 or MD5 based signature.
pub fn weak_signature(rec: &CaRecord) -> Option<String> {
    let alg = rec.signature_algorithm.to_lowercase();
    if alg.contains("sha1") || alg.contains("md5") {
        return Some(format!("weak signature: {}", rec.signature_algorithm));
    }
    None
}

/// RSA/DSA key smaller than 2048 bits (or EC smaller than 256 bits).
pub fn weak_key(rec: &CaRecord) -> Option<String> {
    if rec.public_key_bits == 0 {
        return None;
    }
    let algo = rec.public_key_algorithm.to_lowercase();
    let min = if algo.contains("ec") { 256 } else { 2048 };
    if rec.public_key_bits < min {
        return Some(format!("small key: {} bits", rec.public_key_bits));
    }
    None
}

/// Self-signed certificate that does not claim the CA basic constraint.
pub fn self_signed_without_ca(rec: &CaRecord) -> Option<&'static str> {
    if rec.self_signed && !rec.is_ca {
        Some("self-signed without CA basic constraint")
    } else {
        None
    }
}

/// Validity window that ends before 2000 (parser artifact / backdated cert).
pub fn implausible_validity(rec: &CaRecord) -> Option<&'static str> {
    if rec.not_after.as_str() < "2000-01-01" {
        Some("implausible validity window")
    } else {
        None
    }
}

/// Already expired.
pub fn expired(rec: &CaRecord) -> Option<&'static str> {
    if rec.is_expired(&now_iso()) {
        Some("certificate expired")
    } else {
        None
    }
}

/// A certificate that has not entered its validity window cannot be trusted yet.
pub fn not_yet_valid(rec: &CaRecord) -> Option<&'static str> {
    if rec.not_before > now_iso() {
        Some("certificate not yet valid")
    } else {
        None
    }
}

/// Self-signed root issued within 180 days — public
/// roots are years old, so a fresh one is a red flag.
pub fn recent_self_signed(rec: &CaRecord) -> Option<&'static str> {
    if !rec.self_signed {
        return None;
    }
    let issued = parse_iso(&rec.not_before)?;
    let now = now_unix();
    if issued > now {
        return None;
    }
    let age = now - issued;
    if age <= RECENT_SELF_SIGNED_DAYS * 86_400 {
        return Some("recently issued self-signed root (not traceable to a public CA)");
    }
    None
}

/// All heuristic reasons for a record, in fixed order.
pub fn collect_reasons(rec: &CaRecord) -> Vec<String> {
    [
        weak_signature(rec),
        weak_key(rec),
        self_signed_without_ca(rec).map(str::to_string),
        expired(rec).map(str::to_string),
        not_yet_valid(rec).map(str::to_string),
        implausible_validity(rec).map(str::to_string),
        recent_self_signed(rec).map(str::to_string),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_iso() -> String {
    ctls_core::official::unix_to_iso(now_unix())
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` (the format produced by `CaRecord`).
fn parse_iso(s: &str) -> Option<u64> {
    let fmt = time::format_description::parse_borrowed::<2>(
        "[year]-[month]-[day]T[hour]:[minute]:[second]Z",
    )
    .ok()?;
    let dt = time::PrimitiveDateTime::parse(s, &fmt).ok()?;
    Some(dt.assume_utc().unix_timestamp().max(0) as u64)
}

/// Exposed for tests / UIs: seconds the cert has been alive.
pub fn age_seconds(rec: &CaRecord) -> Option<Duration> {
    let issued = parse_iso(&rec.not_before)?;
    Some(Duration::from_secs(now_unix().saturating_sub(issued)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::test_util::sample_record;

    #[test]
    fn flags_sha1_and_small_key() {
        let mut rec = sample_record();
        rec.signature_algorithm = "sha1WithRSAEncryption".into();
        rec.public_key_bits = 1024;
        let reasons = collect_reasons(&rec);
        assert!(reasons.iter().any(|r| r.contains("weak signature")));
        assert!(reasons.iter().any(|r| r.contains("small key")));
    }

    #[test]
    fn future_certificate_is_suspicious() {
        let mut rec = sample_record();
        rec.not_before = "2999-01-01T00:00:00Z".into();
        assert!(collect_reasons(&rec)
            .iter()
            .any(|r| r.contains("not yet valid")));
        assert!(recent_self_signed(&rec).is_none());
    }

    #[test]
    fn flags_recent_self_signed_only_when_young() {
        let mut rec = sample_record();
        rec.self_signed = true;
        rec.is_ca = true;
        rec.not_before = "1999-01-01T00:00:00Z".into();
        assert!(recent_self_signed(&rec).is_none());

        rec.not_before = ctls_core::official::unix_to_iso(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 3600,
        );
        assert!(recent_self_signed(&rec).is_some());
    }
}

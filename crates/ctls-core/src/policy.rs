//! Policy engine: map trust status → isolation action.
//!
//! Fail-safe: anything not explicitly Allowed stays isolated (Quarantine/Pending).

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::model::TrustLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaStatus {
    Allow,
    Quarantine,
    Block,
    Pending,
}

impl CaStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CaStatus::Allow => "ALLOW",
            CaStatus::Quarantine => "QUARANTINE",
            CaStatus::Block => "BLOCK",
            CaStatus::Pending => "PENDING",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_uppercase().as_str() {
            "ALLOW" | "SAFE" => CaStatus::Allow,
            "BLOCK" | "BLOCKED" => CaStatus::Block,
            "QUARANTINE" | "SUSPICIOUS" => CaStatus::Quarantine,
            _ => CaStatus::Pending,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    /// Allowed → may be applied to the OS trust store / kept as system trust.
    ApplyToSystem,
    /// Quarantine or Pending → keep only inside the Vault (isolated).
    KeepIsolatedOnly,
    /// Blocked → purge from system stores (never trusted).
    Purge,
}

/// Fail-safe mapping: only `Allow` leaves isolation.
pub fn decide(status: CaStatus) -> PolicyAction {
    match status {
        CaStatus::Allow => PolicyAction::ApplyToSystem,
        CaStatus::Quarantine | CaStatus::Pending => PolicyAction::KeepIsolatedOnly,
        CaStatus::Block => PolicyAction::Purge,
    }
}

/// Map a scan `TrustLevel` to a vault `CaStatus`.
/// Unknown/Suspicious fail safe to Quarantine, never Allow.
pub fn status_from_trust(level: TrustLevel) -> CaStatus {
    match level {
        TrustLevel::Safe => CaStatus::Allow,
        TrustLevel::Blocked => CaStatus::Block,
        TrustLevel::Suspicious | TrustLevel::Unknown => CaStatus::Quarantine,
    }
}

/// Explicit user accept may promote a non-blocked cert to Allow.
pub fn status_for_explicit_import(level: TrustLevel) -> CaStatus {
    match level {
        TrustLevel::Blocked => CaStatus::Block,
        _ => CaStatus::Allow,
    }
}

// ---------------------------------------------------------------------------
// Policy as Code (`policy.json` in the data dir)
// ---------------------------------------------------------------------------
//
// Optional file: when present its rules override the built-in mapping for
// import / reeval. Scanner hard blocks (blacklist) always win — a policy can
// never un-block what the scanner blocked.
//
// {
//   "version": 1,
//   "default_action": null,           // null → built-in mapping stays
//   "rules": [
//     { "name": "block-local-malware", "match": { "name_contains": "superfish" },
//       "action": "BLOCK" },
//     { "name": "quarantine-third-party", "match": { "classification": "THIRD-PARTY" },
//       "action": "QUARANTINE" }
//   ]
// }

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy io: {0}")]
    Io(#[from] std::io::Error),
    #[error("policy json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("policy invalid: {}", .0.join("; "))]
    Invalid(Vec<String>),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyFile {
    #[serde(default)]
    pub version: u32,
    /// Applied when no rule matches. `None` → built-in mapping.
    #[serde(default)]
    pub default_action: Option<CaStatus>,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRule {
    pub name: String,
    #[serde(rename = "match")]
    pub matcher: RuleMatch,
    pub action: CaStatus,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleMatch {
    /// Case-insensitive substring of subject OR issuer.
    #[serde(default)]
    pub name_contains: Option<String>,
    #[serde(default)]
    pub issuer_contains: Option<String>,
    /// OFFICIAL | CURATED | THIRD-PARTY | UNKNOWN
    #[serde(default)]
    pub classification: Option<String>,
    /// SAFE | SUSPICIOUS | BLOCKED | UNKNOWN (scanner verdict)
    #[serde(default)]
    pub level: Option<String>,
}

pub const POLICY_FILE_NAME: &str = "policy.json";
const VALID_CLASSIFICATIONS: [&str; 4] = ["OFFICIAL", "CURATED", "THIRD-PARTY", "UNKNOWN"];
const VALID_LEVELS: [&str; 4] = ["SAFE", "SUSPICIOUS", "BLOCKED", "UNKNOWN"];

impl PolicyFile {
    /// Load `policy.json` from the data dir.
    /// `Ok(None)` → no file (use built-in mapping). `Err` → file exists but
    /// is broken (fail closed: caller should surface it, not ignore it).
    pub fn load_from(data_dir: &Path) -> Result<Option<Self>, PolicyError> {
        let path = data_dir.join(POLICY_FILE_NAME);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let pf: PolicyFile = serde_json::from_str(&text)?;
                pf.validate()?;
                Ok(Some(pf))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(PolicyError::Io(e)),
        }
    }

    /// Return all violations (empty → valid).
    pub fn issues(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.version > 1 {
            out.push(format!(
                "unsupported policy version {} (max 1)",
                self.version
            ));
        }
        for (i, r) in self.rules.iter().enumerate() {
            let ctx = if r.name.is_empty() {
                format!("rule #{i}")
            } else {
                format!("rule '{}'", r.name)
            };
            let m = &r.matcher;
            let has_condition = m.name_contains.is_some()
                || m.issuer_contains.is_some()
                || m.classification.is_some()
                || m.level.is_some();
            if !has_condition {
                out.push(format!("{ctx}: empty match (would apply to everything)"));
            }
            if let Some(c) = &m.classification {
                let c = c.to_ascii_uppercase();
                if !VALID_CLASSIFICATIONS.contains(&c.as_str()) {
                    out.push(format!(
                        "{ctx}: unknown classification '{c}' (expected {})",
                        VALID_CLASSIFICATIONS.join("|")
                    ));
                }
            }
            if let Some(l) = &m.level {
                let l = l.to_ascii_uppercase();
                if !VALID_LEVELS.contains(&l.as_str()) {
                    out.push(format!(
                        "{ctx}: unknown level '{l}' (expected {})",
                        VALID_LEVELS.join("|")
                    ));
                }
            }
            if r.action == CaStatus::Allow
                && (m.classification.is_some() || m.level.is_some())
                && m.name_contains.is_none()
                && m.issuer_contains.is_none()
            {
                out.push(format!(
                    "{ctx}: ALLOW by classification/level only — ALLOW must be explicit \
                     (match on name/issuer too)"
                ));
            }
        }
        out
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        let issues = self.issues();
        if issues.is_empty() {
            Ok(())
        } else {
            Err(PolicyError::Invalid(issues))
        }
    }

    /// First matching rule wins; then `default_action`; then `None`
    /// (caller falls back to the built-in mapping).
    /// Fields are compared case-insensitively.
    pub fn decide(
        &self,
        subject: &str,
        issuer: &str,
        level: &str,
        classification: &str,
    ) -> Option<CaStatus> {
        let level = level.to_ascii_uppercase();
        let classification = classification.to_ascii_uppercase();
        for rule in &self.rules {
            if self.rule_matches(rule, subject, issuer, &level, &classification) {
                return Some(rule.action);
            }
        }
        self.default_action
    }

    fn rule_matches(
        &self,
        rule: &PolicyRule,
        subject: &str,
        issuer: &str,
        level: &str,
        classification: &str,
    ) -> bool {
        let m = &rule.matcher;
        let subject_l = subject.to_ascii_lowercase();
        let issuer_l = issuer.to_ascii_lowercase();
        if let Some(p) = &m.name_contains {
            let p = p.to_ascii_lowercase();
            if !subject_l.contains(&p) && !issuer_l.contains(&p) {
                return false;
            }
        }
        if let Some(p) = &m.issuer_contains {
            let p = p.to_ascii_lowercase();
            if !issuer_l.contains(&p) {
                return false;
            }
        }
        if let Some(c) = &m.classification {
            if classification != c.to_ascii_uppercase() {
                return false;
            }
        }
        if let Some(l) = &m.level {
            if level != l.to_ascii_uppercase() {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_safe_quarantine_isolated() {
        assert_eq!(decide(CaStatus::Quarantine), PolicyAction::KeepIsolatedOnly);
        assert_eq!(decide(CaStatus::Pending), PolicyAction::KeepIsolatedOnly);
        assert_eq!(decide(CaStatus::Allow), PolicyAction::ApplyToSystem);
        assert_eq!(decide(CaStatus::Block), PolicyAction::Purge);
    }

    #[test]
    fn unknown_never_becomes_allow() {
        assert_eq!(status_from_trust(TrustLevel::Unknown), CaStatus::Quarantine);
        assert_eq!(
            status_from_trust(TrustLevel::Suspicious),
            CaStatus::Quarantine
        );
    }

    #[test]
    fn explicit_import_rejects_block() {
        assert_eq!(
            status_for_explicit_import(TrustLevel::Blocked),
            CaStatus::Block
        );
        assert_eq!(
            status_for_explicit_import(TrustLevel::Suspicious),
            CaStatus::Allow
        );
    }

    fn sample_policy() -> PolicyFile {
        serde_json::from_str(
            r#"{
                "version": 1,
                "rules": [
                    {"name": "block-superfish", "match": {"name_contains": "superfish"},
                     "action": "BLOCK"},
                    {"name": "quarantine-3p", "match": {"classification": "THIRD-PARTY"},
                     "action": "QUARANTINE"}
                ]
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn policy_rule_first_match_wins() {
        let p = sample_policy();
        assert_eq!(
            p.decide(
                "CN=Superfish Root",
                "CN=Superfish Root",
                "SAFE",
                "THIRD-PARTY"
            ),
            Some(CaStatus::Block)
        );
        assert_eq!(
            p.decide(
                "CN=Corp VPN Root",
                "CN=Corp VPN Root",
                "SAFE",
                "THIRD-PARTY"
            ),
            Some(CaStatus::Quarantine)
        );
        // no rule matches and no default → built-in mapping stays
        assert_eq!(p.decide("CN=Other", "CN=Other", "SAFE", "OFFICIAL"), None);
    }

    #[test]
    fn policy_issuer_and_level_match() {
        let p: PolicyFile = serde_json::from_str(
            r#"{"version": 1, "rules": [
                {"name": "gov", "match": {"issuer_contains": "GOV.IR", "level": "SUSPICIOUS"},
                 "action": "BLOCK"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(
            p.decide("CN=x", "CN=Root GOV.IR", "SUSPICIOUS", "UNKNOWN"),
            Some(CaStatus::Block)
        );
        assert_eq!(p.decide("CN=x", "CN=Root GOV.IR", "SAFE", "UNKNOWN"), None);
    }

    #[test]
    fn policy_default_action_applies_when_no_rule() {
        let p: PolicyFile =
            serde_json::from_str(r#"{"version": 1, "default_action": "QUARANTINE", "rules": []}"#)
                .unwrap();
        assert_eq!(
            p.decide("CN=x", "CN=x", "SAFE", "OFFICIAL"),
            Some(CaStatus::Quarantine)
        );
    }

    #[test]
    fn policy_rejects_empty_match_and_bad_classification() {
        let p: PolicyFile = serde_json::from_str(
            r#"{"version": 1, "rules": [
                {"name": "oops", "match": {}, "action": "BLOCK"},
                {"name": "bad", "match": {"classification": "NOT-A-THING"}, "action": "BLOCK"}
            ]}"#,
        )
        .unwrap();
        let issues = p.issues();
        assert_eq!(issues.len(), 2);
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_allow_by_fingerprint_only_is_rejected() {
        let p: PolicyFile = serde_json::from_str(
            r#"{"version": 1, "rules": [
                {"name": "loose", "match": {"classification": "UNKNOWN"}, "action": "ALLOW"}
            ]}"#,
        )
        .unwrap();
        assert!(!p.issues().is_empty());
    }

    #[test]
    fn policy_allow_with_name_match_is_accepted() {
        let p: PolicyFile = serde_json::from_str(
            r#"{"version": 1, "rules": [
                {"name": "corp", "match": {"name_contains": "corp root"}, "action": "ALLOW"}
            ]}"#,
        )
        .unwrap();
        assert!(p.validate().is_ok());
    }
}

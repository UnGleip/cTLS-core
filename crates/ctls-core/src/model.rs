use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TrustLevel {
    Safe,
    Suspicious,
    Blocked,
    #[default]
    Unknown,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Safe => "SAFE",
            TrustLevel::Suspicious => "SUSPICIOUS",
            TrustLevel::Blocked => "BLOCKED",
            TrustLevel::Unknown => "UNKNOWN",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            TrustLevel::Safe => "green",
            TrustLevel::Suspicious => "yellow",
            TrustLevel::Blocked => "red",
            TrustLevel::Unknown => "gray",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaRecord {
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub sha1_fingerprint: String,
    pub sha256_fingerprint: String,
    pub not_before: String,
    pub not_after: String,
    pub is_ca: bool,
    pub self_signed: bool,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub public_key_bits: u32,
    pub store_name: String,
    pub store_location: String,
    pub der_len: usize,
}

impl CaRecord {
    pub fn is_expired(&self, now_iso: &str) -> bool {
        self.not_after.as_str() < now_iso
    }
}

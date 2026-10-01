use sha1::{Digest, Sha1};
use sha2::Sha256;

pub fn sha1_hex(der: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(der);
    hex::encode(h.finalize())
}

pub fn sha256_hex(der: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(der);
    hex::encode(h.finalize())
}

pub fn format_colon(hex_str: &str) -> String {
    hex_str
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(":")
        .to_uppercase()
}

pub fn normalize_fingerprint(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_known_vector() {
        let d = sha1_hex(b"abc");
        assert_eq!(d, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn normalize_strips_separators() {
        assert_eq!(normalize_fingerprint("59 35 6e a4"), "59356ea4");
        assert_eq!(normalize_fingerprint("59:35:6E:A4"), "59356ea4");
    }
}

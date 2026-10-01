//! Certificate loading: PEM (single/bundle), DER, and basic PKCS#7 / .p7b.
//!
//! Splits multi-cert PEM into individual DER blobs so bundle files work.

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("empty input")]
    Empty,
    #[error("no certificates found")]
    NoCerts,
    #[error("base64 decode failed")]
    Base64,
    #[error("utf-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

/// Extract one or more certificate DER blobs from arbitrary file bytes.
///
/// - PEM with one or many `-----BEGIN CERTIFICATE-----` blocks → one DER each
/// - PKCS#7 / `.p7b` (binary or PEM-wrapped): extract embedded CERTIFICATE
///   blocks when present; otherwise attempt whole-blob DER parse by caller
/// - Raw DER single certificate → single blob
pub fn load_certificates(bytes: &[u8]) -> Result<Vec<Vec<u8>>, ImportError> {
    if bytes.is_empty() {
        return Err(ImportError::Empty);
    }

    // PEM / textual containers
    if looks_like_pem(bytes) {
        let text = std::str::from_utf8(bytes)?;
        let certs = extract_pem_cert_blocks(text);
        if !certs.is_empty() {
            return Ok(certs);
        }
        // PKCS#7 PEM without nested CERTIFICATE labels: decode PKCS7 block and
        // let caller try DER parse; if only PKCS7 body, still return it.
        if let Some(p7) = extract_pem_block(text, "PKCS7") {
            return Ok(vec![p7]);
        }
        if let Some(p7) = extract_pem_block(text, "PKCS #7 SIGNED DATA") {
            return Ok(vec![p7]);
        }
        // Legacy single-block fallback (old behavior)
        if let Some(der) = pem_first_block_to_der(text) {
            return Ok(vec![der]);
        }
        return Err(ImportError::NoCerts);
    }

    // Binary DER (may be PKCS#7 ContentInfo or a single X.509 cert)
    Ok(vec![bytes.to_vec()])
}

/// True if the payload looks like PEM text (any BEGIN marker).
pub fn looks_like_pem(bytes: &[u8]) -> bool {
    bytes.windows(11).any(|w| w == b"BEGIN CERT")
        || bytes.windows(11).any(|w| w == b"BEGIN PKCS7")
        || bytes.windows(11).any(|w| w == b"BEGIN PKCS")
        || bytes.starts_with(b"-----BEGIN")
}

/// Split all `CERTIFICATE` PEM blocks into DER blobs.
pub fn extract_pem_cert_blocks(text: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after = &rest[start + "-----BEGIN CERTIFICATE-----".len()..];
        let Some(end) = after.find("-----END CERTIFICATE-----") else {
            break;
        };
        let body: String = after[..end]
            .lines()
            .flat_map(|l| l.chars().filter(|c| !c.is_whitespace()))
            .collect();
        if let Some(der) = base64_decode(&body) {
            out.push(der);
        }
        rest = &after[end + "-----END CERTIFICATE-----".len()..];
    }
    out
}

fn extract_pem_block(text: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text.find(&begin)?;
    let after = &text[start + begin.len()..];
    let end_pos = after.find(&end)?;
    let body: String = after[..end_pos]
        .lines()
        .flat_map(|l| l.chars().filter(|c| !c.is_whitespace()))
        .collect();
    base64_decode(&body)
}

fn pem_first_block_to_der(text: &str) -> Option<Vec<u8>> {
    let begin = "-----BEGIN ";
    let s = text.find(begin)?;
    let after = &text[s + begin.len()..];
    let label_end = after.find("-----")?;
    let label = &after[..label_end];
    let body_start_marker = format!("-----BEGIN {label}-----");
    let bs = text.find(&body_start_marker)?;
    let body = &text[bs + body_start_marker.len()..];
    let e = body.find(&format!("-----END {label}-----"))?;
    let b64: String = body[..e]
        .lines()
        .flat_map(|l| l.chars().filter(|c| !c.is_whitespace()))
        .collect();
    base64_decode(&b64)
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut rev = [0xffu8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        rev[c as usize] = i as u8;
    }
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &ch in input.as_bytes() {
        if ch == b'=' {
            break;
        }
        let v = rev[ch as usize];
        if v == 0xff {
            continue;
        }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_pem() {
        let pem = "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n";
        let v = load_certificates(pem.as_bytes()).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], b"hello");
    }

    #[test]
    fn bundle_pem_splits() {
        let pem = "-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n\
                   -----BEGIN CERTIFICATE-----\nYg==\n-----END CERTIFICATE-----\n";
        let v = load_certificates(pem.as_bytes()).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], b"a");
        assert_eq!(v[1], b"b");
    }

    #[test]
    fn raw_der_passthrough() {
        let der = [0x30u8, 0x03, 0x02, 0x01, 0x01];
        let v = load_certificates(&der).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], der);
    }

    #[test]
    fn empty_fails() {
        assert!(load_certificates(b"").is_err());
    }
}

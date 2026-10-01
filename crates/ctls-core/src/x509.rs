use crate::fingerprint::{sha1_hex, sha256_hex};
use crate::model::CaRecord;
use x509_parser::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("X.509 parse error: {0}")]
    Parse(String),
}

fn format_time(t: &ASN1Time) -> String {
    let dt = t.to_datetime();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    )
}

fn alg_name(alg: &AlgorithmIdentifier) -> String {
    let oid = alg.algorithm.to_id_string();
    match oid.as_str() {
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".into(),
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".into(),
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption".into(),
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption".into(),
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".into(),
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".into(),
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".into(),
        "1.3.101.112" => "Ed25519".into(),
        _ => oid,
    }
}

fn key_alg_and_bits(cert: &X509Certificate) -> (String, u32) {
    let spki = cert.public_key();
    let oid = spki.algorithm.algorithm.to_id_string();
    let bits = spki.parsed().map(|k| k.key_size() as u32).unwrap_or(0);
    match oid.as_str() {
        "1.2.840.113549.1.1.1" => ("RSA".to_string(), bits),
        "1.2.840.10045.2.1" => ("EC".to_string(), bits),
        "1.3.101.112" => ("Ed25519".to_string(), 256),
        _ => (oid, bits),
    }
}

pub fn parse_der_ca(
    der: &[u8],
    store_name: &str,
    store_location: &str,
) -> Result<CaRecord, CoreError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| CoreError::Parse(e.to_string()))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let self_signed = subject == issuer;

    let (pk_alg, pk_bits) = key_alg_and_bits(&cert);
    let sig_alg = alg_name(&cert.signature_algorithm);

    Ok(CaRecord {
        subject,
        issuer,
        serial_hex: cert.raw_serial_as_string(),
        sha1_fingerprint: sha1_hex(der),
        sha256_fingerprint: sha256_hex(der),
        not_before: format_time(&cert.validity().not_before),
        not_after: format_time(&cert.validity().not_after),
        is_ca: cert.is_ca(),
        self_signed,
        signature_algorithm: sig_alg,
        public_key_algorithm: pk_alg,
        public_key_bits: pk_bits,
        store_name: store_name.to_string(),
        store_location: store_location.to_string(),
        der_len: der.len(),
    })
}

pub fn parse_der_bytes(der: &[u8]) -> Result<CaRecord, CoreError> {
    parse_der_ca(der, "file", "local")
}

/// SHA-256 of the certificate's SubjectPublicKeyInfo (DER TLV) — the stable
/// SPKI pin used for the local admin mTLS channel (leaf certs are re-issued
/// often, their SPKI is what we pin).
pub fn spki_sha256_hex(der: &[u8]) -> Result<String, CoreError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| CoreError::Parse(e.to_string()))?;
    Ok(sha256_hex(cert.public_key().raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_der_bytes(b"not a cert").is_err());
    }
}

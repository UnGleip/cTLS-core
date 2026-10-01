//! Linux trust store: read system dirs + bundles; install via
//! `/usr/local/share/ca-certificates` + `update-ca-certificates`.

use crate::{PlatformError, PlatformStore, StoreLocation};
use ctls_core::{load_certificates, normalize_fingerprint, parse_der_ca, sha1_hex, CaRecord};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Directories holding individual PEM/DER CA files.
const SYSTEM_DIRS: &[&str] = &[
    "/etc/ssl/certs",
    "/usr/share/ca-certificates",
    "/usr/local/share/ca-certificates",
];

/// Concatenated multi-PEM bundles (one file, many certs).
const BUNDLE_FILES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/ca-bundle.pem", // SUSE
    "/etc/ssl/cert.pem",      // Alpine / macOS-with-openssl
];

/// Where cTLS installs custom roots (Debian policy dir; needs root).
const CUSTOM_DIR: &str = "/usr/local/share/ca-certificates";

#[derive(Default)]
pub struct LinuxStore;

fn user_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("ctls")
        .join("ca-certificates")
}

/// PEM-encode one DER certificate.
pub fn pem_encode(der: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in der.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        let chars = [
            TABLE[((n >> 18) & 63) as usize],
            TABLE[((n >> 12) & 63) as usize],
            if chunk.len() > 1 {
                TABLE[((n >> 6) & 63) as usize]
            } else {
                b'='
            },
            if chunk.len() > 2 {
                TABLE[(n & 63) as usize]
            } else {
                b'='
            },
        ];
        out.push_str(std::str::from_utf8(&chars).unwrap_or(""));
        if out.len() % 65 == 0 {
            out.push('\n');
        }
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

fn parse_bytes(
    bytes: &[u8],
    store_name: &str,
    location: &str,
    seen: &mut BTreeSet<String>,
) -> Vec<CaRecord> {
    let mut out = Vec::new();
    let ders = match load_certificates(bytes) {
        Ok(d) => d,
        Err(_) => return out,
    };
    for der in ders {
        let sha1 = normalize_fingerprint(&sha1_hex(&der));
        if !seen.insert(sha1) {
            continue;
        }
        if let Ok(rec) = parse_der_ca(&der, store_name, location) {
            out.push(rec);
        }
    }
    out
}

fn read_dir_certs(
    dir: &Path,
    location: &str,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<CaRecord>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() && !path.is_symlink() {
            continue;
        }
        // skip obvious non-cert files (hash symlinks + .pem/.crt/.der all fine)
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.ends_with(".rds") || name.ends_with(".info") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        // quick sanity: PEM marker or DER-looking binary
        let looks_text = bytes.starts_with(b"-----BEGIN") || bytes.first() == Some(&0x30);
        if !looks_text {
            continue;
        }
        let store_name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("cert");
        out.extend(parse_bytes(&bytes, store_name, location, seen));
    }
}

impl PlatformStore for LinuxStore {
    fn platform_name(&self) -> &'static str {
        "linux"
    }

    fn list_system_cas(&self) -> Result<Vec<CaRecord>, PlatformError> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();

        for dir in SYSTEM_DIRS {
            read_dir_certs(Path::new(dir), "System", &mut seen, &mut out);
        }
        let ud = user_dir();
        if ud.exists() {
            read_dir_certs(&ud, "User", &mut seen, &mut out);
        }
        for bundle in BUNDLE_FILES {
            let Ok(bytes) = std::fs::read(bundle) else {
                continue;
            };
            out.extend(parse_bytes(&bytes, "Root", "System", &mut seen));
        }
        Ok(out)
    }

    fn export_der(&self, sha1: &str) -> Result<Vec<u8>, PlatformError> {
        let target = normalize_fingerprint(sha1);
        let mut seen = BTreeSet::new();
        let mut found = None;

        let mut scan_dir = |dir: &Path, found: &mut Option<Vec<u8>>| {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(bytes) = std::fs::read(&path) else {
                    continue;
                };
                let ders = match load_certificates(&bytes) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                for der in ders {
                    let sha1_hex = normalize_fingerprint(&sha1_hex(&der));
                    seen.insert(sha1_hex.clone());
                    if sha1_hex == target {
                        *found = Some(der);
                        return;
                    }
                }
            }
        };

        for dir in SYSTEM_DIRS {
            scan_dir(Path::new(dir), &mut found);
            if found.is_some() {
                break;
            }
        }
        if found.is_none() {
            for bundle in BUNDLE_FILES {
                let Ok(bytes) = std::fs::read(bundle) else {
                    continue;
                };
                let ders = match load_certificates(&bytes) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                for der in ders {
                    if normalize_fingerprint(&sha1_hex(&der)) == target {
                        found = Some(der);
                        break;
                    }
                }
                if found.is_some() {
                    break;
                }
            }
        }
        found.ok_or(PlatformError::NotFound(target))
    }

    fn install_ca(
        &self,
        der: &[u8],
        _store_name: &str,
        location: StoreLocation,
    ) -> Result<(), PlatformError> {
        let sha1 = normalize_fingerprint(&sha1_hex(der));
        let pem = pem_encode(der);
        let dir = match location {
            StoreLocation::LocalMachine => PathBuf::from(CUSTOM_DIR),
            StoreLocation::CurrentUser => user_dir(),
        };
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{sha1}.crt"));
        std::fs::write(&path, pem).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                PlatformError::PermissionDenied(format!(
                    "{} requires root (try: sudo)",
                    path.display()
                ))
            } else {
                PlatformError::Io(e)
            }
        })?;

        if location == StoreLocation::LocalMachine {
            refresh_trust()?;
        }
        Ok(())
    }

    fn remove_ca(
        &self,
        sha1: &str,
        _store_name: &str,
        location: StoreLocation,
    ) -> Result<bool, PlatformError> {
        let target = normalize_fingerprint(sha1);
        let dir = match location {
            StoreLocation::LocalMachine => PathBuf::from(CUSTOM_DIR),
            StoreLocation::CurrentUser => user_dir(),
        };
        let mut removed = false;
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(bytes) = std::fs::read(&path) else {
                    continue;
                };
                let ders = match load_certificates(&bytes) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                if ders
                    .iter()
                    .any(|d| normalize_fingerprint(&sha1_hex(d)) == target)
                {
                    std::fs::remove_file(&path).map_err(|e| {
                        if e.kind() == std::io::ErrorKind::PermissionDenied {
                            PlatformError::PermissionDenied(format!(
                                "{} requires root (try: sudo)",
                                path.display()
                            ))
                        } else {
                            PlatformError::Io(e)
                        }
                    })?;
                    removed = true;
                }
            }
        }
        if removed && location == StoreLocation::LocalMachine {
            refresh_trust()?;
        }
        Ok(removed)
    }

    fn can_modify(&self) -> bool {
        true // with root for system scope
    }
}

/// Rebuild system trust after changing custom dirs.
fn refresh_trust() -> Result<(), PlatformError> {
    use std::process::Command;
    let mut tried = false;
    if Command::new("update-ca-certificates")
        .arg("--fresh")
        .output()
        .is_ok()
    {
        tried = true;
    }
    if !tried
        && Command::new("update-ca-trust")
            .arg("extract")
            .output()
            .is_ok()
    {
        tried = true;
    }
    if !tried {
        return Err(PlatformError::Msg(
            "neither update-ca-certificates nor update-ca-trust found".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_encode_roundtrip() {
        let der = b"hello-linux-store-bytes";
        let pem = pem_encode(der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        // decode with core loader (base64 in body must round-trip)
        let decoded = ctls_core::load_certificates(pem.as_bytes()).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], der);
    }
}

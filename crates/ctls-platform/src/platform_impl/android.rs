//! Android trust store — **read-only** for normal apps.
//!
//! System roots live in `/system/etc/security/cacerts` (files named
//! `<subject_hash_old>.0`, PEM or DER). Mutating that dir requires root;
//! user-level CA installation goes through Kotlin `DevicePolicyManager`
//! (Android 14+ `Credentials` API) which will be wired from the mobile UI.

use crate::{PlatformError, PlatformStore, StoreLocation};
use ctls_core::{load_certificates, normalize_fingerprint, parse_der_ca, sha1_hex, CaRecord};
use std::collections::BTreeSet;

const SYSTEM_DIR: &str = "/system/etc/security/cacerts";
/// Android 14+ per-user added CAs (usually not readable by third-party apps).
const USER_DIR: &str = "/data/misc/user/0/cacerts-added";

#[derive(Default)]
pub struct AndroidStore;

fn read_dir(dir: &str, location: &str, seen: &mut BTreeSet<String>, out: &mut Vec<CaRecord>) {
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
            let sha1 = normalize_fingerprint(&sha1_hex(&der));
            if !seen.insert(sha1) {
                continue;
            }
            if let Ok(rec) = parse_der_ca(&der, "Root", location) {
                out.push(rec);
            }
        }
    }
}

impl PlatformStore for AndroidStore {
    fn platform_name(&self) -> &'static str {
        "android"
    }

    fn list_system_cas(&self) -> Result<Vec<CaRecord>, PlatformError> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        read_dir(SYSTEM_DIR, "System", &mut seen, &mut out);
        read_dir(USER_DIR, "User", &mut seen, &mut out);
        Ok(out)
    }

    fn export_der(&self, sha1: &str) -> Result<Vec<u8>, PlatformError> {
        let target = normalize_fingerprint(sha1);
        for dir in [SYSTEM_DIR, USER_DIR] {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
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
                    if normalize_fingerprint(&sha1_hex(&der)) == target {
                        return Ok(der);
                    }
                }
            }
        }
        Err(PlatformError::NotFound(target))
    }

    fn install_ca(
        &self,
        _der: &[u8],
        _store_name: &str,
        _location: StoreLocation,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::not_supported(
            "android",
            "apps cannot write the system CA store; install from the Kotlin UI \
             via DevicePolicyManager / Credentials API (root only for /system)",
        ))
    }

    fn remove_ca(
        &self,
        _sha1: &str,
        _store_name: &str,
        _location: StoreLocation,
    ) -> Result<bool, PlatformError> {
        Err(PlatformError::not_supported(
            "android",
            "apps cannot modify the system CA store",
        ))
    }

    fn can_modify(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_does_not_panic_without_root() {
        // On a dev machine (not Android) these dirs don't exist → empty, no error.
        let store = AndroidStore;
        let _ = store.list_system_cas().unwrap_or_default();
    }
}

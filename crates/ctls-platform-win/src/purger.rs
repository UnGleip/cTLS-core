use ctls_core::CaRecord;
use std::path::Path;

use crate::backup::{restore_all, BackupManifest};
use crate::store::{read_store, StoreError, StoreLocation};

#[derive(Debug, thiserror::Error)]
pub enum PurgeError {
    #[error("backup: {0}")]
    Backup(#[from] crate::backup::BackupError),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("refusing to purge without admin rights")]
    NeedsAdmin,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("nothing to purge")]
    Empty,
}

#[derive(Debug, serde::Serialize)]
pub struct PurgeReport {
    pub backup: BackupManifest,
    pub removed: usize,
    pub kept: usize,
}

/// True when the process token is elevated (administrator).
pub fn is_admin() -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut size = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            );
            let _ = CloseHandle(token);
            ok.is_ok() && elevation.TokenIsElevated != 0
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Remove certificates from LocalMachine\Root that are NOT in `allowed_sha1`.
/// Always creates a full backup first. Requires administrator.
#[cfg(windows)]
pub fn purge_untrusted(
    allowed_sha1: &std::collections::BTreeSet<String>,
    backup_dir: impl AsRef<Path>,
) -> Result<PurgeReport, PurgeError> {
    if !is_admin() {
        return Err(PurgeError::NeedsAdmin);
    }

    let backup = crate::backup::backup_all(backup_dir)?;
    let mut removed = 0usize;
    let mut kept = 0usize;

    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertDeleteCertificateFromStore, CertEnumCertificatesInStore, CertOpenStore,
        CERT_CONTEXT, CERT_OPEN_STORE_FLAGS, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
        CERT_SYSTEM_STORE_LOCAL_MACHINE, HCERTSTORE, X509_ASN_ENCODING,
    };

    let store_name = "Root";
    let store_name_w: Vec<u16> = store_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // Pass 1: READ-ONLY enumerate → keep vs delete decision.
        let hstore: HCERTSTORE = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            X509_ASN_ENCODING,
            None,
            CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG.0),
            Some(store_name_w.as_ptr() as *const _),
        )
        .map_err(|e| PurgeError::Store(StoreError::Crypto(e.to_string())))?;

        let mut to_delete: Vec<Vec<u8>> = Vec::new();
        let mut pctx: *mut CERT_CONTEXT = std::ptr::null_mut();
        loop {
            pctx = CertEnumCertificatesInStore(hstore, Some(pctx));
            if pctx.is_null() {
                break;
            }
            let ctx = &*pctx;
            let der = std::slice::from_raw_parts(
                ctx.pbCertEncoded as *const u8,
                ctx.cbCertEncoded as usize,
            );
            let sha1 = ctls_core::normalize_fingerprint(&ctls_core::sha1_hex(der));
            if allowed_sha1.contains(&sha1) {
                kept += 1;
            } else {
                to_delete.push(der.to_vec());
            }
        }
        // Close READ-ONLY handle exactly once before any delete.
        let _ = CertCloseStore(Some(hstore), 0);

        // Pass 2: open READ-WRITE once; match by SHA-1 and delete.
        if !to_delete.is_empty() {
            let hstore_rw: HCERTSTORE = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                X509_ASN_ENCODING,
                None,
                CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_LOCAL_MACHINE),
                Some(store_name_w.as_ptr() as *const _),
            )
            .map_err(|e| PurgeError::Store(StoreError::Crypto(e.to_string())))?;

            for der in &to_delete {
                let target = ctls_core::normalize_fingerprint(&ctls_core::sha1_hex(der));
                let mut cur: *mut CERT_CONTEXT = std::ptr::null_mut();
                loop {
                    cur = CertEnumCertificatesInStore(hstore_rw, Some(cur));
                    if cur.is_null() {
                        break;
                    }
                    let ctx = &*cur;
                    let d = std::slice::from_raw_parts(
                        ctx.pbCertEncoded as *const u8,
                        ctx.cbCertEncoded as usize,
                    );
                    if ctls_core::normalize_fingerprint(&ctls_core::sha1_hex(d)) == target {
                        // CertDeleteCertificateFromStore frees `cur`.
                        if CertDeleteCertificateFromStore(cur).is_ok() {
                            removed += 1;
                        }
                        break;
                    }
                }
            }
            let _ = CertCloseStore(Some(hstore_rw), 0);
        }
    }

    Ok(PurgeReport {
        backup,
        removed,
        kept,
    })
}

/// Windows-only operation; other platforms have no `LocalMachine\Root`.
#[cfg(not(windows))]
pub fn purge_untrusted(
    _allowed_sha1: &std::collections::BTreeSet<String>,
    _backup_dir: impl AsRef<Path>,
) -> Result<PurgeReport, PurgeError> {
    Err(PurgeError::Store(StoreError::Crypto(
        "purge is Windows-only".into(),
    )))
}

/// Dry-run: keep vs would-remove counts for LocalMachine\Root.
pub fn preview_purge(
    allowed: &std::collections::BTreeSet<String>,
) -> Result<(usize, usize), PurgeError> {
    let mut keep = 0usize;
    let mut drop = 0usize;
    let recs = read_store("Root", StoreLocation::LocalMachine)?;
    for r in &recs {
        let sha1 = ctls_core::normalize_fingerprint(&r.sha1_fingerprint);
        if allowed.contains(&sha1) {
            keep += 1;
        } else {
            drop += 1;
        }
    }
    Ok((keep, drop))
}

/// Restore requires administrator (writes LocalMachine stores).
pub fn restore_backup(dir: impl AsRef<Path>) -> Result<usize, PurgeError> {
    if !is_admin() {
        return Err(PurgeError::NeedsAdmin);
    }
    Ok(restore_all(dir)?)
}

#[allow(dead_code)]
fn _unused(_: &CaRecord, _: &[(&str, StoreLocation)]) {}

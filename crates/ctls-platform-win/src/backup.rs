use ctls_core::CaRecord;
use std::path::{Path, PathBuf};

use crate::store::{export_der_by_sha1, read_store, StoreError, StoreLocation, COMMON_STORES};

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, serde::Serialize)]
pub struct BackupManifest {
    pub created_at: String,
    pub stores: Vec<StoreBackupInfo>,
    pub total_certs: usize,
    pub path: String,
}

#[derive(Debug, serde::Serialize)]
pub struct StoreBackupInfo {
    pub store_name: String,
    pub store_location: String,
    pub count: usize,
}

fn now_iso() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

/// Export every certificate from common stores into `dir` as DER files + manifest.json.
/// This MUST be called before any purge.
pub fn backup_all(dir: impl AsRef<Path>) -> Result<BackupManifest, BackupError> {
    let dir = dir.as_ref().to_path_buf();
    std::fs::create_dir_all(&dir)?;

    let mut stores = Vec::new();
    let mut total = 0usize;
    let mut manifest_lines = Vec::new();

    for (name, loc) in COMMON_STORES {
        let recs = match read_store(name, *loc) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if recs.is_empty() {
            continue;
        }
        let store_dir = dir.join(format!("{}-{}", loc.as_str(), name));
        std::fs::create_dir_all(&store_dir)?;
        for r in &recs {
            let der = export_der_by_sha1(name, *loc, &r.sha1_fingerprint)?;
            let file = store_dir.join(format!("{}.der", r.sha1_fingerprint));
            std::fs::write(&file, &der)?;
            manifest_lines.push(format!(
                "{}\\{}\t{}\t{}\t{}",
                loc.as_str(),
                name,
                r.sha1_fingerprint,
                r.subject.replace('\t', " "),
                r.not_after
            ));
        }
        total += recs.len();
        stores.push(StoreBackupInfo {
            store_name: name.to_string(),
            store_location: loc.as_str().to_string(),
            count: recs.len(),
        });
    }

    let manifest_path = dir.join("manifest.tsv");
    std::fs::write(&manifest_path, manifest_lines.join("\n"))?;

    Ok(BackupManifest {
        created_at: now_iso(),
        stores,
        total_certs: total,
        path: dir.to_string_lossy().to_string(),
    })
}

/// Restore certificates from a backup dir into their original stores (add-only).
/// Requires administrator rights for LocalMachine stores.
#[cfg(windows)]
pub fn restore_all(dir: impl AsRef<Path>) -> Result<usize, BackupError> {
    use windows::Win32::Security::Cryptography::{
        CertAddCertificateContextToStore, CertCloseStore, CertCreateCertificateContext,
        CertOpenStore, CERT_OPEN_STORE_FLAGS, CERT_STORE_ADD_REPLACE_EXISTING,
        CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE,
        HCERTSTORE, X509_ASN_ENCODING,
    };

    let dir = dir.as_ref();
    let mut restored = 0usize;

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let folder = entry.file_name().to_string_lossy().to_string();
        let Some((loc_str, store_name)) = folder.split_once('-') else {
            continue;
        };
        let loc_flag = if loc_str == "CurrentUser" {
            CERT_SYSTEM_STORE_CURRENT_USER
        } else {
            CERT_SYSTEM_STORE_LOCAL_MACHINE
        };

        let store_name_w: Vec<u16> = store_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let hstore: HCERTSTORE = match CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                X509_ASN_ENCODING,
                None,
                CERT_OPEN_STORE_FLAGS(loc_flag),
                Some(store_name_w.as_ptr() as *const _),
            ) {
                Ok(h) => h,
                Err(_) => continue,
            };

            for der_entry in std::fs::read_dir(entry.path())? {
                let der_entry = der_entry?;
                let path = der_entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("der") {
                    continue;
                }
                let der = match std::fs::read(&path) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                let pctx = CertCreateCertificateContext(X509_ASN_ENCODING, &der);
                if pctx.is_null() {
                    continue;
                }
                let mut out = std::ptr::null_mut();
                let _ = CertAddCertificateContextToStore(
                    Some(hstore),
                    pctx,
                    CERT_STORE_ADD_REPLACE_EXISTING,
                    Some(&mut out),
                );
                restored += 1;
            }
            let _ = CertCloseStore(Some(hstore), 0);
        }
    }

    Ok(restored)
}

/// Windows-only operation (writes system CertStores).
#[cfg(not(windows))]
pub fn restore_all(_dir: impl AsRef<Path>) -> Result<usize, BackupError> {
    Err(BackupError::Store(StoreError::Crypto(
        "restore is Windows-only".into(),
    )))
}

pub fn default_backup_dir() -> PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".ctls").join("backups")
}

/// Helper used by tests to list one store after restore.
pub fn count_store(name: &str, loc: StoreLocation) -> Result<Vec<CaRecord>, StoreError> {
    read_store(name, loc)
}

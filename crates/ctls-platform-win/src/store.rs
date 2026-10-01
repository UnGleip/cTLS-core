#[cfg(windows)]
use ctls_core::parse_der_ca;
use ctls_core::CaRecord;
#[cfg(windows)]
use std::ptr;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("windows crypto error: {0}")]
    Crypto(String),
    #[error("parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreLocation {
    CurrentUser,
    LocalMachine,
}

impl StoreLocation {
    pub fn as_str(&self) -> &'static str {
        match self {
            StoreLocation::CurrentUser => "CurrentUser",
            StoreLocation::LocalMachine => "LocalMachine",
        }
    }
}

pub const COMMON_STORES: &[(&str, StoreLocation)] = &[
    ("Root", StoreLocation::LocalMachine),
    ("Root", StoreLocation::CurrentUser),
    ("CA", StoreLocation::LocalMachine),
    ("CA", StoreLocation::CurrentUser),
    ("Trust", StoreLocation::LocalMachine),
    ("AuthRoot", StoreLocation::LocalMachine),
    ("My", StoreLocation::CurrentUser),
];

#[cfg(windows)]
pub fn read_store(store_name: &str, location: StoreLocation) -> Result<Vec<CaRecord>, StoreError> {
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertOpenStore, CERT_CONTEXT,
        CERT_OPEN_STORE_FLAGS, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
        CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE, HCERTSTORE,
        X509_ASN_ENCODING,
    };

    let loc = match location {
        StoreLocation::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
        StoreLocation::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
    };

    let flags = CERT_OPEN_STORE_FLAGS(loc | CERT_STORE_READONLY_FLAG.0);

    let store_name_w: Vec<u16> = store_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let hstore: HCERTSTORE = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            X509_ASN_ENCODING,
            None,
            flags,
            Some(store_name_w.as_ptr() as *const _),
        )
        .map_err(|e| StoreError::Crypto(format!("CertOpenStore({store_name}): {e}")))?;

        let mut results = Vec::new();
        let mut pctx: *mut CERT_CONTEXT = ptr::null_mut();

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
            match parse_der_ca(der, store_name, location.as_str()) {
                Ok(rec) => results.push(rec),
                Err(_) => continue,
            }
        }

        let _ = CertCloseStore(Some(hstore), 0);
        Ok(results)
    }
}

#[cfg(windows)]
pub fn read_all_common_stores() -> Result<Vec<CaRecord>, StoreError> {
    let mut all = Vec::new();
    for (name, loc) in COMMON_STORES {
        match read_store(name, *loc) {
            Ok(mut recs) => all.append(&mut recs),
            Err(_) => continue,
        }
    }
    Ok(all)
}

/// Export raw DER for a certificate identified by SHA-1 fingerprint from a store.
#[cfg(windows)]
pub fn export_der_by_sha1(
    store_name: &str,
    location: StoreLocation,
    sha1: &str,
) -> Result<Vec<u8>, StoreError> {
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertOpenStore, CERT_CONTEXT,
        CERT_OPEN_STORE_FLAGS, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
        CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE, HCERTSTORE,
        X509_ASN_ENCODING,
    };

    let target = ctls_core::normalize_fingerprint(sha1);
    let loc = match location {
        StoreLocation::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
        StoreLocation::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
    };
    let flags = CERT_OPEN_STORE_FLAGS(loc | CERT_STORE_READONLY_FLAG.0);
    let store_name_w: Vec<u16> = store_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let hstore: HCERTSTORE = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            X509_ASN_ENCODING,
            None,
            flags,
            Some(store_name_w.as_ptr() as *const _),
        )
        .map_err(|e| StoreError::Crypto(format!("CertOpenStore({store_name}): {e}")))?;

        let mut pctx: *mut CERT_CONTEXT = std::ptr::null_mut();
        let mut found: Option<Vec<u8>> = None;

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
            if ctls_core::sha1_hex(der) == target {
                found = Some(der.to_vec());
                break;
            }
        }

        let _ = CertCloseStore(Some(hstore), 0);
        found.ok_or_else(|| StoreError::Crypto(format!("sha1 {sha1} not found")))
    }
}

#[cfg(not(windows))]
pub fn export_der_by_sha1(
    _store_name: &str,
    _location: StoreLocation,
    _sha1: &str,
) -> Result<Vec<u8>, StoreError> {
    Err(StoreError::Crypto("not windows".into()))
}

#[cfg(not(windows))]
pub fn read_store(
    _store_name: &str,
    _location: StoreLocation,
) -> Result<Vec<CaRecord>, StoreError> {
    Err(StoreError::Crypto("not windows".into()))
}

#[cfg(not(windows))]
pub fn read_all_common_stores() -> Result<Vec<CaRecord>, StoreError> {
    Err(StoreError::Crypto("not windows".into()))
}

/// Abstraction over OS trust stores (matches target architecture `PlatformStore`).
/// Core/UI never touch the registry/CertStore API directly.
pub trait PlatformStore {
    fn list_system_cas(&self) -> Result<Vec<CaRecord>, StoreError>;
    fn install_ca(
        &self,
        der: &[u8],
        store_name: &str,
        location: StoreLocation,
    ) -> Result<(), StoreError>;
    fn remove_ca(
        &self,
        sha1: &str,
        store_name: &str,
        location: StoreLocation,
    ) -> Result<bool, StoreError>;
}

/// Windows implementation of [`PlatformStore`].
pub struct WinStore;

impl PlatformStore for WinStore {
    fn list_system_cas(&self) -> Result<Vec<CaRecord>, StoreError> {
        read_all_common_stores()
    }

    fn install_ca(
        &self,
        der: &[u8],
        store_name: &str,
        location: StoreLocation,
    ) -> Result<(), StoreError> {
        install_ca(der, store_name, location)
    }

    fn remove_ca(
        &self,
        sha1: &str,
        store_name: &str,
        location: StoreLocation,
    ) -> Result<bool, StoreError> {
        remove_ca_by_sha1(sha1, store_name, location)
    }
}

/// Install a certificate DER into a system store.
/// LocalMachine requires administrator rights.
#[cfg(windows)]
pub fn install_ca(der: &[u8], store_name: &str, location: StoreLocation) -> Result<(), StoreError> {
    use windows::Win32::Security::Cryptography::{
        CertAddCertificateContextToStore, CertCloseStore, CertCreateCertificateContext,
        CertOpenStore, CERT_OPEN_STORE_FLAGS, CERT_STORE_ADD_REPLACE_EXISTING,
        CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE,
        HCERTSTORE, X509_ASN_ENCODING,
    };

    if location == StoreLocation::LocalMachine && !crate::purger::is_admin() {
        return Err(StoreError::Crypto(
            "administrator required for LocalMachine stores".into(),
        ));
    }

    let loc = match location {
        StoreLocation::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
        StoreLocation::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
    };
    let store_name_w: Vec<u16> = store_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let hstore: HCERTSTORE = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            X509_ASN_ENCODING,
            None,
            CERT_OPEN_STORE_FLAGS(loc),
            Some(store_name_w.as_ptr() as *const _),
        )
        .map_err(|e| StoreError::Crypto(format!("CertOpenStore({store_name}): {e}")))?;

        let pctx = CertCreateCertificateContext(X509_ASN_ENCODING, der);
        if pctx.is_null() {
            let _ = CertCloseStore(Some(hstore), 0);
            return Err(StoreError::Parse("invalid certificate DER".into()));
        }
        let mut out = std::ptr::null_mut();
        let ok = CertAddCertificateContextToStore(
            Some(hstore),
            pctx,
            CERT_STORE_ADD_REPLACE_EXISTING,
            Some(&mut out),
        );
        let _ = CertCloseStore(Some(hstore), 0);
        ok.map_err(|e| StoreError::Crypto(format!("CertAddCertificateContextToStore: {e}")))?;
    }
    Ok(())
}

/// Remove one certificate by SHA-1 from a store. Returns true if found & deleted.
#[cfg(windows)]
pub fn remove_ca_by_sha1(
    sha1: &str,
    store_name: &str,
    location: StoreLocation,
) -> Result<bool, StoreError> {
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertDeleteCertificateFromStore, CertEnumCertificatesInStore, CertOpenStore,
        CERT_CONTEXT, CERT_OPEN_STORE_FLAGS, CERT_STORE_PROV_SYSTEM_W,
        CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE, HCERTSTORE,
        X509_ASN_ENCODING,
    };

    if location == StoreLocation::LocalMachine && !crate::purger::is_admin() {
        return Err(StoreError::Crypto(
            "administrator required for LocalMachine stores".into(),
        ));
    }

    let target = ctls_core::normalize_fingerprint(sha1);
    let loc = match location {
        StoreLocation::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
        StoreLocation::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
    };
    let store_name_w: Vec<u16> = store_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let hstore: HCERTSTORE = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            X509_ASN_ENCODING,
            None,
            CERT_OPEN_STORE_FLAGS(loc),
            Some(store_name_w.as_ptr() as *const _),
        )
        .map_err(|e| StoreError::Crypto(format!("CertOpenStore({store_name}): {e}")))?;

        let mut cur: *mut CERT_CONTEXT = std::ptr::null_mut();
        let mut found = false;
        loop {
            cur = CertEnumCertificatesInStore(hstore, Some(cur));
            if cur.is_null() {
                break;
            }
            let ctx = &*cur;
            let der = std::slice::from_raw_parts(
                ctx.pbCertEncoded as *const u8,
                ctx.cbCertEncoded as usize,
            );
            if ctls_core::normalize_fingerprint(&ctls_core::sha1_hex(der)) == target {
                if CertDeleteCertificateFromStore(cur).is_ok() {
                    found = true;
                }
                // `cur` freed by delete — do not close-store walk further on it.
                break;
            }
        }
        let _ = CertCloseStore(Some(hstore), 0);
        Ok(found)
    }
}

#[cfg(not(windows))]
pub fn install_ca(
    _der: &[u8],
    _store_name: &str,
    _location: StoreLocation,
) -> Result<(), StoreError> {
    Err(StoreError::Crypto("not windows".into()))
}

#[cfg(not(windows))]
pub fn remove_ca_by_sha1(
    _sha1: &str,
    _store_name: &str,
    _location: StoreLocation,
) -> Result<bool, StoreError> {
    Err(StoreError::Crypto("not windows".into()))
}

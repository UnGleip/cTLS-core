//! Master-key protection backends (Phase 1: hardware-backed key storage).
//!
//! Rules:
//! - The 32-byte vault master key never touches the disk unwrapped.
//! - On Windows a *new* vault prefers the TPM (`Microsoft Platform Crypto
//!   Provider`): a non-exportable RSA-2048 wrap key + OAEP-SHA256. Bulk data
//!   is encrypted with an ephemeral AES-256-GCM data key, which is what gets
//!   TPM-wrapped (payload limit of OAEP never applies to the vault key).
//! - If the TPM is unavailable we fall back to DPAPI and report
//!   `degraded=true` (the caller audits it). The backend of an *existing*
//!   vault is never switched silently: unwrap failures surface as errors.
//! - unix: identity wrap + 0600 file mode (Android Keystore / iOS Keychain
//!   are on the roadmap — see docs/ROADMAP.md).

use crate::VaultError;
#[cfg(windows)]
use aes_gcm::aead::{Aead, KeyInit, OsRng};
#[cfg(windows)]
use aes_gcm::{Aes256Gcm, Key, Nonce};
#[cfg(windows)]
use rand::RngCore;
#[cfg(windows)]
use zeroize::Zeroizing;

pub const NAME_TPM: &str = "windows-tpm";
pub const NAME_DPAPI: &str = "windows-dpapi";
pub const NAME_FILE: &str = "unix-file-0600";

/// Canonicalize a recorded backend name.
pub fn canonical(name: &str) -> Option<&'static str> {
    match name {
        NAME_TPM => Some(NAME_TPM),
        NAME_DPAPI => Some(NAME_DPAPI),
        NAME_FILE => Some(NAME_FILE),
        _ => None,
    }
}

/// Backend assumed for vaults created before backend tracking existed
/// (legacy blobs were DPAPI on Windows, identity elsewhere).
pub fn platform_default_name() -> &'static str {
    if cfg!(windows) {
        NAME_DPAPI
    } else {
        NAME_FILE
    }
}

/// Wrap a fresh master key. Returns `(backend_name, blob, degrade_note)`.
/// On Windows the TPM is tried first; on failure DPAPI is used and a note
/// describing the degraded mode is returned for the audit log.
pub fn protect_new(data: &[u8]) -> Result<(&'static str, Vec<u8>, Option<String>), VaultError> {
    #[cfg(windows)]
    {
        match tpm::protect(data) {
            Ok(blob) => Ok((NAME_TPM, blob, None)),
            Err(e) => {
                let blob = dpapi::protect(data)?;
                Ok((
                    NAME_DPAPI,
                    blob,
                    Some(format!("TPM unavailable, degraded to DPAPI: {e}")),
                ))
            }
        }
    }
    #[cfg(not(windows))]
    {
        let blob = file::protect(data)?;
        Ok((NAME_FILE, blob, None))
    }
}

/// Unwrap with exactly the backend recorded for this vault (fail-closed:
/// no cross-backend guessing — a TPM-wrapped blob is not retried under DPAPI).
pub fn unprotect_existing(name: &str, blob: &[u8]) -> Result<Vec<u8>, VaultError> {
    match name {
        NAME_TPM => {
            #[cfg(windows)]
            {
                tpm::unprotect(blob).map_err(|e| {
                    VaultError::Backend(format!(
                        "master key is TPM-bound ({NAME_TPM}) but the TPM could not unwrap it: \
                         {e}. Re-enable/unlock the TPM or restore the vault from backup"
                    ))
                })
            }
            #[cfg(not(windows))]
            {
                Err(VaultError::Backend(format!(
                    "backend {NAME_TPM} recorded but not available on this platform"
                )))
            }
        }
        NAME_DPAPI => {
            #[cfg(windows)]
            {
                dpapi::unprotect(blob)
            }
            #[cfg(not(windows))]
            {
                Err(VaultError::Backend(format!(
                    "backend {NAME_DPAPI} recorded but not available on this platform"
                )))
            }
        }
        NAME_FILE => {
            #[cfg(not(windows))]
            {
                file::unprotect(blob)
            }
            #[cfg(windows)]
            {
                // Identity blob written on unix: readable as-is (the vault
                // file itself is what protected it).
                Ok(blob.to_vec())
            }
        }
        other => Err(VaultError::Backend(format!(
            "unknown key backend recorded in vault: {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Windows: TPM via the Microsoft Platform Crypto Provider (NCrypt)
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod tpm {
    use super::*;
    use core::ffi::c_void;
    use windows::core::{w, PCWSTR};
    use windows::Win32::Security::Cryptography::*;

    const PROVIDER: PCWSTR = w!("Microsoft Platform Crypto Provider");
    const WRAP_KEY: PCWSTR = w!("ctls-vault-wrap-v1");
    const HEADER: &[u8; 4] = b"CTP1";
    /// RSA-2048 / OAEP-SHA256 can wrap at most 256 - 2*32 - 2 = 190 bytes.
    const MAX_WRAPPED: usize = 512;

    struct Provider(NCRYPT_PROV_HANDLE);
    impl Drop for Provider {
        fn drop(&mut self) {
            unsafe {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(self.0 .0));
            }
        }
    }

    struct WrapKey(NCRYPT_KEY_HANDLE);
    impl Drop for WrapKey {
        fn drop(&mut self) {
            unsafe {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(self.0 .0));
            }
        }
    }

    fn backend_err(ctx: &str, e: impl std::fmt::Display) -> VaultError {
        VaultError::Backend(format!("tpm {ctx}: {e}"))
    }

    /// Serializes open/create of the wrap key inside this process: two
    /// concurrent first-use creates used to leave the persisted key in a
    /// state that could encrypt but not decrypt.
    static OPEN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe fn try_open(prov: NCRYPT_PROV_HANDLE) -> Option<WrapKey> {
        let mut key = NCRYPT_KEY_HANDLE(0);
        NCryptOpenKey(prov, &mut key, WRAP_KEY, CERT_KEY_SPEC(0), NCRYPT_FLAGS(0))
            .ok()
            .map(|_| WrapKey(key))
    }

    unsafe fn open_wrap_key(prov: NCRYPT_PROV_HANDLE) -> Result<WrapKey, VaultError> {
        let _guard = OPEN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(key) = try_open(prov) {
            return Ok(key);
        }
        // First use on this machine: persist a non-exportable RSA wrap key.
        let mut created = NCRYPT_KEY_HANDLE(0);
        if let Err(create_err) = NCryptCreatePersistedKey(
            prov,
            &mut created,
            BCRYPT_RSA_ALGORITHM,
            WRAP_KEY,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        ) {
            // Another process may have created it between our open and
            // create — retry open before giving up.
            return try_open(prov).ok_or_else(|| backend_err("create-key", create_err));
        }
        NCryptSetProperty(
            NCRYPT_HANDLE(created.0),
            NCRYPT_LENGTH_PROPERTY,
            &2048u32.to_le_bytes(),
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| backend_err("set-length", e))?;
        // Non-exportable: refuse to ever export the wrapping key.
        NCryptSetProperty(
            NCRYPT_HANDLE(created.0),
            NCRYPT_EXPORT_POLICY_PROPERTY,
            &0u32.to_le_bytes(),
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| backend_err("set-export-policy", e))?;
        NCryptFinalizeKey(created, NCRYPT_FLAGS(0)).map_err(|e| backend_err("finalize-key", e))?;
        // Self-test: a key we cannot round-trip must never be recorded as
        // the vault's backend — fail here so the caller degrades to DPAPI.
        let canary = [0xA5u8; 32];
        let wrapped = oaep_encrypt_on(created, &canary)?;
        let back = Zeroizing::new(oaep_decrypt_on(created, &wrapped)?);
        if back.as_slice() != canary {
            return Err(VaultError::Backend(
                "tpm key creation self-test failed (round-trip mismatch)".into(),
            ));
        }
        Ok(WrapKey(created))
    }

    unsafe fn oaep_encrypt_on(key: NCRYPT_KEY_HANDLE, data: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut out = vec![0u8; MAX_WRAPPED];
        let mut written: u32 = 0;
        let pad = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
            pbLabel: std::ptr::null_mut(),
            cbLabel: 0,
        };
        NCryptEncrypt(
            key,
            Some(data),
            Some(&pad as *const BCRYPT_OAEP_PADDING_INFO as *const c_void),
            Some(out.as_mut_slice()),
            &mut written,
            NCRYPT_PAD_OAEP_FLAG,
        )
        .map_err(|e| backend_err("encrypt", e))?;
        out.truncate(written as usize);
        Ok(out)
    }

    unsafe fn oaep_decrypt_on(
        key: NCRYPT_KEY_HANDLE,
        wrapped: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let mut out = vec![0u8; MAX_WRAPPED];
        let mut written: u32 = 0;
        let pad = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
            pbLabel: std::ptr::null_mut(),
            cbLabel: 0,
        };
        NCryptDecrypt(
            key,
            Some(wrapped),
            Some(&pad as *const BCRYPT_OAEP_PADDING_INFO as *const c_void),
            Some(out.as_mut_slice()),
            &mut written,
            NCRYPT_PAD_OAEP_FLAG,
        )
        .map_err(|e| backend_err("decrypt", e))?;
        out.truncate(written as usize);
        Ok(out)
    }

    fn oaep_wrap(data: &[u8]) -> Result<Vec<u8>, VaultError> {
        let provider = open_provider()?;
        let key = unsafe { open_wrap_key(provider.0) }?;
        unsafe { oaep_encrypt_on(key.0, data) }
    }

    fn oaep_unwrap(wrapped: &[u8]) -> Result<Vec<u8>, VaultError> {
        let provider = open_provider()?;
        let key = unsafe { open_wrap_key(provider.0) }?;
        unsafe { oaep_decrypt_on(key.0, wrapped) }
    }

    fn open_provider() -> Result<Provider, VaultError> {
        let mut prov = NCRYPT_PROV_HANDLE(0);
        unsafe { NCryptOpenStorageProvider(&mut prov, PROVIDER, 0) }
            .map_err(|e| backend_err("open-provider", e))?;
        Ok(Provider(prov))
    }

    /// `blob = "CTP1" || u32le(wrapped_len) || wrapped_aes_key || nonce || ct`
    pub(super) fn protect(data: &[u8]) -> Result<Vec<u8>, VaultError> {
        let mut aes_key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut aes_key[..]);
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key[..]));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), data)
            .map_err(|e| VaultError::Crypto(e.to_string()))?;
        let wrapped = oaep_wrap(&aes_key[..])?;
        let mut out = Vec::with_capacity(HEADER.len() + 4 + wrapped.len() + nonce.len() + ct.len());
        out.extend_from_slice(HEADER);
        out.extend_from_slice(&(wrapped.len() as u32).to_le_bytes());
        out.extend_from_slice(&wrapped);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub(super) fn unprotect(blob: &[u8]) -> Result<Vec<u8>, VaultError> {
        if blob.len() < HEADER.len() + 4 || &blob[..HEADER.len()] != HEADER {
            return Err(VaultError::Backend("bad TPM blob header".into()));
        }
        let wl = u32::from_le_bytes(
            blob[4..8]
                .try_into()
                .map_err(|_| VaultError::Backend("bad TPM blob length".into()))?,
        ) as usize;
        if blob.len() < 8 + wl + 12 {
            return Err(VaultError::Backend("truncated TPM blob".into()));
        }
        let wrapped = &blob[8..8 + wl];
        let nonce = &blob[8 + wl..8 + wl + 12];
        let ct = &blob[8 + wl + 12..];
        let aes_key = Zeroizing::new(oaep_unwrap(wrapped)?);
        if aes_key.len() != 32 {
            return Err(VaultError::Backend(
                "unwrapped data key length != 32".into(),
            ));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&aes_key);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key[..]));
        cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|e| VaultError::Crypto(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Windows: DPAPI (software fallback + legacy default)
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod dpapi {
    use super::*;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };

    pub(super) fn protect(data: &[u8]) -> Result<Vec<u8>, VaultError> {
        unsafe {
            let in_blob = CRYPT_INTEGER_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };
            let mut out_blob = CRYPT_INTEGER_BLOB::default();
            CryptProtectData(
                &in_blob,
                windows::core::PCWSTR::null(),
                None,
                None,
                None,
                0,
                &mut out_blob,
            )
            .map_err(|e| VaultError::Backend(format!("dpapi protect: {e}")))?;
            let out =
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
            let _ = LocalFree(Some(HLOCAL(out_blob.pbData as _)));
            Ok(out)
        }
    }

    pub(super) fn unprotect(data: &[u8]) -> Result<Vec<u8>, VaultError> {
        unsafe {
            let in_blob = CRYPT_INTEGER_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };
            let mut out_blob = CRYPT_INTEGER_BLOB::default();
            CryptUnprotectData(&in_blob, None, None, None, None, 0, &mut out_blob)
                .map_err(|e| VaultError::Backend(format!("dpapi unprotect: {e}")))?;
            let out =
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
            let _ = LocalFree(Some(HLOCAL(out_blob.pbData as _)));
            Ok(out)
        }
    }
}

// ---------------------------------------------------------------------------
// unix: identity wrap (file mode 0600 is the actual protection)
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
mod file {
    use super::*;

    pub(super) fn protect(data: &[u8]) -> Result<Vec<u8>, VaultError> {
        Ok(data.to_vec())
    }

    pub(super) fn unprotect(data: &[u8]) -> Result<Vec<u8>, VaultError> {
        Ok(data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_name_canonicalization() {
        assert_eq!(canonical(NAME_TPM), Some(NAME_TPM));
        assert_eq!(canonical("garbage"), None);
        assert!(platform_default_name() == NAME_DPAPI || platform_default_name() == NAME_FILE);
    }

    #[test]
    fn protect_new_unprotect_roundtrip() {
        let key = [7u8; 32];
        let (name, blob, note) = protect_new(&key).unwrap();
        eprintln!("backend={name} degrade_note={note:?}");
        let raw = unprotect_existing(name, &blob).unwrap();
        assert_eq!(raw, key);
        // re-unwrap through the canonical name (as a reopened vault would)
        let raw2 = unprotect_existing(canonical(name).unwrap(), &blob).unwrap();
        assert_eq!(raw2, key);
    }

    #[test]
    fn wrong_backend_fails_closed() {
        let (_name, blob, _note) = protect_new(&[9u8; 32]).unwrap();
        if !cfg!(windows) {
            // a unix (identity) blob must not silently open as DPAPI etc.
            assert!(unprotect_existing(NAME_DPAPI, &blob).is_err());
        }
        assert!(unprotect_existing("no-such-backend", &blob).is_err());
    }

    /// Exercises the real TPM path when this machine has one; skipped
    /// (with a note) when it does not.
    #[cfg(windows)]
    #[test]
    fn tpm_roundtrip_if_available() {
        match tpm::protect(b"phase1-hardware-key-test") {
            Ok(blob) => {
                let raw = tpm::unprotect(&blob).unwrap();
                assert_eq!(raw, b"phase1-hardware-key-test");
                eprintln!("TPM backend available and round-trips");
            }
            Err(e) => eprintln!("TPM unavailable on this machine, skipping: {e}"),
        }
    }
}

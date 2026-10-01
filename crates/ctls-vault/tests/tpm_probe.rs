//! Probe: which NCrypt parameters make TPM OAEP decrypt work?
//! (temporary diagnostic for the windows-tpm key backend)

#![cfg(windows)]

use windows::core::{w, HSTRING};
use windows::Win32::Security::Cryptography::*;

unsafe fn create_or_open(
    prov: NCRYPT_PROV_HANDLE,
    name: &str,
    spec: CERT_KEY_SPEC,
) -> Result<NCRYPT_KEY_HANDLE, String> {
    let hs = HSTRING::from(name);
    let mut key = NCRYPT_KEY_HANDLE(0);
    if NCryptOpenKey(prov, &mut key, &hs, spec, NCRYPT_FLAGS(0)).is_ok() {
        return Ok(key);
    }
    NCryptCreatePersistedKey(
        prov,
        &mut key,
        BCRYPT_RSA_ALGORITHM,
        &hs,
        spec,
        NCRYPT_FLAGS(0),
    )
    .map_err(|e| format!("create: {e}"))?;
    NCryptSetProperty(
        NCRYPT_HANDLE(key.0),
        NCRYPT_LENGTH_PROPERTY,
        &2048u32.to_le_bytes(),
        NCRYPT_FLAGS(0),
    )
    .map_err(|e| format!("len: {e}"))?;
    NCryptSetProperty(
        NCRYPT_HANDLE(key.0),
        NCRYPT_EXPORT_POLICY_PROPERTY,
        &0u32.to_le_bytes(),
        NCRYPT_FLAGS(0),
    )
    .map_err(|e| format!("exp: {e}"))?;
    NCryptFinalizeKey(key, NCRYPT_FLAGS(0)).map_err(|e| format!("finalize: {e}"))?;
    Ok(key)
}

unsafe fn enc(
    key: NCRYPT_KEY_HANDLE,
    hash: windows::core::PCWSTR,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let pad = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: hash,
        pbLabel: std::ptr::null_mut(),
        cbLabel: 0,
    };
    let mut out = vec![0u8; 512];
    let mut written = 0u32;
    NCryptEncrypt(
        key,
        Some(data),
        Some(&pad as *const BCRYPT_OAEP_PADDING_INFO as *const _),
        Some(out.as_mut_slice()),
        &mut written,
        NCRYPT_PAD_OAEP_FLAG,
    )
    .map_err(|e| format!("encrypt: {e}"))?;
    out.truncate(written as usize);
    Ok(out)
}

unsafe fn dec(
    key: NCRYPT_KEY_HANDLE,
    hash: windows::core::PCWSTR,
    wrapped: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, String> {
    let pad = BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: hash,
        pbLabel: std::ptr::null_mut(),
        cbLabel: 0,
    };
    let mut out = vec![0u8; out_len];
    let mut written = 0u32;
    NCryptDecrypt(
        key,
        Some(wrapped),
        Some(&pad as *const BCRYPT_OAEP_PADDING_INFO as *const _),
        Some(out.as_mut_slice()),
        &mut written,
        NCRYPT_PAD_OAEP_FLAG,
    )
    .map_err(|e| format!("decrypt(out={out_len}): {e}"))?;
    out.truncate(written as usize);
    Ok(out)
}

#[test]
fn probe_tpm_oaep_combos() {
    unsafe {
        let mut prov = NCRYPT_PROV_HANDLE(0);
        if let Err(e) =
            NCryptOpenStorageProvider(&mut prov, w!("Microsoft Platform Crypto Provider"), 0)
        {
            eprintln!("no platform crypto provider: {e}");
            return;
        }
        let combos: [(&str, CERT_KEY_SPEC, windows::core::PCWSTR); 6] = [
            ("spec0-sha256", CERT_KEY_SPEC(0), BCRYPT_SHA256_ALGORITHM),
            ("spec1-sha256", CERT_KEY_SPEC(1), BCRYPT_SHA256_ALGORITHM),
            ("spec2-sha256", CERT_KEY_SPEC(2), BCRYPT_SHA256_ALGORITHM),
            ("spec0-sha1", CERT_KEY_SPEC(0), BCRYPT_SHA1_ALGORITHM),
            ("spec1-sha1", CERT_KEY_SPEC(1), BCRYPT_SHA1_ALGORITHM),
            ("spec2-sha1", CERT_KEY_SPEC(2), BCRYPT_SHA1_ALGORITHM),
        ];
        for (label, spec, hash) in combos {
            let name = format!("ctls-probe-{label}");
            let key = match create_or_open(prov, &name, spec) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("{label}: create failed: {e}");
                    continue;
                }
            };
            let plaintext = [0x42u8; 32];
            let wrapped = match enc(key, hash, &plaintext) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("{label}: {e}");
                    continue;
                }
            };
            let d512 = dec(key, hash, &wrapped, 512);
            let d256 = dec(key, hash, &wrapped, 256);
            let d_nopad = {
                let mut out = vec![0u8; 512];
                let mut written = 0u32;
                NCryptDecrypt(
                    key,
                    Some(wrapped.as_slice()),
                    None,
                    Some(out.as_mut_slice()),
                    &mut written,
                    NCRYPT_FLAGS(0),
                )
                .map_err(|e| format!("dec-nopad: {e}"))
                .map(|_| {
                    out.truncate(written as usize);
                    out
                })
            };
            eprintln!(
                "{label}: enc ok ({}B) | dec512={} | dec256={} | dec-pkcs1-nopad={}",
                wrapped.len(),
                match &d512 {
                    Ok(v) => format!("OK {}B", v.len()),
                    Err(e) => e.clone(),
                },
                match &d256 {
                    Ok(v) => format!("OK {}B", v.len()),
                    Err(e) => e.clone(),
                },
                match &d_nopad {
                    Ok(v) => format!("OK {}B", v.len()),
                    Err(e) => e.clone(),
                },
            );
            let _ = NCryptDeleteKey(key, 0);
            let _ = NCryptFreeObject(NCRYPT_HANDLE(key.0));
        }
        let _ = NCryptFreeObject(NCRYPT_HANDLE(prov.0));
    }
}

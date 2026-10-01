//! iOS trust store — **read-only stub**.
//!
//! The iOS system root store is not enumerable from an app sandbox and
//! certificates cannot be added to it programmatically (Apple manages trust
//! centrally). The mobile UI can still manage the isolated Vault + Gateway;
//! bundle-pinned roots are read from the app bundle by the UI layer.
//!
//! Future: Security.framework (`SecTrustSettings*` is macOS-only) / Keychain
//! for vault key storage via `crate`-level FFI.

use crate::{PlatformError, PlatformStore, StoreLocation};
use ctls_core::CaRecord;

#[derive(Default)]
pub struct IosStore;

impl PlatformStore for IosStore {
    fn platform_name(&self) -> &'static str {
        "ios"
    }

    fn list_system_cas(&self) -> Result<Vec<CaRecord>, PlatformError> {
        // System roots are not readable from the sandbox; return empty
        // (never an error — the UI still works with Vault-only data).
        Ok(Vec::new())
    }

    fn export_der(&self, sha1: &str) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::NotFound(sha1.to_string()))
    }

    fn install_ca(
        &self,
        _der: &[u8],
        _store_name: &str,
        _location: StoreLocation,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::not_supported(
            "ios",
            "iOS does not allow apps to modify system trust; use MDM/profiles",
        ))
    }

    fn remove_ca(
        &self,
        _sha1: &str,
        _store_name: &str,
        _location: StoreLocation,
    ) -> Result<bool, PlatformError> {
        Err(PlatformError::not_supported(
            "ios",
            "iOS does not allow apps to modify system trust",
        ))
    }

    fn can_modify(&self) -> bool {
        false
    }
}

//! Windows implementation — delegates to the `ctls-platform-win` crate.

use crate::{PlatformError, PlatformStore, StoreLocation};
use ctls_core::CaRecord;

#[derive(Default)]
pub struct WindowsStore;

impl PlatformStore for WindowsStore {
    fn platform_name(&self) -> &'static str {
        "windows"
    }

    fn list_system_cas(&self) -> Result<Vec<CaRecord>, PlatformError> {
        ctls_platform_win::read_all_common_stores().map_err(|e| PlatformError::Msg(e.to_string()))
    }

    fn export_der(&self, sha1: &str) -> Result<Vec<u8>, PlatformError> {
        let mut last_err = PlatformError::NotFound(sha1.to_string());
        for (name, loc) in ctls_platform_win::COMMON_STORES {
            match ctls_platform_win::export_der_by_sha1(name, *loc, sha1) {
                Ok(der) => return Ok(der),
                Err(e) => last_err = PlatformError::Msg(e.to_string()),
            }
        }
        Err(last_err)
    }

    fn install_ca(
        &self,
        der: &[u8],
        store_name: &str,
        location: StoreLocation,
    ) -> Result<(), PlatformError> {
        let loc = match location {
            StoreLocation::CurrentUser => ctls_platform_win::StoreLocation::CurrentUser,
            StoreLocation::LocalMachine => ctls_platform_win::StoreLocation::LocalMachine,
        };
        ctls_platform_win::install_ca(der, store_name, loc)
            .map_err(|e| PlatformError::Msg(e.to_string()))
    }

    fn remove_ca(
        &self,
        sha1: &str,
        store_name: &str,
        location: StoreLocation,
    ) -> Result<bool, PlatformError> {
        let loc = match location {
            StoreLocation::CurrentUser => ctls_platform_win::StoreLocation::CurrentUser,
            StoreLocation::LocalMachine => ctls_platform_win::StoreLocation::LocalMachine,
        };
        ctls_platform_win::remove_ca_by_sha1(sha1, store_name, loc)
            .map_err(|e| PlatformError::Msg(e.to_string()))
    }

    fn can_modify(&self) -> bool {
        true
    }
}

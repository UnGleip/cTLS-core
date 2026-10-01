//! Cross-platform trust-store abstraction.
//!
//! One [`PlatformStore`] trait for every OS; UIs and the CLI only talk to this
//! crate and never touch CertStore APIs / filesystem paths directly.
//!
//! | OS | list | install/remove | notes |
//! |---|---|---|---|
//! | Windows | CertStore (common stores) | yes (admin for LocalMachine) | full impl |
//! | Linux | `/etc/ssl/certs`, bundles, `/usr/local/share/ca-certificates` | yes (root) | `update-ca-certificates` / `update-ca-trust` |
//! | Android | `/system/etc/security/cacerts` | no (read-only for apps) | install via Kotlin `DevicePolicyManager` later |
//! | iOS | not enumerable from sandbox | no | list returns empty; Keychain later |

use ctls_core::CaRecord;

pub mod platform_impl;

pub use platform_impl::current_store;

/// Where a certificate lives / should be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StoreLocation {
    /// Per-user scope (Windows `CurrentUser`, `~/.local/share/ctls` on Unix).
    CurrentUser,
    /// Machine-wide scope (Windows `LocalMachine`, `/usr/local/share/ca-certificates`, …).
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

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("not supported on {platform}: {reason}")]
    NotSupported { platform: String, reason: String },
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Msg(String),
}

impl PlatformError {
    pub fn not_supported(platform: &str, reason: &str) -> Self {
        PlatformError::NotSupported {
            platform: platform.to_string(),
            reason: reason.to_string(),
        }
    }
}

/// OS trust-store operations. All methods are read-only unless stated.
pub trait PlatformStore: Send + Sync {
    /// Stable identifier: `windows` / `linux` / `android` / `ios`.
    fn platform_name(&self) -> &'static str;

    /// Enumerate CA certificates the OS trusts (never fails hard —
    /// unreadable locations are skipped).
    fn list_system_cas(&self) -> Result<Vec<CaRecord>, PlatformError>;

    /// Raw DER of a certificate by SHA-1 fingerprint (searches all stores).
    fn export_der(&self, sha1: &str) -> Result<Vec<u8>, PlatformError>;

    /// Write a certificate into a store. May require elevation
    /// (Windows LocalMachine, Linux system dir).
    fn install_ca(
        &self,
        der: &[u8],
        store_name: &str,
        location: StoreLocation,
    ) -> Result<(), PlatformError>;

    /// Remove by SHA-1. Returns `Ok(false)` when not found.
    fn remove_ca(
        &self,
        sha1: &str,
        store_name: &str,
        location: StoreLocation,
    ) -> Result<bool, PlatformError>;

    /// Whether this platform allows apps to mutate its trust store at all.
    fn can_modify(&self) -> bool;
}

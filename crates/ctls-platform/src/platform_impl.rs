//! OS dispatch for [`crate::current_store`].

#[cfg(windows)]
pub mod windows;

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
pub mod linux;

#[cfg(target_os = "android")]
pub mod android;

#[cfg(target_os = "ios")]
pub mod ios;

#[cfg(windows)]
pub use windows::WindowsStore as CurrentImpl;

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
pub use linux::LinuxStore as CurrentImpl;

#[cfg(target_os = "android")]
pub use android::AndroidStore as CurrentImpl;

#[cfg(target_os = "ios")]
pub use ios::IosStore as CurrentImpl;

use crate::PlatformStore;

/// The store implementation for the OS this binary was compiled for.
pub fn current_store() -> Box<dyn PlatformStore> {
    Box::<CurrentImpl>::default()
}

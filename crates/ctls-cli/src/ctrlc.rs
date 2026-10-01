//! Minimal Ctrl+C handler.

#[cfg(windows)]
static CALLBACK: std::sync::OnceLock<Box<dyn Fn() + Send + Sync>> = std::sync::OnceLock::new();

#[cfg(windows)]
unsafe extern "system" fn handler(_ctrl_type: u32) -> windows::core::BOOL {
    if let Some(cb) = CALLBACK.get() {
        cb();
    }
    windows::core::BOOL(1)
}

pub fn ctrlc_set(f: impl Fn() + Send + Sync + 'static) {
    #[cfg(windows)]
    {
        use windows::Win32::System::Console::SetConsoleCtrlHandler;
        let _ = CALLBACK.set(Box::new(f));
        unsafe {
            let _ = SetConsoleCtrlHandler(Some(handler), true);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = f;
    }
}

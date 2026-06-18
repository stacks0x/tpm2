pub mod commands;
pub mod properties;
pub mod rc;
pub mod wire;

#[cfg(windows)]
mod platform;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(windows)]
pub use platform::*;

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(any(windows, target_os = "linux")))]
pub fn submit_tpm_command(_cmd: &[u8]) -> Result<Vec<u8>, String> {
    Err("TPM transport is only available on Windows and Linux".to_string())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn device_path() -> Option<&'static str> {
    None
}

#[cfg(any(windows, target_os = "linux"))]
pub fn is_available() -> bool {
    let cmd = commands::get_random_8();
    match submit_tpm_command(&cmd) {
        Ok(resp) => commands::tpm_rc_from_response(&resp).is_some_and(|rc| rc == 0),
        Err(_) => false,
    }
}

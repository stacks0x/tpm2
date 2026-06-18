pub mod commands;
pub mod rc;
pub mod wire;

#[cfg(windows)]
mod platform;

#[cfg(windows)]
pub use platform::*;

#[cfg(not(windows))]
pub fn submit_tpm_command(_cmd: &[u8]) -> Result<Vec<u8>, String> {
    Err("TBS is Windows-only".to_string())
}

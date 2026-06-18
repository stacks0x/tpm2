//! TPM command layer (Option A: tss-esapi). Behind the `esapi` feature.

#[cfg(all(feature = "esapi", not(target_os = "macos")))]
mod esapi;

#[cfg(all(feature = "esapi", not(target_os = "macos")))]
pub use esapi::*;

#[cfg(not(all(feature = "esapi", not(target_os = "macos"))))]
pub fn is_available() -> bool {
    false
}

#[cfg(not(all(feature = "esapi", not(target_os = "macos"))))]
pub fn probe() -> Result<(), String> {
    Err("tss-esapi backend not enabled (build with --features esapi)".to_string())
}

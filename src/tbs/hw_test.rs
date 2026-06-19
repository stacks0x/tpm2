//! Opt-in hardware integration tests. Default `cargo test` never touches the TPM.

use std::path::Path;

/// Set `TPM2_HARDWARE_TEST=1` to run tests that open `/dev/tpmrm0` (or TBS on Windows).
pub fn enabled() -> bool {
    std::env::var("TPM2_HARDWARE_TEST").ok().as_deref() == Some("1")
        && Path::new("/dev/tpmrm0").exists()
}

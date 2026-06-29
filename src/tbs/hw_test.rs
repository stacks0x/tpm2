//! Opt-in hardware integration tests.
//!
//! - `TPM2_HARDWARE_TEST=1` — read-only smoke tests (EK cert read, PCR read, GetRandom).
//! - `TPM2_ALLOW_MUTATING=1` — additionally allows tests that define NV, extend PCR, seal, etc.
//! - `.local/THIS_IS_DEV_MACHINE` — blocks **mutating** tests on the primary dev machine even
//!   if env vars are set (agents must not opt in here without explicit user permission).

use std::path::Path;

const DEV_MACHINE_MARKER: &str = ".local/THIS_IS_DEV_MACHINE";

/// Read-only hardware tests (no TPM state change).
pub fn enabled() -> bool {
    std::env::var("TPM2_HARDWARE_TEST").ok().as_deref() == Some("1")
        && tpm_device_present()
}

/// Mutating hardware tests — never on the marked dev machine unless user explicitly opts in.
pub fn mutating_enabled() -> bool {
    enabled()
        && std::env::var("TPM2_ALLOW_MUTATING").ok().as_deref() == Some("1")
        && !dev_machine_marker_present()
}

fn tpm_device_present() -> bool {
    #[cfg(target_os = "linux")]
    {
        return Path::new("/dev/tpmrm0").exists();
    }
    #[cfg(windows)]
    {
        return true;
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

fn dev_machine_marker_present() -> bool {
    Path::new(DEV_MACHINE_MARKER).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutating_disabled_when_dev_marker_present() {
        if !Path::new(DEV_MACHINE_MARKER).exists() {
            return;
        }
        std::env::set_var("TPM2_HARDWARE_TEST", "1");
        std::env::set_var("TPM2_ALLOW_MUTATING", "1");
        assert!(!mutating_enabled());
        std::env::remove_var("TPM2_HARDWARE_TEST");
        std::env::remove_var("TPM2_ALLOW_MUTATING");
    }
}

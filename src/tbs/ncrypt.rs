//! NCrypt HRESULT classification for Windows PCP.

use crate::tbs::error::TpmOpError;

/// NCrypt call site — affects elevation-aware disambiguation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NcryptOp {
    General,
    MachineProvision,
    ActivateCredential,
}

const NTE_NOT_FOUND: u32 = 0x8009_0011;
const NTE_BAD_KEYSET: u32 = 0x8009_0016;
const NTE_EXISTS: u32 = 0x8009_000B;
const NTE_INVALID_PARAMETER: u32 = 0x8009_0027;
const NTE_DEVICE_NOT_READY: u32 = 0x8009_0030;
const NTE_PERM: u32 = 0x8009_0010;
const NTE_BAD_FLAGS: u32 = 0x8009_0029;
/// Observed from PCP activation read when caller lacks elevation.
const PCP_TPM_RC_VALUE: u32 = 0x8028_0084;

pub fn classify_ncrypt(hresult: u32, context: &str, op: NcryptOp) -> TpmOpError {
    let context = context.to_string();

    if op == NcryptOp::ActivateCredential && hresult == PCP_TPM_RC_VALUE {
        return if crate::tbs::pcp::is_process_elevated() || crate::tbs::pcp::is_running_as_system()
        {
            TpmOpError::marshalling_tpm_rc(
                context,
                "PCP activation read failed with TPM_RC_VALUE after elevation",
                hresult,
            )
        } else {
            TpmOpError::RequiresElevation {
                context,
                hresult,
            }
        };
    }

    match hresult {
        NTE_NOT_FOUND | NTE_BAD_KEYSET => TpmOpError::KeyNotFound { context, hresult },
        NTE_EXISTS => TpmOpError::AlreadyExists { context, hresult },
        NTE_INVALID_PARAMETER => TpmOpError::invalid_argument(format!(
            "{context}: invalid NCrypt parameter (HRESULT 0x{hresult:08X})"
        )),
        NTE_DEVICE_NOT_READY | NTE_PERM | NTE_BAD_FLAGS => {
            if op == NcryptOp::MachineProvision {
                TpmOpError::RequiresElevation { context, hresult }
            } else {
                TpmOpError::RequiresElevation { context, hresult }
            }
        }
        _ if is_access_denied_hresult(hresult) => {
            if op == NcryptOp::MachineProvision {
                TpmOpError::RequiresElevation { context, hresult }
            } else {
                TpmOpError::access_denied(format!(
                    "{context} (HRESULT 0x{hresult:08X})"
                ))
            }
        }
        _ => TpmOpError::marshalling_hresult(
            context,
            "NCrypt failed",
            hresult,
        ),
    }
}

fn is_access_denied_hresult(hresult: u32) -> bool {
    const ERROR_ACCESS_DENIED: u32 = 5;
    const E_ACCESSDENIED: u32 = 0x8007_0005;
    hresult == ERROR_ACCESS_DENIED || hresult == E_ACCESSDENIED
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tbs::codes;

    #[test]
    fn activate_value_hresult_not_elevated_is_requires_elevation() {
        // Test classifier logic without elevation check by using ActivateCredential op
        // when not elevated - skip if elevated in CI
        #[cfg(windows)]
        if crate::tbs::pcp::is_process_elevated() {
            return;
        }
        let err = classify_ncrypt(
            PCP_TPM_RC_VALUE,
            "NCryptSetProperty(PCP_TPM12_IDACTIVATION)",
            NcryptOp::ActivateCredential,
        );
        assert_eq!(err.code(), codes::REQUIRES_ELEVATION);
        assert_eq!(err.hresult(), Some(PCP_TPM_RC_VALUE));
    }

    #[test]
    fn key_not_found_maps_cleanly() {
        let err = classify_ncrypt(NTE_NOT_FOUND, "NCryptOpenKey", NcryptOp::General);
        assert_eq!(err.code(), codes::KEY_NOT_FOUND);
        assert_eq!(err.hresult(), Some(NTE_NOT_FOUND));
    }
}

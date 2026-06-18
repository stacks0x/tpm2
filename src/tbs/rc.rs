//! TPM 2.0 response code helpers for hand-marshalled probes.

const TPM_RC_FMT1: u32 = 0x0000_0080;
const TPM_RC_A: u32 = 0x0000_0300;
const TPM_RC_VER1_MASK: u32 = 0xFFFF_FF00;
const TPM_RC_VER1: u32 = 0x0000_0100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RcClass {
    Success,
    Auth,
    Format,
    Other,
}

/// Classify a wire-format TPM_RC from the response header.
///
/// Auth-class RCs indicate hierarchy/auth requirements (privilege signal).
/// Format-class RCs indicate malformed commands (fix marshalling first).
pub fn classify_tpm_rc(rc: u32) -> RcClass {
    if rc == 0 {
        return RcClass::Success;
    }

    // Authorization failures (FMT1 | A nibble)
    if (rc & TPM_RC_A) == TPM_RC_A {
        return RcClass::Auth;
    }

    // VER1 parameter/format errors as returned on the wire (0x000001xx)
    if (rc & TPM_RC_VER1_MASK) == TPM_RC_VER1 {
        return RcClass::Format;
    }

    // FMT1 bit set in the error number byte
    if (rc & TPM_RC_FMT1) != 0 {
        return RcClass::Format;
    }

    RcClass::Other
}

pub fn describe_tpm_rc(rc: u32) -> &'static str {
    match classify_tpm_rc(rc) {
        RcClass::Success => "success",
        RcClass::Auth => "auth-class (privilege / hierarchy auth required)",
        RcClass::Format => "format-class (malformed command — fix marshalling, not a privilege result)",
        RcClass::Other => "other TPM error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_is_zero() {
        assert_eq!(classify_tpm_rc(0), RcClass::Success);
    }

    #[test]
    fn size_error_is_format() {
        assert_eq!(classify_tpm_rc(0x0000_017F), RcClass::Format);
    }

    #[test]
    fn attributes_error_is_format() {
        assert_eq!(classify_tpm_rc(0x0000_0143), RcClass::Format);
    }

    #[test]
    fn auth_fail_is_auth() {
        assert_eq!(classify_tpm_rc(0x0000_038E), RcClass::Auth);
    }
}

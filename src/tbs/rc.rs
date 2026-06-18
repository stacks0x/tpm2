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

pub fn classify_tpm_rc(rc: u32) -> RcClass {
    if rc == 0 {
        return RcClass::Success;
    }
    if (rc & TPM_RC_A) == TPM_RC_A {
        return RcClass::Auth;
    }
    if (rc & TPM_RC_VER1_MASK) == TPM_RC_VER1 {
        return RcClass::Format;
    }
    if (rc & TPM_RC_FMT1) != 0 {
        return RcClass::Format;
    }
    RcClass::Other
}

pub fn describe_tpm_rc(rc: u32) -> String {
    let name = match rc {
        0 => "success",
        0x0000_0125 => "TPM_RC_ASYMMETRIC",
        0x0000_0143 => "TPM_RC_ATTRIBUTES",
        0x0000_017F => "TPM_RC_SIZE",
        0x0000_038E => "TPM_RC_AUTH_FAIL",
        _ => "unknown",
    };
    let class = match classify_tpm_rc(rc) {
        RcClass::Success => "success",
        RcClass::Auth => "auth-class (privilege / hierarchy auth required)",
        RcClass::Format => "format-class (malformed command — fix marshalling, not a privilege result)",
        RcClass::Other => "other TPM error",
    };
    format!("{name} — {class}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_is_zero() {
        assert_eq!(classify_tpm_rc(0), RcClass::Success);
    }

    #[test]
    fn asymmetric_is_format() {
        assert_eq!(classify_tpm_rc(0x0000_0125), RcClass::Format);
    }

    #[test]
    fn auth_fail_is_auth() {
        assert_eq!(classify_tpm_rc(0x0000_038E), RcClass::Auth);
    }
}

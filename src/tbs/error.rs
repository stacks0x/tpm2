//! Structured TPM operation errors mapped to JS `TpmError`.

use crate::tbs::codes;
use crate::tbs::rc::{classify_tpm_rc, RcClass, WINDOWS_TPM_E_COMMAND_BLOCKED};

#[derive(Debug, Clone)]
pub enum TpmOpError {
    InvalidArgument {
        message: String,
    },
    RequiresElevation {
        context: String,
        hresult: u32,
    },
    AccessDenied {
        message: String,
    },
    NotSupported {
        message: String,
        suggestion: Option<&'static str>,
    },
    KeyNotFound {
        context: String,
        hresult: u32,
    },
    AlreadyExists {
        context: String,
        hresult: u32,
    },
    CommandBlocked {
        context: String,
        tpm_rc: u32,
    },
    MarshallingError {
        context: String,
        message: String,
        tpm_rc: Option<u32>,
        hresult: Option<u32>,
    },
    AuthFailed {
        context: String,
        tpm_rc: u32,
    },
    TransportError {
        message: String,
    },
    TpmRc {
        context: String,
        tpm_rc: u32,
    },
    Unavailable {
        message: String,
        suggestion: Option<&'static str>,
    },
}

impl TpmOpError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidArgument { .. } => codes::INVALID_ARGUMENT,
            Self::RequiresElevation { .. } => codes::REQUIRES_ELEVATION,
            Self::AccessDenied { .. } => codes::ACCESS_DENIED,
            Self::NotSupported { .. } => codes::NOT_SUPPORTED,
            Self::KeyNotFound { .. } => codes::KEY_NOT_FOUND,
            Self::AlreadyExists { .. } => codes::ALREADY_EXISTS,
            Self::CommandBlocked { .. } => codes::COMMAND_BLOCKED,
            Self::MarshallingError { .. } => codes::MARSHALLING_ERROR,
            Self::AuthFailed { .. } => codes::AUTH_FAILED,
            Self::TransportError { .. } => codes::TRANSPORT_ERROR,
            Self::TpmRc { .. } => codes::TPM_RC,
            Self::Unavailable { .. } => codes::TPM_UNAVAILABLE,
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::InvalidArgument { message } => message.clone(),
            Self::RequiresElevation { context, hresult } => {
                format!("{context} (HRESULT 0x{hresult:08X})")
            }
            Self::AccessDenied { message } => message.clone(),
            Self::NotSupported { message, .. } => message.clone(),
            Self::KeyNotFound { context, hresult } => {
                format!("{context} (HRESULT 0x{hresult:08X})")
            }
            Self::AlreadyExists { context, hresult } => {
                format!("{context} (HRESULT 0x{hresult:08X})")
            }
            Self::CommandBlocked { context, tpm_rc } => format!(
                "{context}: Windows TBS blocked TPM2 command 0x{tpm_rc:08X} (TPM_E_COMMAND_BLOCKED); \
                 the Windows TPM driver allow-list does not permit this ordinal via raw TBS for the current process"
            ),
            Self::MarshallingError {
                context,
                message,
                tpm_rc,
                hresult,
            } => match (tpm_rc, hresult) {
                (Some(rc), Some(hr)) => format!(
                    "{context}: {message} (TPM_RC 0x{rc:08X}, HRESULT 0x{hr:08X})"
                ),
                (Some(rc), None) => format!("{context}: {message} (TPM_RC 0x{rc:08X})"),
                (None, Some(hr)) => format!("{context}: {message} (HRESULT 0x{hr:08X})"),
                (None, None) => format!("{context}: {message}"),
            },
            Self::AuthFailed { context, tpm_rc } => {
                format!("{context} (TPM_RC 0x{tpm_rc:08X})")
            }
            Self::TransportError { message } => message.clone(),
            Self::TpmRc { context, tpm_rc } => format!("{context} (TPM_RC 0x{tpm_rc:08X})"),
            Self::Unavailable { message, .. } => message.clone(),
        }
    }

    pub fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::Unavailable { suggestion, .. } => *suggestion,
            Self::NotSupported { suggestion, .. } => *suggestion,
            Self::AccessDenied { .. } => Some(
                "Add the process user to the tss group, or pass the device into the container.",
            ),
            Self::RequiresElevation { .. } => Some(
                "Re-run as Administrator or SYSTEM (production enrollment uses SYSTEM).",
            ),
            Self::CommandBlocked { .. } => Some(
                "On Windows, ActivateCredential must use NCrypt PCP — raw TBS cannot reach this ordinal (elevation does not help).",
            ),
            Self::InvalidArgument { .. } => None,
            Self::KeyNotFound { .. } => None,
            Self::AlreadyExists { .. } => Some(
                "Use overwrite: true to replace an existing persisted key of the same name.",
            ),
            Self::MarshallingError { .. } => None,
            Self::AuthFailed { .. } => None,
            Self::TransportError { .. } => None,
            Self::TpmRc { .. } => None,
        }
    }

    pub fn tpm_rc(&self) -> Option<u32> {
        match self {
            Self::CommandBlocked { tpm_rc, .. }
            | Self::AuthFailed { tpm_rc, .. }
            | Self::TpmRc { tpm_rc, .. } => Some(*tpm_rc),
            Self::MarshallingError { tpm_rc, .. } => *tpm_rc,
            _ => None,
        }
    }

    pub fn hresult(&self) -> Option<u32> {
        match self {
            Self::MarshallingError { hresult: Some(h), .. }
            | Self::RequiresElevation { hresult: h, .. }
            | Self::KeyNotFound { hresult: h, .. }
            | Self::AlreadyExists { hresult: h, .. } => Some(*h),
            _ => None,
        }
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::Unavailable {
            message: message.into(),
            suggestion: Some(
                "Ensure a TPM is present and the native platform package is installed.",
            ),
        }
    }

    pub fn access_denied(message: impl Into<String>) -> Self {
        Self::AccessDenied {
            message: message.into(),
        }
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::InvalidArgument {
            message: message.into(),
        }
    }

    pub fn not_supported(message: impl Into<String>, suggestion: Option<&'static str>) -> Self {
        Self::NotSupported {
            message: message.into(),
            suggestion,
        }
    }

    pub fn marshalling(context: impl Into<String>, message: impl Into<String>) -> Self {
        Self::MarshallingError {
            context: context.into(),
            message: message.into(),
            tpm_rc: None,
            hresult: None,
        }
    }

    pub fn marshalling_hresult(
        context: impl Into<String>,
        message: impl Into<String>,
        hresult: u32,
    ) -> Self {
        Self::MarshallingError {
            context: context.into(),
            message: message.into(),
            tpm_rc: None,
            hresult: Some(hresult),
        }
    }

    pub fn marshalling_tpm_rc(
        context: impl Into<String>,
        message: impl Into<String>,
        tpm_rc: u32,
    ) -> Self {
        Self::MarshallingError {
            context: context.into(),
            message: message.into(),
            tpm_rc: Some(tpm_rc),
            hresult: None,
        }
    }

    pub fn from_tpm_rc(rc: u32, context: impl Into<String>) -> Self {
        let context = context.into();
        // FMT1 handle errors (0x8B) are not codec bugs — index/handle not present.
        if rc == 0x0000_008B || rc == 0x0000_018B {
            return Self::TpmRc { context, tpm_rc: rc };
        }
        match classify_tpm_rc(rc) {
            RcClass::Auth => Self::AuthFailed {
                context,
                tpm_rc: rc,
            },
            RcClass::Format => Self::MarshallingError {
                context,
                message: crate::tbs::rc::describe_tpm_rc(rc),
                tpm_rc: Some(rc),
                hresult: None,
            },
            RcClass::Success => Self::TpmRc { context, tpm_rc: rc },
            RcClass::Other => Self::TpmRc { context, tpm_rc: rc },
        }
    }

    /// Generic operation/marshalling failure (legacy `other` call sites).
    pub fn other(message: impl Into<String>) -> Self {
        Self::marshalling("operation", message)
    }

    pub fn transport(err: String) -> Self {
        let lower = err.to_ascii_lowercase();
        if lower.contains("permission denied")
            || lower.contains("access denied")
            || lower.contains("eacces")
        {
            return Self::access_denied(err);
        }
        Self::TransportError { message: err }
    }

    pub fn wire_message(&self) -> String {
        let suggestion = self.suggestion().unwrap_or("");
        let tpm_rc = self.tpm_rc().map(|r| r.to_string()).unwrap_or_default();
        let hresult = self.hresult().map(|r| r.to_string()).unwrap_or_default();
        format!(
            "__tpm2__{}|{}|{}|{}|{}",
            self.code(),
            self.message(),
            suggestion,
            tpm_rc,
            hresult
        )
    }
}

pub type TpmResult<T> = Result<T, TpmOpError>;

pub fn check_tpm_rc(resp: &[u8], context: &str) -> TpmResult<()> {
    let rc = crate::tbs::commands::tpm_rc_from_response(resp).ok_or_else(|| {
        TpmOpError::marshalling(context, "TPM response too short")
    })?;
    if rc != 0 {
        if rc == WINDOWS_TPM_E_COMMAND_BLOCKED {
            return Err(TpmOpError::CommandBlocked {
                context: context.to_string(),
                tpm_rc: rc,
            });
        }
        return Err(TpmOpError::from_tpm_rc(rc, context));
    }
    Ok(())
}

/// `TPM2_PCR_Extend` on Windows: standard users get `TPM_E_COMMAND_BLOCKED` from TBS;
/// Administrator can extend (validated on real hardware). Map that block to elevation.
pub fn check_pcr_extend_rc(resp: &[u8]) -> TpmResult<()> {
    let rc = crate::tbs::commands::tpm_rc_from_response(resp).ok_or_else(|| {
        TpmOpError::marshalling("PCR_Extend", "TPM response too short")
    })?;
    if rc == 0 {
        return Ok(());
    }
    #[cfg(windows)]
    if rc == WINDOWS_TPM_E_COMMAND_BLOCKED {
        return Err(TpmOpError::RequiresElevation {
            context: "PCR_Extend".to_string(),
            hresult: rc,
        });
    }
    check_tpm_rc(resp, "PCR_Extend")
}

/// Owner NV admin commands on Windows: standard users get `TPM_E_COMMAND_BLOCKED` from TBS.
pub fn check_nv_owner_rc(resp: &[u8], context: &str) -> TpmResult<()> {
    let rc = crate::tbs::commands::tpm_rc_from_response(resp).ok_or_else(|| {
        TpmOpError::marshalling(context, "TPM response too short")
    })?;
    if rc == 0 {
        return Ok(());
    }
    #[cfg(windows)]
    if rc == WINDOWS_TPM_E_COMMAND_BLOCKED {
        return Err(TpmOpError::RequiresElevation {
            context: context.to_string(),
            hresult: rc,
        });
    }
    check_tpm_rc(resp, context)
}

#[cfg(feature = "napi")]
impl From<TpmOpError> for napi::Error {
    fn from(e: TpmOpError) -> Self {
        napi::Error::from_reason(e.wire_message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tbs::codes;

    #[test]
    fn wire_message_includes_hresult_field() {
        let err = TpmOpError::RequiresElevation {
            context: "NCryptCreatePersistedKey".to_string(),
            hresult: 0x80090030,
        };
        let wire = err.wire_message();
        assert!(wire.starts_with("__tpm2__"));
        let parts: Vec<&str> = wire.trim_start_matches("__tpm2__").split('|').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], codes::REQUIRES_ELEVATION);
        assert_eq!(parts[4], format!("{}", 0x80090030u32));
    }

    #[test]
    fn auth_class_maps_to_auth_failed() {
        let err = TpmOpError::from_tpm_rc(0x0000_038E, "PolicySecret");
        assert_eq!(err.code(), codes::AUTH_FAILED);
        assert_eq!(err.tpm_rc(), Some(0x0000_038E));
    }

    #[test]
    fn format_class_maps_to_marshalling_error() {
        let err = TpmOpError::from_tpm_rc(0x0000_0125, "Quote");
        assert_eq!(err.code(), codes::MARSHALLING_ERROR);
    }

    #[test]
    fn pcr_extend_command_blocked_maps_to_elevation_on_windows() {
        let mut resp = vec![0u8; 10];
        resp[6..10].copy_from_slice(&WINDOWS_TPM_E_COMMAND_BLOCKED.to_be_bytes());
        let err = super::check_pcr_extend_rc(&resp).unwrap_err();
        #[cfg(windows)]
        {
            assert_eq!(err.code(), codes::REQUIRES_ELEVATION);
            assert_eq!(err.hresult(), Some(WINDOWS_TPM_E_COMMAND_BLOCKED));
            assert_eq!(err.tpm_rc(), None);
        }
        #[cfg(not(windows))]
        {
            assert_eq!(err.code(), codes::COMMAND_BLOCKED);
        }
    }

    #[test]
    fn nv_define_command_blocked_maps_to_elevation_on_windows() {
        let mut resp = vec![0u8; 10];
        resp[6..10].copy_from_slice(&WINDOWS_TPM_E_COMMAND_BLOCKED.to_be_bytes());
        let err = super::check_nv_owner_rc(&resp, "NV_DefineSpace").unwrap_err();
        #[cfg(windows)]
        {
            assert_eq!(err.code(), codes::REQUIRES_ELEVATION);
            assert_eq!(err.hresult(), Some(WINDOWS_TPM_E_COMMAND_BLOCKED));
        }
        #[cfg(not(windows))]
        {
            assert_eq!(err.code(), codes::COMMAND_BLOCKED);
        }
    }
}

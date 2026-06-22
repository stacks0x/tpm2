//! Structured TPM operation errors mapped to JS `TpmError`.

#[derive(Debug, Clone)]
pub struct TpmOpError {
    pub code: &'static str,
    pub message: String,
    pub suggestion: Option<&'static str>,
    pub tpm_rc: Option<u32>,
}

impl TpmOpError {
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            code: "TPM_UNAVAILABLE",
            message: message.into(),
            suggestion: Some("Ensure a TPM is present and the native platform package is installed."),
            tpm_rc: None,
        }
    }

    pub fn access_denied(message: impl Into<String>) -> Self {
        Self {
            code: "ACCESS_DENIED",
            message: message.into(),
            suggestion: Some(
                "Add the process user to the tss group, or pass the device into the container.",
            ),
            tpm_rc: None,
        }
    }

    pub fn tpm_rc(rc: u32, context: impl Into<String>) -> Self {
        Self {
            code: "TPM_RC",
            message: format!("{} (TPM_RC 0x{rc:08X})", context.into()),
            suggestion: None,
            tpm_rc: Some(rc),
        }
    }

    pub fn transport(err: String) -> Self {
        let lower = err.to_ascii_lowercase();
        if lower.contains("permission denied")
            || lower.contains("access denied")
            || lower.contains("eacces")
        {
            return Self::access_denied(err);
        }
        Self::unavailable(err)
    }

    pub fn other(message: impl Into<String>) -> Self {
        Self {
            code: "TPM_RC",
            message: message.into(),
            suggestion: None,
            tpm_rc: None,
        }
    }

    pub fn wire_message(&self) -> String {
        let suggestion = self.suggestion.unwrap_or("");
        let tpm_rc = self.tpm_rc.map(|r| r.to_string()).unwrap_or_default();
        format!(
            "__tpm2__{}|{}|{}|{}",
            self.code, self.message, suggestion, tpm_rc
        )
    }
}

pub type TpmResult<T> = Result<T, TpmOpError>;

pub fn check_tpm_rc(resp: &[u8], context: &str) -> TpmResult<()> {
    let rc = crate::tbs::commands::tpm_rc_from_response(resp)
        .ok_or_else(|| TpmOpError::other(format!("{context}: TPM response too short")))?;
    if rc != 0 {
        if rc == crate::tbs::rc::WINDOWS_TPM_E_COMMAND_BLOCKED {
            return Err(TpmOpError {
                code: "COMMAND_BLOCKED",
                message: format!(
                    "{context}: Windows TBS blocked TPM2 command 0x{rc:08X} (TPM_E_COMMAND_BLOCKED); \
                     the Windows TPM driver allow-list does not permit this ordinal via raw TBS \
                     (elevation does not help)"
                ),
                suggestion: Some(
                    "Windows credential activation uses NCrypt PCP (PCP_TPM12_IDACTIVATION).",
                ),
                tpm_rc: Some(rc),
            });
        }
        return Err(TpmOpError::tpm_rc(rc, context));
    }
    Ok(())
}

#[cfg(feature = "napi")]
impl From<TpmOpError> for napi::Error {
    fn from(e: TpmOpError) -> Self {
        napi::Error::from_reason(e.wire_message())
    }
}

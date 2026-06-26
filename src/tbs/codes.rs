//! Stable public error codes for node-tpm2. Semver after `latest` — do not rename casually.
//! Tier 2 `index.d.ts` `TpmErrorCode` union should match this list.

pub const TPM_UNAVAILABLE: &str = "TPM_UNAVAILABLE";
pub const ACCESS_DENIED: &str = "ACCESS_DENIED";
pub const COMMAND_BLOCKED: &str = "COMMAND_BLOCKED";
pub const REQUIRES_ELEVATION: &str = "REQUIRES_ELEVATION";
pub const NOT_SUPPORTED: &str = "NOT_SUPPORTED";
pub const INVALID_ARGUMENT: &str = "INVALID_ARGUMENT";
pub const KEY_NOT_FOUND: &str = "KEY_NOT_FOUND";
pub const ALREADY_EXISTS: &str = "ALREADY_EXISTS";
pub const MARSHALLING_ERROR: &str = "MARSHALLING_ERROR";
pub const TRANSPORT_ERROR: &str = "TRANSPORT_ERROR";
pub const AUTH_FAILED: &str = "AUTH_FAILED";
pub const TPM_RC: &str = "TPM_RC";

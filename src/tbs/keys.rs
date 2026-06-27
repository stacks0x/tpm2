//! Key lifecycle: CreatePrimary, Create (AK), Load, FlushContext.

use crate::tbs::commands::{create_primary_owner, flush_handle, object_handle_from_response, PrimaryKind};
use crate::tbs::error::{check_tpm_rc, TpmOpError, TpmResult};
use crate::tbs::parse::ResponseParser;
use crate::tbs::wire::{
    asym_scheme_null, command_with_password_session, kdf_scheme_null, tpm2b, tpm2b_empty, u16,
    u32,
};
use crate::tbs::submit_tpm_command;

const TPM_CC_CREATE: u32 = 0x0000_0153;
const TPM_CC_LOAD: u32 = 0x0000_0157;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ECC_NIST_P256: u16 = 0x0003;

/// Matches tpm2_create defaults for `ecc` signing keys under a storage primary.
/// Includes `adminWithPolicy` for ActivateCredential (Part 3 §12.3 ADMIN role).
const AK_OBJECT_ATTRIBUTES: u32 = 0x0006_00F2;

#[derive(Debug, Clone)]
pub struct ProvisionAkResult {
    pub ak_public_der: Vec<u8>,
    pub ak_blob: AkBlob,
}

#[derive(Debug, Clone, Default)]
pub struct ProvisionAkOptions {
    /// Persisted PCP key name on Windows. Random when omitted.
    pub key_name: Option<String>,
    #[cfg(windows)]
    pub scope: crate::tbs::ak_blob::PcpKeyScope,
    /// Replace an existing persisted key of the same name (Windows enrollment idempotency).
    #[cfg(windows)]
    pub overwrite: bool,
}

#[cfg(windows)]
pub use crate::tbs::ak_blob::PcpKeyScope;

#[derive(Debug, Clone)]
pub struct AkBlob {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

pub struct LoadedKey {
    pub handle: u32,
    pub parent: u32,
}

impl LoadedKey {
    pub fn flush(self) -> TpmResult<()> {
        flush_transient(self.handle)
    }
}

pub struct StoragePrimary {
    pub handle: u32,
}

impl StoragePrimary {
    pub fn flush(self) -> TpmResult<()> {
        flush_transient(self.handle)
    }
}

pub fn create_storage_primary() -> TpmResult<StoragePrimary> {
    let cmd = create_primary_owner(PrimaryKind::EccP256);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "CreatePrimary")?;
    let handle = object_handle_from_response(&resp)
        .ok_or_else(|| TpmOpError::other("CreatePrimary: missing object handle"))?;
    Ok(StoragePrimary { handle })
}

fn public_ecc_ak() -> Vec<u8> {
    let policy = crate::tbs::policy_digest::activate_credential_policy_digest();
    let mut t = Vec::new();
    t.extend_from_slice(&u16(TPM_ALG_ECC));
    t.extend_from_slice(&u16(TPM_ALG_SHA256));
    t.extend_from_slice(&u32(AK_OBJECT_ATTRIBUTES));
    t.extend(tpm2b(&policy));
    t.extend(asym_scheme_null()); // symmetric: TPM_ALG_NULL
    t.extend(asym_scheme_null()); // asymmetric scheme: TPM_ALG_NULL (ECDSA at Quote time)
    t.extend_from_slice(&u16(TPM_ECC_NIST_P256));
    t.extend(kdf_scheme_null());
    t.extend(tpm2b_empty());
    t.extend(tpm2b_empty());
    tpm2b(&t)
}

fn sensitive_create_null_auth() -> Vec<u8> {
    tpm2b(&[0x00, 0x00, 0x00, 0x00])
}

/// Create a transient AK under an existing storage primary (internal / probe use).
pub fn create_ak(parent: u32) -> TpmResult<AkBlob> {
    let mut params = Vec::new();
    params.extend(sensitive_create_null_auth());
    params.extend(public_ecc_ak());
    params.extend(tpm2b_empty());
    params.extend_from_slice(&u32(0));

    let cmd = command_with_password_session(parent, TPM_CC_CREATE, &params);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "Create")?;

    let mut parser = ResponseParser::after_rc(&resp)?;
    let _param_size = parser.read_u32()?;
    let private = read_tpm2b_wire(&mut parser)?;
    let public = read_tpm2b_wire(&mut parser)?;
    Ok(AkBlob { public, private })
}

/// Read a TPM2B as raw wire bytes (size prefix + payload) for Load/Quote round-trip.
pub(crate) fn read_tpm2b_wire(parser: &mut ResponseParser) -> TpmResult<Vec<u8>> {
    let size = parser.read_u16()? as usize;
    let payload = parser.read_bytes(size)?.to_vec();
    let mut wire = Vec::with_capacity(2 + size);
    wire.extend_from_slice(&(size as u16).to_be_bytes());
    wire.extend(payload);
    Ok(wire)
}

pub fn load_ak(parent: u32, blob: &AkBlob) -> TpmResult<LoadedKey> {
    let mut params = Vec::new();
    params.extend_from_slice(&blob.private);
    params.extend_from_slice(&blob.public);

    let cmd = command_with_password_session(parent, TPM_CC_LOAD, &params);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "Load")?;

    let handle = object_handle_from_response(&resp)
        .ok_or_else(|| TpmOpError::other("Load: missing object handle"))?;
    Ok(LoadedKey { handle, parent })
}

pub fn flush_transient(handle: u32) -> TpmResult<()> {
    flush_handle(handle)
}

/// Provision a wrapped AK blob under a freshly created storage primary; flushes the primary.
#[cfg(not(windows))]
pub fn provision_ak_blob() -> TpmResult<AkBlob> {
    provision_ak_blob_with_options(&ProvisionAkOptions::default())
}

#[cfg(not(windows))]
pub fn provision_ak_blob_with_options(_opts: &ProvisionAkOptions) -> TpmResult<AkBlob> {
    let primary = create_storage_primary()?;
    let blob = create_ak(primary.handle)?;
    primary.flush()?;
    Ok(blob)
}

#[cfg(windows)]
pub fn provision_ak_blob() -> TpmResult<AkBlob> {
    crate::tbs::pcp::provision_ak_blob()
}

#[cfg(windows)]
pub fn provision_ak_blob_with_options(opts: &ProvisionAkOptions) -> TpmResult<AkBlob> {
    crate::tbs::pcp::provision_ak_blob_with_options(opts)
}

/// Provision AK and return SPKI DER + wrapped blob (spec §4.3 `provisionAk`).
#[cfg(not(windows))]
pub fn provision_ak() -> TpmResult<ProvisionAkResult> {
    provision_ak_with_options(&ProvisionAkOptions::default())
}

#[cfg(not(windows))]
pub fn provision_ak_with_options(_opts: &ProvisionAkOptions) -> TpmResult<ProvisionAkResult> {
    let ak_blob = provision_ak_blob_with_options(_opts)?;
    let ak_public_der = crate::tbs::read_public::public_wire_to_spki_der(&ak_blob.public)?;
    Ok(ProvisionAkResult {
        ak_public_der,
        ak_blob,
    })
}

#[cfg(windows)]
pub fn provision_ak() -> TpmResult<ProvisionAkResult> {
    crate::tbs::pcp::provision_ak()
}

#[cfg(windows)]
pub fn provision_ak_with_options(opts: &ProvisionAkOptions) -> TpmResult<ProvisionAkResult> {
    crate::tbs::pcp::provision_ak_with_options(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ak_public_template_size() {
        let t = public_ecc_ak();
        assert!(t.len() > 20);
        assert_eq!(&t[2..4], &TPM_ALG_ECC.to_be_bytes());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_ak_blob_roundtrip() {
        if !crate::tbs::hw_test::enabled() {
            return;
        }
        let primary = create_storage_primary().expect("CreatePrimary");
        let blob = create_ak(primary.handle).expect("Create AK");
        let loaded = load_ak(primary.handle, &blob).expect("Load AK");
        loaded.flush().expect("flush AK");
        primary.flush().expect("flush primary");
    }
}

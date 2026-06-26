//! Windows Platform Crypto Provider (PCP) — go-attestation model.
//!
//! - RSA 2048 persisted identity AK (not Linux's ECDSA wrapped blob)
//! - User-scoped keys (PCP1) for dev; machine-scoped + DACL (PCP2) for fleet enroll
//! - Activate via `PCP_TPM12_IDACTIVATION` (enrollment / elevated)
//! - Quote via PCP TBS context + `TPM2_Quote` with NULL scheme (key default RSASSA)

use windows::core::{w, PCWSTR};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptFinalizeKey, NCryptFreeObject,
    NCryptGetProperty, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, CERT_KEY_SPEC,
    NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
};
use windows::Win32::Security::{
    GetSecurityDescriptorLength, DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};

use crate::tbs::ak_blob::{
    decode_pcp_blob, encode_pcp_blob, public_wire_from_pcp_meta, PcpAkMetadata, PcpKeyScope,
};
use crate::tbs::error::{TpmOpError, TpmResult};
use crate::tbs::keys::{AkBlob, ProvisionAkOptions, ProvisionAkResult};
use crate::tbs::ncrypt::{classify_ncrypt, NcryptOp};
use crate::tbs::pcr::PcrBank;
use crate::tbs::quote::{pcp_rsa_quote_scheme, quote_with_submit, rsassa_sha256_scheme, QuoteResult};
use crate::tbs::read_public::public_wire_to_spki_der;
use crate::tbs::session_hmac::random_nonce_32;
use crate::tbs::wire::tpm2b;

const KEY_USAGE_POLICY_IDENTITY: u32 = 0x8;
const RSA_KEY_BITS: u32 = 2048;
const NCRYPT_MACHINE_KEY_FLAG: u32 = 0x0000_0020;
const NCRYPT_OVERWRITE_KEY_FLAG: u32 = 0x0000_0040;
const NCRYPT_NO_FLAGS: NCRYPT_FLAGS = NCRYPT_FLAGS(0);
const NCRYPT_NO_SECURITY_FLAGS: OBJECT_SECURITY_INFORMATION = OBJECT_SECURITY_INFORMATION(0);
const NCRYPT_LEGACY_KEY_SPEC: CERT_KEY_SPEC = CERT_KEY_SPEC(0);

/// DACL: SYSTEM/Administrators full; Built-in Users read + execute (sign/use), no write.
const MACHINE_KEY_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;BU)";

struct PcpProvider {
    handle: NCRYPT_PROV_HANDLE,
}

impl PcpProvider {
    fn open() -> TpmResult<Self> {
        let mut handle = NCRYPT_PROV_HANDLE::default();
        unsafe {
            NCryptOpenStorageProvider(
                &mut handle,
                w!("Microsoft Platform Crypto Provider"),
                0,
            )
            .map_err(map_ncrypt("NCryptOpenStorageProvider", NcryptOp::General))?;
        }
        Ok(Self { handle })
    }

    fn security_descr_supported(&self) -> TpmResult<bool> {
        let mut value: u32 = 0;
        let mut cb = 4u32;
        unsafe {
            NCryptGetProperty(
                self.handle,
                w!("Security Descr Support"),
                Some(std::slice::from_raw_parts_mut(
                    (&mut value as *mut u32).cast(),
                    4,
                )),
                &mut cb,
                NCRYPT_NO_SECURITY_FLAGS,
            )
            .map_err(map_ncrypt(
                "NCryptGetProperty(Security Descr Support)",
                NcryptOp::General,
            ))?;
        }
        Ok(value != 0)
    }

    fn create_identity_ak(&self, key_name: &str, opts: &ProvisionAkOptions) -> TpmResult<PcpKey> {
        if opts.scope == PcpKeyScope::Machine && !self.security_descr_supported()? {
            return Err(TpmOpError::not_supported(
                "PCP provider does not advertise Security Descr Support; \
                 machine-scoped AK requires DACL (fleet enrollment blocked)",
                None,
            ));
        }

        let ncrypt_op = if opts.scope == PcpKeyScope::Machine {
            NcryptOp::MachineProvision
        } else {
            NcryptOp::General
        };

        if opts.overwrite {
            let _ = self.delete_persisted_key_if_exists(key_name, opts.scope);
        }

        let mut key = NCRYPT_KEY_HANDLE::default();
        let name = wide(key_name);
        let create_flags = ncrypt_key_flags(opts.scope, opts.overwrite);
        unsafe {
            NCryptCreatePersistedKey(
                self.handle,
                &mut key,
                w!("RSA"),
                PCWSTR(name.as_ptr()),
                NCRYPT_LEGACY_KEY_SPEC,
                create_flags,
            )
            .map_err(map_ncrypt("NCryptCreatePersistedKey", ncrypt_op))?;

            set_u32_property(key, w!("Length"), RSA_KEY_BITS)?;
            set_u32_property(key, w!("PCP_KEY_USAGE_POLICY"), KEY_USAGE_POLICY_IDENTITY)?;

            if opts.scope == PcpKeyScope::Machine {
                set_machine_key_dacl(key)?;
            }

            NCryptFinalizeKey(key, NCRYPT_NO_FLAGS)
                .map_err(map_ncrypt("NCryptFinalizeKey", ncrypt_op))?;
        }
        Ok(PcpKey { handle: key })
    }

    /// PCP often ignores NCRYPT_OVERWRITE_KEY_FLAG; delete explicitly when re-provisioning.
    fn delete_persisted_key_if_exists(&self, key_name: &str, scope: PcpKeyScope) -> TpmResult<()> {
        let name = wide(key_name);
        let open_flags = ncrypt_key_flags(scope, false);
        let mut key = NCRYPT_KEY_HANDLE::default();
        unsafe {
            match NCryptOpenKey(
                self.handle,
                &mut key,
                PCWSTR(name.as_ptr()),
                NCRYPT_LEGACY_KEY_SPEC,
                open_flags,
            ) {
                Ok(()) => {
                    NCryptDeleteKey(key, 0).map_err(map_ncrypt("NCryptDeleteKey", NcryptOp::General))?;
                    let _ = NCryptFreeObject(key);
                }
                Err(e) if is_key_not_found(&e) => {}
                Err(e) => {
                    return Err(map_ncrypt("NCryptOpenKey (delete probe)", NcryptOp::General)(e))
                }
            }
        }
        Ok(())
    }

    fn open_key(&self, key_name: &str, scope: PcpKeyScope) -> TpmResult<PcpKey> {
        let mut key = NCRYPT_KEY_HANDLE::default();
        let name = wide(key_name);
        let open_flags = ncrypt_key_flags(scope, false);
        unsafe {
            NCryptOpenKey(
                self.handle,
                &mut key,
                PCWSTR(name.as_ptr()),
                NCRYPT_LEGACY_KEY_SPEC,
                open_flags,
            )
            .map_err(map_ncrypt("NCryptOpenKey", NcryptOp::General))?;
        }
        Ok(PcpKey { handle: key })
    }

    fn tbs_context(&self) -> TpmResult<*mut std::ffi::c_void> {
        let buf = get_buffer_property_prov(self.handle, w!("PCP_PLATFORMHANDLE"))?;
        parse_tbs_context(&buf)
    }
}

impl Drop for PcpProvider {
    fn drop(&mut self) {
        unsafe {
            let _ = NCryptFreeObject(self.handle);
        }
    }
}

struct PcpKey {
    handle: NCRYPT_KEY_HANDLE,
}

impl PcpKey {
    fn id_binding(&self) -> TpmResult<PcpAkMetadata> {
        let buf =
            get_buffer_property_key(self.handle, w!("PCP_TPM12_IDBINDING"), NcryptOp::General)?;
        decode_id_binding(&buf)
    }

    fn tpm_handle(&self) -> TpmResult<u32> {
        let buf =
            get_buffer_property_key(self.handle, w!("PCP_PLATFORMHANDLE"), NcryptOp::General)?;
        parse_tpm_object_handle(&buf)
    }

    fn activate_credential(&self, credential_blob: &[u8], secret: &[u8]) -> TpmResult<Vec<u8>> {
        let mut activation = Vec::with_capacity(4 + credential_blob.len() + secret.len());
        activation.extend(tpm2b(credential_blob));
        activation.extend(tpm2b(secret));

        unsafe {
            NCryptSetProperty(
                self.handle,
                w!("PCP_TPM12_IDACTIVATION"),
                &activation,
                NCRYPT_NO_FLAGS,
            )
            .map_err(map_ncrypt(
                "NCryptSetProperty(PCP_TPM12_IDACTIVATION)",
                NcryptOp::ActivateCredential,
            ))?;
        }
        let buf = get_buffer_property_key(
            self.handle,
            w!("PCP_TPM12_IDACTIVATION"),
            NcryptOp::ActivateCredential,
        )?;
        Ok(unwrap_tpm2b_response(&buf))
    }
}

impl Drop for PcpKey {
    fn drop(&mut self) {
        unsafe {
            let _ = NCryptFreeObject(self.handle);
        }
    }
}

fn ncrypt_key_flags(scope: PcpKeyScope, overwrite: bool) -> NCRYPT_FLAGS {
    let mut flags = 0u32;
    if scope == PcpKeyScope::Machine {
        flags |= NCRYPT_MACHINE_KEY_FLAG;
    }
    if overwrite {
        flags |= NCRYPT_OVERWRITE_KEY_FLAG;
    }
    NCRYPT_FLAGS(flags)
}

fn default_key_name() -> String {
    let nonce = random_nonce_32();
    format!("node-tpm2-ak-{}", hex_encode(&nonce))
}

fn validate_provision_options(opts: &ProvisionAkOptions) -> TpmResult<()> {
    if opts.scope != PcpKeyScope::Machine {
        return Ok(());
    }
    let name = opts.key_name.as_deref().unwrap_or("").trim();
    if name.is_empty() {
        return Err(TpmOpError::invalid_argument(
            "machine-scoped provisionAk requires a non-empty keyName",
        ));
    }
    if name.starts_with("node-tpm2-ak-") {
        return Err(TpmOpError::invalid_argument(
            "machine scope cannot use the auto-generated dev key name; set an explicit fleet keyName",
        ));
    }
    Ok(())
}

fn resolve_key_name(opts: &ProvisionAkOptions) -> String {
    opts.key_name
        .clone()
        .unwrap_or_else(default_key_name)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::prelude::*;
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn map_ncrypt(context: &str, op: NcryptOp) -> impl Fn(windows::core::Error) -> TpmOpError + use<'_> {
    let context = context.to_string();
    move |e: windows::core::Error| {
        let hresult = e.code().0 as u32;
        classify_ncrypt(hresult, &context, op)
    }
}

fn is_key_not_found(err: &windows::core::Error) -> bool {
    const NTE_NOT_FOUND: u32 = 0x8009_0011;
    const NTE_BAD_KEYSET: u32 = 0x8009_0016;
    let code = err.code().0 as u32;
    code == NTE_NOT_FOUND || code == NTE_BAD_KEYSET
}

fn set_u32_property(key: NCRYPT_KEY_HANDLE, name: PCWSTR, value: u32) -> TpmResult<()> {
    unsafe {
        NCryptSetProperty(key, name, &value.to_le_bytes(), NCRYPT_NO_FLAGS)
            .map_err(map_ncrypt("NCryptSetProperty", NcryptOp::General))?;
    }
    Ok(())
}

fn set_machine_key_dacl(key: NCRYPT_KEY_HANDLE) -> TpmResult<()> {
    let sddl = wide(MACHINE_KEY_SDDL);
    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            1,
            &mut sd,
            None,
        )
        .map_err(map_ncrypt(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            NcryptOp::General,
        ))?;

        let len = GetSecurityDescriptorLength(sd);
        if len == 0 {
            return Err(TpmOpError::marshalling(
                "set_machine_key_dacl",
                "empty security descriptor from SDDL",
            ));
        }
        let sd_bytes = std::slice::from_raw_parts(sd.0.cast(), len as usize);

        NCryptSetProperty(
            key,
            w!("Security Descr"),
            sd_bytes,
            NCRYPT_FLAGS(DACL_SECURITY_INFORMATION.0),
        )
        .map_err(map_ncrypt("NCryptSetProperty(Security Descr)", NcryptOp::General))?;
    }
    Ok(())
}

fn unwrap_tpm2b_response(buf: &[u8]) -> Vec<u8> {
    if buf.len() >= 2 {
        let size = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if size + 2 == buf.len() {
            return buf[2..].to_vec();
        }
    }
    buf.to_vec()
}

fn get_buffer_property_key(
    key: NCRYPT_KEY_HANDLE,
    name: PCWSTR,
    op: NcryptOp,
) -> TpmResult<Vec<u8>> {
    let mut size = 0u32;
    unsafe {
        NCryptGetProperty(key, name, None, &mut size, NCRYPT_NO_SECURITY_FLAGS)
            .map_err(map_ncrypt("NCryptGetProperty(size)", op))?;
        if size == 0 {
            return Err(TpmOpError::marshalling(
                "NCryptGetProperty",
                "returned zero size",
            ));
        }
        let mut buf = vec![0u8; size as usize];
        NCryptGetProperty(key, name, Some(&mut buf), &mut size, NCRYPT_NO_SECURITY_FLAGS)
            .map_err(map_ncrypt("NCryptGetProperty", op))?;
        buf.truncate(size as usize);
        Ok(buf)
    }
}

fn get_buffer_property_prov(prov: NCRYPT_PROV_HANDLE, name: PCWSTR) -> TpmResult<Vec<u8>> {
    let mut size = 0u32;
    unsafe {
        NCryptGetProperty(prov, name, None, &mut size, NCRYPT_NO_SECURITY_FLAGS)
            .map_err(map_ncrypt("NCryptGetProperty(size)", NcryptOp::General))?;
        if size == 0 {
            return Err(TpmOpError::marshalling(
                "NCryptGetProperty",
                "returned zero size",
            ));
        }
        let mut buf = vec![0u8; size as usize];
        NCryptGetProperty(prov, name, Some(&mut buf), &mut size, NCRYPT_NO_SECURITY_FLAGS)
            .map_err(map_ncrypt("NCryptGetProperty", NcryptOp::General))?;
        buf.truncate(size as usize);
        Ok(buf)
    }
}

fn decode_id_binding(blob: &[u8]) -> TpmResult<PcpAkMetadata> {
    if blob.len() < 4 {
        return Err(TpmOpError::marshalling(
            "decode_id_binding",
            "PCP ID binding blob too short",
        ));
    }
    let mut cursor = blob;
    let raw_public = read_be_tpm2b(&mut cursor)?;
    let raw_creation_data = read_be_tpm2b(&mut cursor)?;
    let raw_attest = read_be_tpm2b(&mut cursor)?;
    let raw_signature = cursor.to_vec();
    if raw_public.is_empty() {
        return Err(TpmOpError::marshalling(
            "decode_id_binding",
            "PCP ID binding missing public key",
        ));
    }
    Ok(PcpAkMetadata {
        key_name: String::new(),
        scope: PcpKeyScope::User,
        raw_public,
        raw_creation_data,
        raw_attest,
        raw_signature,
    })
}

fn read_be_tpm2b(cursor: &mut &[u8]) -> TpmResult<Vec<u8>> {
    if cursor.len() < 2 {
        return Err(TpmOpError::marshalling(
            "read_be_tpm2b",
            "truncated TPM2B in PCP binding",
        ));
    }
    let size = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
    *cursor = &cursor[2..];
    if cursor.len() < size {
        return Err(TpmOpError::marshalling(
            "read_be_tpm2b",
            "truncated TPM2B payload in PCP binding",
        ));
    }
    let out = cursor[..size].to_vec();
    *cursor = &cursor[size..];
    Ok(out)
}

fn parse_tbs_context(buf: &[u8]) -> TpmResult<*mut std::ffi::c_void> {
    match buf.len() {
        8 => {
            let ptr = u64::from_le_bytes(buf[..8].try_into().expect("8 bytes"));
            Ok(ptr as *mut std::ffi::c_void)
        }
        4 => {
            let ptr = u32::from_le_bytes(buf[..4].try_into().expect("4 bytes"));
            Ok(ptr as *mut std::ffi::c_void)
        }
        len => Err(TpmOpError::marshalling(
            "parse_tbs_context",
            format!("PCP TBS context has unexpected size {len} (expected 4 or 8)"),
        )),
    }
}

fn parse_tpm_object_handle(buf: &[u8]) -> TpmResult<u32> {
    if buf.len() < 4 {
        return Err(TpmOpError::marshalling(
            "parse_tpm_object_handle",
            format!("PCP TPM object handle too short ({} bytes)", buf.len()),
        ));
    }
    Ok(u32::from_le_bytes(buf[..4].try_into().expect("4 bytes")))
}

pub fn provision_ak_blob_with_options(opts: &ProvisionAkOptions) -> TpmResult<AkBlob> {
    validate_provision_options(opts)?;
    let pcp = PcpProvider::open()?;
    let key_name = resolve_key_name(opts);
    let key = pcp.create_identity_ak(&key_name, opts)?;
    let mut meta = key.id_binding()?;
    meta.key_name = key_name;
    meta.scope = opts.scope;
    Ok(encode_pcp_blob(&meta))
}

pub fn provision_ak_blob() -> TpmResult<AkBlob> {
    provision_ak_blob_with_options(&ProvisionAkOptions::default())
}

pub fn provision_ak_with_options(opts: &ProvisionAkOptions) -> TpmResult<ProvisionAkResult> {
    let ak_blob = provision_ak_blob_with_options(opts)?;
    let meta = decode_pcp_blob(&ak_blob)?;
    let wire = public_wire_from_pcp_meta(&meta);
    let ak_public_der = public_wire_to_spki_der(&wire)?;
    Ok(ProvisionAkResult {
        ak_public_der,
        ak_blob,
    })
}

pub fn provision_ak() -> TpmResult<ProvisionAkResult> {
    provision_ak_with_options(&ProvisionAkOptions::default())
}

/// Probe helper: report PCP security-descriptor support (required for machine keys).
pub fn pcp_capabilities() -> TpmResult<PcpCapabilities> {
    let pcp = PcpProvider::open()?;
    Ok(PcpCapabilities {
        security_descr_supported: pcp.security_descr_supported()?,
    })
}

pub struct PcpCapabilities {
    pub security_descr_supported: bool,
}

pub fn quote_with_pcp_ak_blob(
    ak_blob: &AkBlob,
    pcr_selection: &[u32],
    qualifying_data: &[u8],
    bank: PcrBank,
) -> TpmResult<QuoteResult> {
    let meta = decode_pcp_blob(ak_blob)?;
    let pcp = PcpProvider::open()?;
    let tbs = pcp.tbs_context()?;
    let key = pcp.open_key(&meta.key_name, meta.scope)?;
    let tpm_handle = key.tpm_handle()?;

    let submit = |cmd: &[u8]| crate::tbs::platform::submit_to_context(tbs, cmd);
    match quote_with_submit(
        tpm_handle,
        pcr_selection,
        qualifying_data,
        bank,
        &pcp_rsa_quote_scheme(),
        submit,
    ) {
        Ok(result) => Ok(result),
        Err(e) if quote_scheme_retry(&e) => {
            let submit = |cmd: &[u8]| crate::tbs::platform::submit_to_context(tbs, cmd);
            quote_with_submit(
                tpm_handle,
                pcr_selection,
                qualifying_data,
                bank,
                &rsassa_sha256_scheme(),
                submit,
            )
        }
        Err(e) => Err(e),
    }
}

fn quote_scheme_retry(err: &TpmOpError) -> bool {
    matches!(
        err.tpm_rc(),
        Some(0x0000_0092) | Some(0x0000_0192)
    )
}

pub fn activate_credential_with_pcp_blob(
    ak_blob: &AkBlob,
    credential_blob: &[u8],
    secret: &[u8],
) -> TpmResult<Vec<u8>> {
    let meta = decode_pcp_blob(ak_blob)?;
    let pcp = PcpProvider::open()?;
    let key = pcp.open_key(&meta.key_name, meta.scope)?;
    key.activate_credential(credential_blob, secret)
}

/// True when the process token is elevated (admin). PCP activation requires this.
pub fn is_process_elevated() -> bool {
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}

/// True when the process token is NT AUTHORITY\\SYSTEM (Intune/SCCM/GPO enrollment context).
pub fn is_running_as_system() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, IsWellKnownSid, TokenUser, WinLocalSystemSid, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        struct TokenGuard(HANDLE);
        impl Drop for TokenGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
        let _guard = TokenGuard(token);

        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        if len == 0 {
            return false;
        }
        let mut buf = vec![0u8; len as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            len,
            &mut len,
        )
        .is_err()
        {
            return false;
        }
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        if tu.User.Sid.0.is_null() {
            return false;
        }
        IsWellKnownSid(tu.User.Sid, WinLocalSystemSid).as_bool()
    }
}

/// Human-readable security context for probe logs.
pub fn provision_context_label() -> &'static str {
    if is_running_as_system() {
        "SYSTEM"
    } else if is_process_elevated() {
        "Administrator (elevated)"
    } else {
        "standard user"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tbs::codes;

    #[test]
    fn machine_provision_unprivileged_requires_elevation() {
        if is_process_elevated() || is_running_as_system() {
            return;
        }
        let opts = ProvisionAkOptions {
            key_name: Some("node-tpm2-test-machine-elevation".to_string()),
            scope: PcpKeyScope::Machine,
            overwrite: true,
        };
        let err = provision_ak_with_options(&opts).unwrap_err();
        assert_eq!(err.code(), codes::REQUIRES_ELEVATION);
        assert!(err.hresult().is_some());
    }
}

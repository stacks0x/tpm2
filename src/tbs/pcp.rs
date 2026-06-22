//! Windows Platform Crypto Provider (PCP) for AK provisioning and credential activation.
//!
//! Raw TBS cannot invoke `TPM2_ActivateCredential` on Windows; PCP exposes it via
//! `NCryptSetProperty` / `PCP_TPM12_IDACTIVATION`.

use windows::core::{w, PCWSTR};
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptFinalizeKey, NCryptFreeObject, NCryptGetProperty,
    NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, CERT_KEY_SPEC, NCRYPT_FLAGS,
    NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
};
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

use crate::tbs::ak_blob::{decode_pcp_blob, encode_pcp_blob, public_wire_from_pcp_meta, PcpAkMetadata};
use crate::tbs::error::{TpmOpError, TpmResult};
use crate::tbs::keys::{AkBlob, ProvisionAkResult};
use crate::tbs::pcr::PcrBank;
use crate::tbs::quote::{quote_with_submit, QuoteResult};
use crate::tbs::read_public::public_wire_to_spki_der;
use crate::tbs::session_hmac::random_nonce_32;

const KEY_USAGE_POLICY_IDENTITY: u32 = 0x8;
const NCRYPT_NO_FLAGS: NCRYPT_FLAGS = NCRYPT_FLAGS(0);
const NCRYPT_NO_SECURITY_FLAGS: OBJECT_SECURITY_INFORMATION = OBJECT_SECURITY_INFORMATION(0);
const NCRYPT_LEGACY_KEY_SPEC: CERT_KEY_SPEC = CERT_KEY_SPEC(0);

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
            .map_err(ncrypt_err("NCryptOpenStorageProvider"))?;
        }
        Ok(Self { handle })
    }

    fn create_identity_ak(&self, key_name: &str) -> TpmResult<PcpKey> {
        let mut key = NCRYPT_KEY_HANDLE::default();
        let name = wide(key_name);
        unsafe {
            NCryptCreatePersistedKey(
                self.handle,
                &mut key,
                w!("ECDSA_P256"),
                PCWSTR(name.as_ptr()),
                NCRYPT_LEGACY_KEY_SPEC,
                NCRYPT_NO_FLAGS,
            )
            .map_err(ncrypt_err("NCryptCreatePersistedKey"))?;

            set_u32_property(key, w!("PCP_KEY_USAGE_POLICY"), KEY_USAGE_POLICY_IDENTITY)?;

            NCryptFinalizeKey(key, NCRYPT_NO_FLAGS).map_err(ncrypt_err("NCryptFinalizeKey"))?;
        }
        Ok(PcpKey { handle: key })
    }

    fn open_key(&self, key_name: &str) -> TpmResult<PcpKey> {
        let mut key = NCRYPT_KEY_HANDLE::default();
        let name = wide(key_name);
        unsafe {
            NCryptOpenKey(
                self.handle,
                &mut key,
                PCWSTR(name.as_ptr()),
                NCRYPT_LEGACY_KEY_SPEC,
                NCRYPT_NO_FLAGS,
            )
            .map_err(ncrypt_err("NCryptOpenKey"))?;
        }
        Ok(PcpKey { handle: key })
    }

    /// TBS context owned by PCP; valid for the lifetime of this provider handle.
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
        let buf = get_buffer_property_key(self.handle, w!("PCP_TPM12_IDBINDING"))?;
        decode_id_binding(&buf)
    }

    fn tpm_handle(&self) -> TpmResult<u32> {
        let buf = get_buffer_property_key(self.handle, w!("PCP_PLATFORMHANDLE"))?;
        parse_tpm_object_handle(&buf)
    }

    fn activate_credential(&self, credential_blob: &[u8], secret: &[u8]) -> TpmResult<Vec<u8>> {
        let mut activation = Vec::with_capacity(credential_blob.len() + secret.len());
        activation.extend_from_slice(credential_blob);
        activation.extend_from_slice(secret);

        unsafe {
            NCryptSetProperty(
                self.handle,
                w!("PCP_TPM12_IDACTIVATION"),
                &activation,
                NCRYPT_NO_FLAGS,
            )
            .map_err(ncrypt_err("NCryptSetProperty(PCP_TPM12_IDACTIVATION)"))?;
        }
        get_buffer_property_key(self.handle, w!("PCP_TPM12_IDACTIVATION"))
    }
}

impl Drop for PcpKey {
    fn drop(&mut self) {
        unsafe {
            let _ = NCryptFreeObject(self.handle);
        }
    }
}

fn random_key_name() -> String {
    let nonce = random_nonce_32();
    format!("node-tpm2-ak-{}", hex_encode(&nonce))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::prelude::*;
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn ncrypt_err(context: &str) -> impl Fn(windows::core::Error) -> TpmOpError + use<'_> {
    let context = context.to_string();
    move |e: windows::core::Error| TpmOpError::other(format!("{context}: {e}"))
}

fn set_u32_property(
    key: NCRYPT_KEY_HANDLE,
    name: PCWSTR,
    value: u32,
) -> TpmResult<()> {
    unsafe {
        NCryptSetProperty(key, name, &value.to_le_bytes(), NCRYPT_NO_FLAGS)
            .map_err(ncrypt_err("NCryptSetProperty"))?;
    }
    Ok(())
}

fn get_buffer_property_key(key: NCRYPT_KEY_HANDLE, name: PCWSTR) -> TpmResult<Vec<u8>> {
    let mut size = 0u32;
    unsafe {
        let _ = NCryptGetProperty(key, name, None, &mut size, NCRYPT_NO_SECURITY_FLAGS);
        if size == 0 {
            return Err(TpmOpError::other("NCryptGetProperty returned zero size"));
        }
        let mut buf = vec![0u8; size as usize];
        NCryptGetProperty(key, name, Some(&mut buf), &mut size, NCRYPT_NO_SECURITY_FLAGS)
            .map_err(ncrypt_err("NCryptGetProperty"))?;
        buf.truncate(size as usize);
        Ok(buf)
    }
}

fn get_buffer_property_prov(prov: NCRYPT_PROV_HANDLE, name: PCWSTR) -> TpmResult<Vec<u8>> {
    let mut size = 0u32;
    unsafe {
        let _ = NCryptGetProperty(prov, name, None, &mut size, NCRYPT_NO_SECURITY_FLAGS);
        if size == 0 {
            return Err(TpmOpError::other("NCryptGetProperty returned zero size"));
        }
        let mut buf = vec![0u8; size as usize];
        NCryptGetProperty(prov, name, Some(&mut buf), &mut size, NCRYPT_NO_SECURITY_FLAGS)
            .map_err(ncrypt_err("NCryptGetProperty"))?;
        buf.truncate(size as usize);
        Ok(buf)
    }
}

/// TPM 2.0 PCP ID binding blob: TPM2B_PUBLIC, TPM2B_CREATION_DATA, TPM2B_ATTEST, TPMT_SIGNATURE.
fn decode_id_binding(blob: &[u8]) -> TpmResult<PcpAkMetadata> {
    if blob.len() < 4 {
        return Err(TpmOpError::other("PCP ID binding blob too short"));
    }
    let mut cursor = blob;
    let raw_public = read_be_tpm2b(&mut cursor)?;
    let raw_creation_data = read_be_tpm2b(&mut cursor)?;
    let raw_attest = read_be_tpm2b(&mut cursor)?;
    let raw_signature = cursor.to_vec();
    if raw_public.is_empty() {
        return Err(TpmOpError::other("PCP ID binding missing public key"));
    }
    Ok(PcpAkMetadata {
        key_name: String::new(),
        raw_public,
        raw_creation_data,
        raw_attest,
        raw_signature,
    })
}

fn read_be_tpm2b(cursor: &mut &[u8]) -> TpmResult<Vec<u8>> {
    if cursor.len() < 2 {
        return Err(TpmOpError::other("truncated TPM2B in PCP binding"));
    }
    let size = u16::from_be_bytes([cursor[0], cursor[1]]) as usize;
    *cursor = &cursor[2..];
    if cursor.len() < size {
        return Err(TpmOpError::other("truncated TPM2B payload in PCP binding"));
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
        _ => Err(TpmOpError::other(format!(
            "PCP TBS context has unexpected size {} (expected 4 or 8)",
            buf.len()
        ))),
    }
}

fn parse_tpm_object_handle(buf: &[u8]) -> TpmResult<u32> {
    if buf.len() < 4 {
        return Err(TpmOpError::other(format!(
            "PCP TPM object handle too short ({} bytes)",
            buf.len()
        )));
    }
    Ok(u32::from_le_bytes(buf[..4].try_into().expect("4 bytes")))
}

pub fn provision_ak_blob() -> TpmResult<AkBlob> {
    let pcp = PcpProvider::open()?;
    let key_name = random_key_name();
    let key = pcp.create_identity_ak(&key_name)?;
    let mut meta = key.id_binding()?;
    meta.key_name = key_name;
    Ok(encode_pcp_blob(&meta))
}

pub fn provision_ak() -> TpmResult<ProvisionAkResult> {
    let ak_blob = provision_ak_blob()?;
    let meta = decode_pcp_blob(&ak_blob)?;
    let wire = public_wire_from_pcp_meta(&meta);
    let ak_public_der = public_wire_to_spki_der(&wire)?;
    Ok(ProvisionAkResult {
        ak_public_der,
        ak_blob,
    })
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
    let key = pcp.open_key(&meta.key_name)?;
    let tpm_handle = key.tpm_handle()?;
    quote_with_submit(tpm_handle, pcr_selection, qualifying_data, bank, |cmd| {
        crate::tbs::platform::submit_to_context(tbs, cmd)
    })
}

pub fn activate_credential_with_pcp_blob(
    ak_blob: &AkBlob,
    credential_blob: &[u8],
    secret: &[u8],
) -> TpmResult<Vec<u8>> {
    let meta = decode_pcp_blob(ak_blob)?;
    let pcp = PcpProvider::open()?;
    let key = pcp.open_key(&meta.key_name)?;
    key.activate_credential(credential_blob, secret)
}

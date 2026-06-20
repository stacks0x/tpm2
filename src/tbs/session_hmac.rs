//! TPM 2.0 policy/HMAC session authorization (Linux tpm2-sessions.c order).

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

const SHA256_DIGEST_SIZE: usize = 32;
const TPM2_MSO_PERSISTENT: u32 = 0x81;
const TPM2_MSO_VOLATILE: u32 = 0x80;
const TPM2_MSO_NVRAM: u32 = 0x01;

pub struct SessionAuthInput<'a> {
    pub session_handle: u32,
    pub session_key: &'a [u8],
    pub nonce_tpm: &'a [u8],
    pub nonce_caller: &'a [u8],
    pub command_code: u32,
    pub handles: &'a [u32],
    pub handle_names: &'a [&'a [u8]],
    pub params: &'a [u8],
    pub session_attributes: u8,
}

/// Session key for TPM2_StartAuthSession with tpmKey/bind = TPM_RH_NULL (Part 1 §19.6.8).
///
/// Unbound unsalted sessions have an empty sessionKey; KDFa applies only to salted/bound starts.
pub fn unbound_unsalted_session_key() -> &'static [u8] {
    &[]
}

/// cpHash = SHA256(cmdCode_BE || handle_name(s) || params)
pub fn compute_cp_hash(command_code: u32, handle_names: &[&[u8]], params: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(command_code.to_be_bytes());
    for name in handle_names {
        hasher.update(name);
    }
    hasher.update(params);
    hasher.finalize().into()
}

/// authHmac = HMAC(session_key, cpHash || nonceCaller || nonceTPM || sessionAttributes)
pub fn compute_auth_hmac(
    session_key: &[u8],
    cp_hash: &[u8],
    nonce_caller: &[u8],
    nonce_tpm: &[u8],
    session_attributes: u8,
) -> [u8; SHA256_DIGEST_SIZE] {
    let mut buf = Vec::with_capacity(cp_hash.len() + nonce_caller.len() + nonce_tpm.len() + 1);
    buf.extend_from_slice(cp_hash);
    buf.extend_from_slice(nonce_caller);
    buf.extend_from_slice(nonce_tpm);
    buf.push(session_attributes);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(session_key).expect("HMAC accepts any key length");
    mac.update(&buf);
    mac.finalize().into_bytes().into()
}

pub fn policy_session_auth_area(input: SessionAuthInput<'_>) -> Vec<u8> {
    let cp_hash = compute_cp_hash(input.command_code, input.handle_names, input.params);
    let auth_hmac = compute_auth_hmac(
        input.session_key,
        &cp_hash,
        input.nonce_caller,
        input.nonce_tpm,
        input.session_attributes,
    );
    build_session_auth(
        input.session_handle,
        input.nonce_caller,
        input.session_attributes,
        &auth_hmac,
    )
}

/// Map policy session handle to the authorization-area session handle (tpm2-tools/RM).
pub fn policy_auth_session_handle(policy_session_handle: u32) -> u32 {
    let index = policy_session_handle & 0x00FF_FFFF;
    0x0200_0000 | (index + 1)
}

/// Authorization-area session handle on the wire.
///
/// Use the handle returned by `StartAuthSession` on all platforms. The legacy abrmd `0x02…`
/// mapping is not used by in-kernel `/dev/tpmrm0` or Windows TBS.
pub fn auth_session_handle_wire(policy_session_handle: u32) -> u32 {
    policy_session_handle
}

/// Match a session handle from a response auth area to our policy session handle.
pub fn session_handles_match(auth_area_handle: u32, session_handle: u32) -> bool {
    auth_area_handle == session_handle
        || auth_area_handle == auth_session_handle_wire(session_handle)
        || auth_area_handle == policy_auth_session_handle(session_handle)
}

pub fn build_session_auth(
    policy_session_handle: u32,
    nonce_caller: &[u8],
    session_attributes: u8,
    auth_hmac: &[u8],
) -> Vec<u8> {
    let auth_handle = auth_session_handle_wire(policy_session_handle);
    let mut session = Vec::with_capacity(4 + 2 + nonce_caller.len() + 1 + 2 + auth_hmac.len());
    session.extend_from_slice(&auth_handle.to_be_bytes());
    session.extend(super::wire::tpm2b(nonce_caller));
    session.push(session_attributes);
    session.extend(super::wire::tpm2b(auth_hmac));
    session
}


pub fn random_nonce_32() -> [u8; SHA256_DIGEST_SIZE] {
    let mut nonce = [0u8; SHA256_DIGEST_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

fn tpm2b_name_from_handle(handle: u32) -> Vec<u8> {
    let bytes = handle.to_be_bytes();
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(&bytes);
    out
}

/// Name bytes for cpHash (TPM 2.0 Part 1 §37.4.2).
/// Persistent/volatile/NV objects use their TPM2B Name; all other handles use raw UINT32 BE.
pub fn handle_name_for_cphash(handle: u32, object_name: Option<&[u8]>) -> Vec<u8> {
    if uses_object_name(handle) {
        object_name
            .map(|n| n.to_vec())
            .unwrap_or_else(|| tpm2b_name_from_handle(handle))
    } else {
        handle.to_be_bytes().to_vec()
    }
}

fn uses_object_name(handle: u32) -> bool {
    let mso = (handle >> 24) & 0xFF;
    mso == TPM2_MSO_PERSISTENT || mso == TPM2_MSO_VOLATILE || mso == TPM2_MSO_NVRAM
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_auth_handle_maps_index_plus_one() {
        assert_eq!(policy_auth_session_handle(0x0300_0013), 0x0200_0014);
    }

    #[test]
    fn unbound_unsalted_session_key_is_empty() {
        assert!(unbound_unsalted_session_key().is_empty());
    }

    #[test]
    fn rh_handle_name_is_raw_uint32() {
        let name = handle_name_for_cphash(0x4000_000B, None);
        assert_eq!(name, [0x40, 0x00, 0x00, 0x0B]);
    }

    #[test]
    fn persistent_handle_uses_object_name() {
        let obj_name = [0x00, 0x03, 0x01, 0x02, 0x03];
        let name = handle_name_for_cphash(0x8101_0001, Some(&obj_name));
        assert_eq!(name, obj_name);
    }
}

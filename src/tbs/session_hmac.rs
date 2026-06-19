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

/// session_key = KDFa(SHA256, empty_auth, "ATH", nonceTPM, nonceCaller, 256)
pub fn session_key_from_start(nonce_tpm: &[u8], nonce_caller: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    kdfa_sha256(&[], b"ATH", nonce_tpm, nonce_caller, 256)
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
    build_session_auth(input.session_handle, input.nonce_caller, input.session_attributes, &auth_hmac)
}

/// Map policy session handle to the authorization-area session handle (tpm2-tools/RM).
pub fn policy_auth_session_handle(policy_session_handle: u32) -> u32 {
    let index = policy_session_handle & 0x00FF_FFFF;
    0x0200_0000 | (index + 1)
}

pub fn build_session_auth(
    policy_session_handle: u32,
    nonce_caller: &[u8],
    session_attributes: u8,
    auth_hmac: &[u8],
) -> Vec<u8> {
    let auth_handle = policy_auth_session_handle(policy_session_handle);
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

fn kdfa_sha256(
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> [u8; SHA256_DIGEST_SIZE] {
    let out_len = SHA256_DIGEST_SIZE;
    let mut out = [0u8; SHA256_DIGEST_SIZE];
    let mut counter = 0u32;
    let mut written = 0usize;
    while written < out_len {
        counter += 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(&counter.to_be_bytes());
        buf.extend_from_slice(label);
        buf.push(0);
        buf.extend_from_slice(context_u);
        buf.extend_from_slice(context_v);
        buf.extend_from_slice(&bits.to_be_bytes());
        let block = hmac_sha256_block(key, &buf);
        let take = (out_len - written).min(block.len());
        out[written..written + take].copy_from_slice(&block[..take]);
        written += take;
    }
    out
}

fn hmac_sha256_block(key: &[u8], data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_auth_handle_maps_index_plus_one() {
        assert_eq!(policy_auth_session_handle(0x0300_0013), 0x0200_0014);
    }

    #[test]
    fn session_key_empty_auth_deterministic() {
        let tpm = [0xAAu8; 32];
        let caller = [0xBBu8; 32];
        let k1 = session_key_from_start(&tpm, &caller);
        let k2 = session_key_from_start(&tpm, &caller);
        assert_eq!(k1, k2);
        assert_ne!(k1, [0u8; 32]);
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

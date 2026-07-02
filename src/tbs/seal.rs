//! TPM2 seal / unseal — keyedhash sealed objects with optional PolicyPCR.

use crate::tbs::commands::{flush_handle, object_handle_from_response};
use crate::tbs::error::{check_tpm_rc, TpmOpError, TpmResult};
use crate::tbs::keys::{
    create_storage_primary, read_tpm2b_wire, AkBlob, LoadedKey,
};
use crate::tbs::parse::{
    parameters_after_rc, ResponseParser, session_nonce_from_response, start_auth_session_nonce_tpm,
};
use crate::tbs::pcr::{pcr_selection_list, PcrBank};
use crate::tbs::read_public::read_public;
use crate::tbs::session_hmac::{
    handle_name_for_cphash, policy_session_auth_area, random_nonce_32,
    unbound_unsalted_session_key, SessionAuthInput,
};
use crate::tbs::wire::{
    asym_scheme_null, command_with_handles_and_sessions, command_with_handles_no_session,
    password_session_null_auth, start_auth_session_policy, tpm2b, tpm2b_empty, u16, u32,
};
use crate::tbs::submit_tpm_command;

const TPM_CC_CREATE: u32 = 0x0000_0153;
const TPM_CC_LOAD: u32 = 0x0000_0157;
const TPM_CC_UNSEAL: u32 = 0x0000_015C;
const TPM_CC_POLICY_PCR: u32 = 0x0000_017D;
const TPM_CC_POLICY_GET_DIGEST: u32 = 0x0000_017B;

const TPM_ALG_KEYEDHASH: u16 = 0x0008;
const TPM_ALG_SHA256: u16 = 0x000B;
/// fixedTPM | fixedParent | userWithAuth | noDA
const SEAL_OBJECT_ATTRIBUTES: u32 = 0x0040_0052;
const TPMA_SESSION_CONTINUESESSION: u8 = 0x01;

const SEAL_MAGIC: &[u8; 4] = b"SEAL";
const SEAL_VERSION: u8 = 1;

struct PolicySession {
    handle: u32,
    nonce_tpm: Vec<u8>,
}

impl PolicySession {
    fn flush(self) -> TpmResult<()> {
        flush_handle(self.handle)
    }

    fn apply_response_nonce(&mut self, resp: &[u8]) {
        if let Ok(nonce) = session_nonce_from_response(resp, self.handle) {
            self.nonce_tpm = nonce;
        }
    }

    fn auth_area(
        &self,
        command_code: u32,
        handles: &[u32],
        handle_names: &[&[u8]],
        params: &[u8],
    ) -> Vec<u8> {
        let nonce_caller = random_nonce_32();
        policy_session_auth_area(SessionAuthInput {
            session_handle: self.handle,
            session_key: unbound_unsalted_session_key(),
            nonce_tpm: &self.nonce_tpm,
            nonce_caller: &nonce_caller,
            command_code,
            handles,
            handle_names,
            params,
            session_attributes: TPMA_SESSION_CONTINUESESSION,
        })
    }
}

fn start_policy_session() -> TpmResult<PolicySession> {
    let nonce_caller = random_nonce_32();
    let cmd = start_auth_session_policy(&nonce_caller);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "StartAuthSession")?;
    let handle = object_handle_from_response(&resp)
        .ok_or_else(|| TpmOpError::other("StartAuthSession: missing session handle"))?;
    let nonce_tpm = start_auth_session_nonce_tpm(&resp)?;
    Ok(PolicySession {
        handle,
        nonce_tpm,
    })
}

fn policy_pcr(session: &mut PolicySession, pcr_selection: &[u8]) -> TpmResult<()> {
    let cmd = command_with_handles_no_session(&[session.handle], TPM_CC_POLICY_PCR, pcr_selection);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "PolicyPCR")?;
    session.apply_response_nonce(&resp);
    Ok(())
}

fn policy_get_digest(session: &PolicySession) -> TpmResult<Vec<u8>> {
    let cmd = command_with_handles_no_session(&[session.handle], TPM_CC_POLICY_GET_DIGEST, &[]);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "PolicyGetDigest")?;
    let mut parser = ResponseParser::after_rc(&resp)?;
    Ok(parser.read_tpm2b()?)
}

fn sensitive_create_with_data(data: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend(tpm2b_empty()); // userAuth
    inner.extend(tpm2b(data));
    tpm2b(&inner)
}

fn public_sealed_template(policy_digest: Option<&[u8]>) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&u16(TPM_ALG_KEYEDHASH));
    t.extend_from_slice(&u16(TPM_ALG_SHA256));
    t.extend_from_slice(&u32(SEAL_OBJECT_ATTRIBUTES));
    match policy_digest {
        Some(d) => t.extend(tpm2b(d)),
        None => t.extend(tpm2b_empty()),
    }
    t.extend(asym_scheme_null()); // keyedhash scheme: TPM_ALG_NULL
    t.extend(tpm2b_empty()); // unique
    tpm2b(&t)
}

fn create_sealed_object(
    parent: u32,
    data: &[u8],
    policy_digest: Option<&[u8]>,
) -> TpmResult<AkBlob> {
    let mut params = Vec::new();
    params.extend(sensitive_create_with_data(data));
    params.extend(public_sealed_template(policy_digest));
    params.extend(tpm2b_empty()); // outsideInfo
    params.extend(tpm2b_empty()); // creationPCR

    let cmd = command_with_handles_and_sessions(
        &[parent],
        &password_session_null_auth(),
        TPM_CC_CREATE,
        &params,
    );
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "Create")?;

    let mut parser = ResponseParser::after_rc(&resp)?;
    let _param_size = parser.read_u32()?;
    let private = read_tpm2b_wire(&mut parser)?;
    let public = read_tpm2b_wire(&mut parser)?;
    Ok(AkBlob { public, private })
}

fn load_sealed(
    parent: u32,
    blob: &AkBlob,
    policy_session: Option<&PolicySession>,
) -> TpmResult<LoadedKey> {
    let mut params = Vec::new();
    params.extend_from_slice(&blob.private);
    params.extend_from_slice(&blob.public);

    let mut sessions = password_session_null_auth();
    if let Some(ps) = policy_session {
        let name = read_public(parent)?.name;
        let parent_name = handle_name_for_cphash(parent, Some(&name));
        let policy_auth = ps.auth_area(
            TPM_CC_LOAD,
            &[parent],
            &[parent_name.as_slice()],
            &params,
        );
        sessions.extend_from_slice(&policy_auth);
    }

    let cmd = command_with_handles_and_sessions(&[parent], &sessions, TPM_CC_LOAD, &params);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "Load")?;

    let handle = object_handle_from_response(&resp)
        .ok_or_else(|| TpmOpError::other("Load: missing object handle"))?;
    Ok(LoadedKey { handle, parent })
}

fn unseal_object(
    object_handle: u32,
    object_name: &[u8],
    policy_session: Option<&PolicySession>,
) -> TpmResult<Vec<u8>> {
    let params: &[u8] = &[];
    let object_name = handle_name_for_cphash(object_handle, Some(object_name));
    let sessions = if let Some(ps) = policy_session {
        ps.auth_area(
            TPM_CC_UNSEAL,
            &[object_handle],
            &[object_name.as_slice()],
            params,
        )
    } else {
        password_session_null_auth()
    };

    let cmd = command_with_handles_and_sessions(&[object_handle], &sessions, TPM_CC_UNSEAL, params);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "Unseal")?;
    let mut parser = parameters_after_rc(&resp)?;
    Ok(parser.read_tpm2b()?)
}

fn validate_pcr_selection(pcr_selection: &[u32]) -> TpmResult<()> {
    if pcr_selection.is_empty() {
        return Err(TpmOpError::invalid_argument(
            "pcrSelection must not be empty when provided",
        ));
    }
    for &idx in pcr_selection {
        if idx >= 24 {
            return Err(TpmOpError::invalid_argument(format!(
                "PCR index must be 0–23, got {idx}"
            )));
        }
    }
    Ok(())
}

fn encode_seal_blob(blob: &AkBlob, pcr_selection: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SEAL_MAGIC);
    out.push(SEAL_VERSION);
    out.extend_from_slice(&(pcr_selection.len() as u32).to_be_bytes());
    for &idx in pcr_selection {
        out.extend_from_slice(&idx.to_be_bytes());
    }
    out.extend_from_slice(&(blob.public.len() as u32).to_be_bytes());
    out.extend_from_slice(&(blob.private.len() as u32).to_be_bytes());
    out.extend_from_slice(&blob.public);
    out.extend_from_slice(&blob.private);
    out
}

fn decode_seal_blob(data: &[u8]) -> TpmResult<(AkBlob, Vec<u32>)> {
    if data.len() < 14 || &data[0..4] != SEAL_MAGIC {
        return Err(TpmOpError::invalid_argument("invalid seal blob (bad magic)"));
    }
    if data[4] != SEAL_VERSION {
        return Err(TpmOpError::invalid_argument(format!(
            "unsupported seal blob version {}",
            data[4]
        )));
    }
    let pcr_count = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
    let mut off = 9;
    if off + pcr_count * 4 + 8 > data.len() {
        return Err(TpmOpError::invalid_argument("truncated seal blob"));
    }
    let mut pcr_selection = Vec::with_capacity(pcr_count);
    for _ in 0..pcr_count {
        pcr_selection.push(u32::from_be_bytes([
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
        ]));
        off += 4;
    }
    let pub_len = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        as usize;
    off += 4;
    let priv_len = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        as usize;
    off += 4;
    if off + pub_len + priv_len > data.len() {
        return Err(TpmOpError::invalid_argument("truncated seal blob payloads"));
    }
    let public = data[off..off + pub_len].to_vec();
    off += pub_len;
    let private = data[off..off + priv_len].to_vec();
    Ok((AkBlob { public, private }, pcr_selection))
}

pub fn seal(data: &[u8], pcr_selection: Option<&[u32]>) -> TpmResult<Vec<u8>> {
    if data.is_empty() {
        return Err(TpmOpError::invalid_argument("seal data must not be empty"));
    }

    let pcr_indices = pcr_selection.unwrap_or(&[]);
    if let Some(sel) = pcr_selection {
        validate_pcr_selection(sel)?;
    }

    let primary = create_storage_primary()?;
    let mut policy_session = None;

    let blob = if pcr_indices.is_empty() {
        create_sealed_object(primary.handle, data, None)?
    } else {
        let mut session = start_policy_session()?;
        let pcr_sel = pcr_selection_list(PcrBank::Sha256, pcr_indices);
        policy_pcr(&mut session, &pcr_sel)?;
        let digest = policy_get_digest(&session)?;
        let blob = create_sealed_object(primary.handle, data, Some(&digest))?;
        policy_session = Some(session);
        blob
    };

    let encoded = encode_seal_blob(&blob, pcr_indices);
    if let Some(session) = policy_session {
        let _ = session.flush();
    }
    primary.flush()?;
    Ok(encoded)
}

pub fn unseal(blob: &[u8]) -> TpmResult<Vec<u8>> {
    let (key_blob, pcr_indices) = decode_seal_blob(blob)?;
    let primary = create_storage_primary()?;

    let result = if pcr_indices.is_empty() {
        let loaded = load_sealed(primary.handle, &key_blob, None)?;
        let name = read_public(loaded.handle)?.name;
        let plain = unseal_object(loaded.handle, &name, None)?;
        let _ = loaded.flush();
        plain
    } else {
        let mut session = start_policy_session()?;
        let pcr_sel = pcr_selection_list(PcrBank::Sha256, &pcr_indices);
        policy_pcr(&mut session, &pcr_sel)?;
        let loaded = load_sealed(primary.handle, &key_blob, Some(&session))?;
        let name = read_public(loaded.handle)?.name;
        let plain = unseal_object(loaded.handle, &name, Some(&session))?;
        let _ = loaded.flush();
        let _ = session.flush();
        plain
    };

    primary.flush()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_blob_roundtrip_encoding() {
        let blob = AkBlob {
            public: {
                let mut v = vec![0xAB; 18];
                v[0] = 0x00;
                v[1] = 0x10;
                v
            },
            private: {
                let mut v = vec![0xCD; 10];
                v[0] = 0x00;
                v[1] = 0x08;
                v
            },
        };
        let encoded = encode_seal_blob(&blob, &[7, 11]);
        let (decoded, pcrs) = decode_seal_blob(&encoded).expect("decode");
        assert_eq!(decoded.public, blob.public);
        assert_eq!(decoded.private, blob.private);
        assert_eq!(pcrs, vec![7, 11]);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let err = decode_seal_blob(b"BAD!").unwrap_err();
        assert_eq!(err.code(), crate::tbs::codes::INVALID_ARGUMENT);
    }

    #[test]
    fn public_sealed_template_starts_with_keyedhash() {
        let t = public_sealed_template(None);
        assert_eq!(&t[2..4], &TPM_ALG_KEYEDHASH.to_be_bytes());
    }

    #[test]
    fn create_command_uses_password_session_for_parent() {
        let mut params = Vec::new();
        params.extend(sensitive_create_with_data(b"secret"));
        params.extend(public_sealed_template(None));
        params.extend(tpm2b_empty());
        params.extend(tpm2b_empty());
        let cmd = command_with_handles_and_sessions(
            &[0x80FF_FFFE],
            &password_session_null_auth(),
            TPM_CC_CREATE,
            &params,
        );
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        assert_eq!(&cmd[6..10], &TPM_CC_CREATE.to_be_bytes());
    }

    #[test]
    fn validate_pcr_selection_rejects_out_of_range() {
        let err = validate_pcr_selection(&[24]).unwrap_err();
        assert_eq!(err.code(), crate::tbs::codes::INVALID_ARGUMENT);
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn hw_seal_roundtrip_without_pcr() {
        if !crate::tbs::hw_test::mutating_enabled() {
            return;
        }
        let secret = b"node-tpm2-seal-test-secret";
        let sealed = seal(secret, None).expect("seal");
        let plain = unseal(&sealed).expect("unseal");
        assert_eq!(plain, secret);
    }
}

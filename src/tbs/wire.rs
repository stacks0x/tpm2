//! TPM 2.0 wire-format marshalling (big-endian).

const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_RH_PW: u32 = 0x4000_0009;
const TPM_RH_NULL: u32 = 0x4000_0007;
const TPM_SE_POLICY: u8 = 0x01;
const TPM_ALG_SHA256: u16 = 0x000B;

pub fn u16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

pub fn u32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// TPM2B_* : UINT16 size + buffer (size bytes only, no padding).
pub fn tpm2b(data: &[u8]) -> Vec<u8> {
    let len = u16::try_from(data.len()).expect("TPM2B size fits u16");
    let mut out = Vec::with_capacity(2 + data.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    out
}

pub fn tpm2b_empty() -> Vec<u8> {
    vec![0x00, 0x00]
}

/// TPM2 command header + body.
pub fn command(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
    let size = u32::try_from(10 + body.len()).expect("command fits u32");
    let mut cmd = Vec::with_capacity(size as usize);
    cmd.extend_from_slice(&tag.to_be_bytes());
    cmd.extend_from_slice(&size.to_be_bytes());
    cmd.extend_from_slice(&code.to_be_bytes());
    cmd.extend_from_slice(body);
    debug_assert_eq!(cmd.len(), size as usize);
    cmd
}

/// Empty-auth password session for hierarchy commands (Owner/Endorsement/Platform).
pub fn password_session_null_auth() -> Vec<u8> {
    let mut session = Vec::with_capacity(9);
    session.extend_from_slice(&TPM_RH_PW.to_be_bytes());
    session.extend(tpm2b_empty()); // nonceCaller
    session.push(0x01); // TPMA_SESSION_CONTINUESESSION
    session.extend(tpm2b_empty()); // empty auth value
    session
}

/// Command with one handle + password session + parameter block.
pub fn command_with_password_session(handle: u32, code: u32, params: &[u8]) -> Vec<u8> {
    command_with_handles_and_session(&[handle], &password_session_null_auth(), code, params)
}

/// Command with multiple handles + one auth session + parameters.
pub fn command_with_handles_and_session(
    handles: &[u32],
    session: &[u8],
    code: u32,
    params: &[u8],
) -> Vec<u8> {
    command_with_handles_and_sessions(handles, session, code, params)
}

/// Command with multiple handles + concatenated auth sessions + parameters.
pub fn command_with_handles_and_sessions(
    handles: &[u32],
    sessions: &[u8],
    code: u32,
    params: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    for h in handles {
        body.extend_from_slice(&h.to_be_bytes());
    }
    body.extend_from_slice(&(sessions.len() as u32).to_be_bytes());
    body.extend_from_slice(sessions);
    body.extend_from_slice(params);
    command(TPM_ST_SESSIONS, code, &body)
}

/// Command with handles and parameters only (Part 3: `TPM_ST_NO_SESSIONS`).
pub fn command_with_handles_no_session(handles: &[u32], code: u32, params: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for h in handles {
        body.extend_from_slice(&h.to_be_bytes());
    }
    body.extend_from_slice(params);
    command(TPM_ST_NO_SESSIONS, code, &body)
}

/// Auth area for ActivateCredential: policy session (auth index 1) + password (auth index 2).
pub fn policy_and_password_sessions(policy_session: &[u8]) -> Vec<u8> {
    let mut sessions = policy_session.to_vec();
    sessions.extend_from_slice(&password_session_null_auth());
    sessions
}

/// TPM2_StartAuthSession for an unbound policy session.
pub fn start_auth_session_policy(nonce_caller: &[u8]) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend_from_slice(&TPM_RH_NULL.to_be_bytes());
    params.extend_from_slice(&TPM_RH_NULL.to_be_bytes());
    params.extend(tpm2b(nonce_caller));
    params.extend(tpm2b_empty()); // encryptedSalt
    params.push(TPM_SE_POLICY);
    params.extend(asym_scheme_null()); // no session encryption
    params.extend_from_slice(&u16(TPM_ALG_SHA256));
    command(TPM_ST_NO_SESSIONS, 0x0000_0176, &params)
}

/// Default symmetric wrapper for restricted storage keys: AES-128-CFB.
pub fn sym_def_aes128_cfb() -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&u16(0x0006)); // TPM_ALG_AES
    s.extend_from_slice(&u16(128)); // AES-128
    s.extend_from_slice(&u16(0x0043)); // TPM_ALG_CFB
    s
}

/// TPMT_ASYM_SCHEME / TPMT_RSA_SCHEME / TPMT_ECC_SCHEME with NULL algorithm.
pub fn asym_scheme_null() -> Vec<u8> {
    u16(0x0010).to_vec() // TPM_ALG_NULL
}

/// TPMT_KDF_SCHEME with NULL algorithm.
pub fn kdf_scheme_null() -> Vec<u8> {
    u16(0x0010).to_vec()
}

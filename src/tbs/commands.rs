//! Hand-marshalled TPM 2.0 command buffers for direct-TBS probes.

use crate::tbs::wire::{
    asym_scheme_null, command, command_with_password_session, kdf_scheme_null,
    sym_def_aes128_cfb, tpm2b, tpm2b_empty, u16, u32,
};

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
#[allow(dead_code)]
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017A;
const TPM_CC_GET_RANDOM: u32 = 0x0000_017B;
const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;

const TPM_CAP_HANDLES: u32 = 0x0000_0001;
/// First transient-object handle (`TPM_HT_TRANSIENT << 24`).
const TPM_HT_TRANSIENT: u32 = 0x8000_0000;

const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ECC_NIST_P256: u16 = 0x0003;

/// tpm2_createprimary storage template attributes (0x30072).
const STORAGE_PRIMARY_ATTRIBUTES: u32 = 0x0003_0072;

#[derive(Debug, Clone, Copy)]
pub enum PrimaryKind {
    Rsa2048,
    EccP256,
}

impl PrimaryKind {
    pub fn label(self) -> &'static str {
        match self {
            PrimaryKind::Rsa2048 => "RSA-2048 storage",
            PrimaryKind::EccP256 => "ECC P256 storage",
        }
    }
}

/// TPM_HT_TRANSIENT object handle returned by CreatePrimary (0x80xxxxxx).
pub fn is_transient_object_handle(handle: u32) -> bool {
    handle & 0xFF00_0000 == 0x8000_0000
}

/// TPM_HT_TRANSIENT object, HMAC/policy session, or saved session handle.
pub fn is_flush_context_handle(handle: u32) -> bool {
    matches!(
        handle & 0xFF00_0000,
        0x8000_0000 | 0x0200_0000 | 0x0300_0000
    )
}

/// TPM2_FlushContext — only transient objects and auth sessions (never persistent keys).
pub fn flush_context(handle: u32) -> Vec<u8> {
    debug_assert!(
        is_flush_context_handle(handle),
        "FlushContext must target a transient object or session handle"
    );
    command(TPM_ST_NO_SESSIONS, TPM_CC_FLUSH_CONTEXT, &u32(handle))
}

/// Submit FlushContext after refusing persistent / permanent handles.
pub fn flush_handle(handle: u32) -> crate::tbs::error::TpmResult<()> {
    use crate::tbs::error::{check_tpm_rc, TpmOpError};
    use crate::tbs::submit_tpm_command;

    if !is_flush_context_handle(handle) {
        return Err(TpmOpError::other(format!(
            "refusing FlushContext on handle 0x{handle:08X} (not a transient object or session)"
        )));
    }
    let resp = submit_tpm_command(&flush_context(handle)).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "FlushContext")?;
    Ok(())
}

/// TPM2_GetCapability for loaded transient object handles.
pub fn get_capability_transient_handles() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&u32(TPM_CAP_HANDLES));
    body.extend_from_slice(&u32(TPM_HT_TRANSIENT));
    body.extend_from_slice(&u32(0xFFFF_FFFF)); // return as many as the TPM allows
    command(TPM_ST_NO_SESSIONS, TPM_CC_GET_CAPABILITY, &body)
}

/// Handle field from a successful CreatePrimary response.
///
/// For both `TPM_ST_NO_SESSIONS` and `TPM_ST_SESSIONS` responses, `objectHandle` is the
/// first parameter at offset 10 (after tag, size, and response code). Verified on Linux
/// swtpm: bytes 10–13 are `0x80FFFFFF`, matching `GetCapability handles-transient`.
pub fn object_handle_from_response(resp: &[u8]) -> Option<u32> {
    if resp.len() < 14 {
        return None;
    }
    let rc = tpm_rc_from_response(resp)?;
    if rc != 0 {
        return None;
    }
    Some(u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]))
}

/// Transient object handles from a successful `GetCapability(TPM_CAP_HANDLES)` response.
pub fn transient_handles_from_getcap(resp: &[u8]) -> Option<Vec<u32>> {
    let rc = tpm_rc_from_response(resp)?;
    if rc != 0 {
        return None;
    }
    if resp.len() < 19 {
        return None;
    }
    let capability = u32::from_be_bytes([resp[11], resp[12], resp[13], resp[14]]);
    if capability != TPM_CAP_HANDLES {
        return None;
    }
    let count = u32::from_be_bytes([resp[15], resp[16], resp[17], resp[18]]) as usize;
    let mut handles = Vec::with_capacity(count);
    let mut offset = 19;
    for _ in 0..count {
        if offset + 4 > resp.len() {
            break;
        }
        let handle = u32::from_be_bytes([
            resp[offset],
            resp[offset + 1],
            resp[offset + 2],
            resp[offset + 3],
        ]);
        if is_transient_object_handle(handle) {
            handles.push(handle);
        }
        offset += 4;
    }
    Some(handles)
}

/// TPM2_GetRandom(bytesRequested)
pub fn get_random_cmd(bytes_requested: u16) -> Vec<u8> {
    command(TPM_ST_NO_SESSIONS, TPM_CC_GET_RANDOM, &u16(bytes_requested))
}

/// TPM2_GetRandom(8)
pub fn get_random_8() -> [u8; 12] {
    get_random_cmd(8).try_into().expect("GetRandom is 12 bytes")
}

/// Null userAuth + empty data inside TPM2B_SENSITIVE_CREATE (what tpm2-tss sends).
fn sensitive_create_null_auth() -> Vec<u8> {
    tpm2b(&[0x00, 0x00, 0x00, 0x00])
}

fn public_rsa2048_storage_primary() -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&u16(TPM_ALG_RSA));
    t.extend_from_slice(&u16(TPM_ALG_SHA256));
    t.extend_from_slice(&u32(STORAGE_PRIMARY_ATTRIBUTES));
    t.extend(tpm2b_empty());
    t.extend(sym_def_aes128_cfb());
    t.extend(asym_scheme_null());
    t.extend_from_slice(&u16(2048));
    t.extend_from_slice(&u32(0)); // exponent 0 => 65537
    t.extend(tpm2b_empty());
    tpm2b(&t)
}

fn public_ecc_p256_storage_primary() -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&u16(TPM_ALG_ECC));
    t.extend_from_slice(&u16(TPM_ALG_SHA256));
    t.extend_from_slice(&u32(STORAGE_PRIMARY_ATTRIBUTES));
    t.extend(tpm2b_empty());
    t.extend(sym_def_aes128_cfb());
    t.extend(asym_scheme_null());
    t.extend_from_slice(&u16(TPM_ECC_NIST_P256));
    t.extend(kdf_scheme_null());
    t.extend(tpm2b_empty());
    t.extend(tpm2b_empty());
    tpm2b(&t)
}

fn create_primary_params(public: Vec<u8>) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend(sensitive_create_null_auth());
    params.extend(public);
    params.extend(tpm2b_empty()); // outsideInfo
    params.extend_from_slice(&u32(0)); // creationPCR.count = 0
    params
}

/// Owner-hierarchy CreatePrimary with null auth via password session.
pub fn create_primary_owner(kind: PrimaryKind) -> Vec<u8> {
    create_primary_on_hierarchy(TPM_RH_OWNER, kind)
}

/// Endorsement-hierarchy CreatePrimary (EK surrogate when no persistent EK exists).
pub fn create_primary_endorsement(kind: PrimaryKind) -> Vec<u8> {
    create_primary_on_hierarchy(TPM_RH_ENDORSEMENT, kind)
}

fn create_primary_on_hierarchy(hierarchy: u32, kind: PrimaryKind) -> Vec<u8> {
    let public = match kind {
        PrimaryKind::Rsa2048 => public_rsa2048_storage_primary(),
        PrimaryKind::EccP256 => public_ecc_p256_storage_primary(),
    };
    let params = create_primary_params(public);
    command_with_password_session(hierarchy, TPM_CC_CREATE_PRIMARY, &params)
}

/// ECC first (swtpm preference), then RSA fallback.
pub fn create_primary_candidates() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "ECC P256 storage primary",
            create_primary_owner(PrimaryKind::EccP256),
        ),
        (
            "RSA-2048 storage primary",
            create_primary_owner(PrimaryKind::Rsa2048),
        ),
    ]
}

pub fn tpm_rc_from_response(resp: &[u8]) -> Option<u32> {
    if resp.len() < 10 {
        return None;
    }
    Some(u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]))
}

pub fn tpm_rc_name(rc: u32) -> &'static str {
    match rc {
        0 => "success",
        0x0000_0100 => "TPM_RC_INITIALIZE",
        0x0000_0125 => "TPM_RC_ASYMMETRIC",
        0x0000_0143 => "TPM_RC_ATTRIBUTES",
        0x0000_017F => "TPM_RC_SIZE",
        0x0000_018B => "TPM_RC_HANDLE",
        0x0000_038E => "TPM_RC_AUTH_FAIL",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_random_golden() {
        assert_eq!(
            get_random_8(),
            [
                0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B, 0x00, 0x08
            ]
        );
    }

    #[test]
    fn ecc_create_primary_golden() {
        let cmd = create_primary_owner(PrimaryKind::EccP256);
        assert_eq!(cmd.len(), 67);
        assert_eq!(&cmd[0..2], &[0x80, 0x02]); // TPM_ST_SESSIONS
        assert_eq!(&cmd[2..6], &[0x00, 0x00, 0x00, 0x43]); // 67 bytes
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x31]);
        assert_eq!(&cmd[10..14], &[0x40, 0x00, 0x00, 0x01]); // TPM_RH_OWNER
        assert_eq!(&cmd[14..18], &[0x00, 0x00, 0x00, 0x09]); // auth area size
        assert_eq!(&cmd[18..22], &[0x40, 0x00, 0x00, 0x09]); // TPM_RH_PW
        assert_eq!(&cmd[22..27], &[0x00, 0x00, 0x01, 0x00, 0x00]); // nonce + attr + empty auth
        assert_eq!(&cmd[27..33], &[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]); // inSensitive
        assert_eq!(&cmd[33..35], &[0x00, 0x1A]); // inPublic size
        assert_eq!(&cmd[35..37], &[0x00, 0x23]); // ECC
        assert_eq!(&cmd[39..43], &STORAGE_PRIMARY_ATTRIBUTES.to_be_bytes());
    }

    #[test]
    fn rsa_create_primary_size() {
        let cmd = create_primary_owner(PrimaryKind::Rsa2048);
        assert_eq!(cmd.len(), 67);
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        assert_eq!(&cmd[35..37], &[0x00, 0x01]); // RSA
    }

    #[test]
    fn flush_context_golden() {
        let cmd = flush_context(0x80FF_FFFF);
        assert_eq!(cmd.len(), 14);
        assert_eq!(&cmd[0..2], &[0x80, 0x01]);
        assert_eq!(&cmd[2..6], &[0x00, 0x00, 0x00, 0x0E]);
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x65]);
        assert_eq!(&cmd[10..14], &[0x80, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn transient_handle_detection() {
        assert!(is_transient_object_handle(0x80FF_FFFF));
        assert!(!is_transient_object_handle(0x8100_0001)); // persistent
        assert!(!is_transient_object_handle(0x4000_0001)); // owner hierarchy
    }

    /// Linux swtpm golden: TPM_ST_SESSIONS CreatePrimary, objectHandle at offset 10.
    #[test]
    fn object_handle_from_linux_create_primary_golden() {
        let golden: [u8; 50] = [
            0x80, 0x02, 0x00, 0x00, 0x01, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x01, 0x13, 0x00, 0x5a, 0x00, 0x23, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x72,
            0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00, 0x43, 0x00, 0x10, 0x00, 0x03, 0x00, 0x10,
            0x00, 0x20, 0x86, 0x4d, 0xb7, 0xb8, 0x38, 0x47,
        ];
        assert_eq!(object_handle_from_response(&golden), Some(0x80FF_FFFF));
        assert_eq!(u16::from_be_bytes([golden[0], golden[1]]), TPM_ST_SESSIONS);
    }

    #[test]
    fn object_handle_from_sessions_response() {
        let mut resp = vec![0u8; 32];
        resp[0..2].copy_from_slice(&[0x80, 0x02]);
        resp[2..6].copy_from_slice(&32u32.to_be_bytes());
        resp[6..10].copy_from_slice(&0u32.to_be_bytes());
        resp[10..14].copy_from_slice(&0x80FF_FFFFu32.to_be_bytes());
        assert_eq!(object_handle_from_response(&resp), Some(0x80FF_FFFF));
    }

    #[test]
    fn transient_handles_from_getcap_golden() {
        let resp: [u8; 23] = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x01, 0x80, 0xff, 0xff, 0xff,
        ];
        assert_eq!(
            transient_handles_from_getcap(&resp),
            Some(vec![0x80FF_FFFF])
        );
    }

    #[test]
    fn get_capability_transient_handles_golden() {
        let cmd = get_capability_transient_handles();
        assert_eq!(cmd.len(), 22);
        assert_eq!(&cmd[0..2], &[0x80, 0x01]);
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x7A]);
        assert_eq!(&cmd[10..14], &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(&cmd[14..18], &[0x80, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn object_handle_from_no_sessions_response() {
        let mut resp = vec![0u8; 18];
        resp[0..2].copy_from_slice(&[0x80, 0x01]);
        resp[2..6].copy_from_slice(&18u32.to_be_bytes());
        resp[6..10].copy_from_slice(&0u32.to_be_bytes());
        resp[10..14].copy_from_slice(&0x8000_00ABu32.to_be_bytes());
        assert_eq!(object_handle_from_response(&resp), Some(0x8000_00AB));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_create_primary_flush_roundtrip() {
        use std::path::Path;

        use crate::tbs::submit_tpm_command;

        if !crate::tbs::hw_test::enabled() {
            return;
        }

        let cmd = create_primary_owner(PrimaryKind::EccP256);
        let resp = submit_tpm_command(&cmd).expect("CreatePrimary");
        let rc = tpm_rc_from_response(&resp).expect("rc");
        assert_eq!(rc, 0, "CreatePrimary failed 0x{rc:08X}");

        let handle = object_handle_from_response(&resp).expect("objectHandle");
        assert!(
            is_transient_object_handle(handle),
            "expected transient handle, got 0x{handle:08X}"
        );

        let cap = submit_tpm_command(&get_capability_transient_handles()).expect("GetCapability");
        let listed = transient_handles_from_getcap(&cap).unwrap_or_default();
        assert!(
            listed.contains(&handle),
            "GetCapability should list 0x{handle:08X}, got {listed:?}"
        );

        let flush_resp = submit_tpm_command(&flush_context(handle)).expect("FlushContext");
        let flush_rc = tpm_rc_from_response(&flush_resp).expect("flush rc");
        assert_eq!(flush_rc, 0, "FlushContext failed 0x{flush_rc:08X}");

        let cap_after = submit_tpm_command(&get_capability_transient_handles()).expect("GetCapability");
        let remaining = transient_handles_from_getcap(&cap_after).unwrap_or_default();
        assert!(
            !remaining.contains(&handle),
            "handle 0x{handle:08X} still loaded after flush: {remaining:?}"
        );
    }
}

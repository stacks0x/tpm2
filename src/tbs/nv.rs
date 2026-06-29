//! TPM2 NV_ReadPublic / NV_Read / NV_Write.

use crate::tbs::error::{check_tpm_rc, TpmOpError, TpmResult};
use crate::tbs::parse::{parameters_after_rc, ResponseParser};
use crate::tbs::read_public::parse_handle;
use crate::tbs::wire::{
    command_with_handles_and_session, command_with_handles_no_session,
    password_session_auth, tpm2b, tpm2b_empty,
};
use crate::tbs::submit_tpm_command;

const TPM_CC_NV_READ: u32 = 0x0000_014E;
const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0178;
const TPM_CC_NV_WRITE: u32 = 0x0000_0137;
const TPM_CC_NV_DEFINE_SPACE: u32 = 0x0000_012A;
const TPM_CC_NV_UNDEFINE_SPACE: u32 = 0x0000_0122;
const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_ALG_SHA256: u16 = 0x000B;

// TPMA_NV (TPM 2.0 Part 2, Table "TPMA_NV")
const TPMA_NV_PPWRITE: u32 = 1 << 0;
const TPMA_NV_OWNERWRITE: u32 = 1 << 1;
const TPMA_NV_AUTHWRITE: u32 = 1 << 2;
const TPMA_NV_PPREAD: u32 = 1 << 16;
const TPMA_NV_OWNERREAD: u32 = 1 << 17;
const TPMA_NV_AUTHREAD: u32 = 1 << 18;
const TPMA_NV_NO_DA: u32 = 1 << 27;

/// Default for `nv_define`: owner read/write, no dictionary attack lockout.
pub const DEFAULT_NV_DEFINE_ATTRIBUTES: u32 =
    TPMA_NV_OWNERREAD | TPMA_NV_OWNERWRITE | TPMA_NV_NO_DA;

/// Owner NV index range (TPM 2.0 Part 2).
const OWNER_NV_INDEX_MIN: u32 = 0x0180_0000;
const OWNER_NV_INDEX_MAX: u32 = 0x01BF_FFFF;

/// Standard EK certificate NV indices (TCG provisioning).
const EK_CERT_INDICES: [u32; 2] = [0x01c0_0002, 0x01c0_000A];

pub struct NvIndexInfo {
    pub data_size: u16,
    pub attributes: u32,
}

/// Parse NV index handle from hex string (`0x01c00002`) or decimal/hex without prefix.
pub fn parse_nv_handle(handle: &str) -> TpmResult<u32> {
    parse_handle(handle)
}

pub fn read_ek_certificate() -> TpmResult<Option<Vec<u8>>> {
    for &index in &EK_CERT_INDICES {
        match nv_read_public(index).and_then(|info| {
            if info.data_size == 0 {
                return Ok(None);
            }
            nv_read(index, 0, info.data_size, None, None, None).map(Some)
        }) {
            Ok(Some(data)) if !data.is_empty() => return Ok(Some(data)),
            Ok(_) => continue,
            Err(e) if e.code() == crate::tbs::codes::TPM_RC => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

pub fn nv_read_public(index: u32) -> TpmResult<NvIndexInfo> {
    let cmd = command_with_handles_no_session(&[index], TPM_CC_NV_READ_PUBLIC, &[]);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "NV_ReadPublic")?;
    parse_nv_read_public_response(&resp)
}

fn parse_nv_read_public_response(resp: &[u8]) -> TpmResult<NvIndexInfo> {
    parse_nv_read_public_fields(resp)
}

fn parse_nv_read_public_fields(resp: &[u8]) -> TpmResult<NvIndexInfo> {
    parse_nv_read_public_fields_skip(resp, nv_read_public_skip_param_size(resp)).or_else(|_| {
        let alt = !nv_read_public_skip_param_size(resp);
        parse_nv_read_public_fields_skip(resp, alt)
    })
}

/// Windows TBS often omits the response parameter-area size prefix (same as ReadPublic).
fn nv_read_public_skip_param_size(resp: &[u8]) -> bool {
    if resp.len() < 12 {
        return true;
    }
    let first_u16 = u16::from_be_bytes([resp[10], resp[11]]);
    !(first_u16 >= 14 && (12 + first_u16 as usize) <= resp.len())
}

fn parse_nv_read_public_fields_skip(
    resp: &[u8],
    skip_param_size: bool,
) -> TpmResult<NvIndexInfo> {
    let mut parser = ResponseParser::after_rc(resp)?;
    if skip_param_size {
        let _ = parser.read_u32()?;
    }
    let nv_public = parser.read_tpm2b()?;
    if nv_public.len() < 14 {
        return Err(TpmOpError::other("NV_ReadPublic: truncated nvPublic"));
    }
    let attributes = u32::from_be_bytes([nv_public[6], nv_public[7], nv_public[8], nv_public[9]]);
    let data_size = u16::from_be_bytes([nv_public[12], nv_public[13]]);
    Ok(NvIndexInfo {
        data_size,
        attributes,
    })
}

/// Resolve NV metadata. On Windows, raw TBS often rejects `NV_ReadPublic` for owner-range
/// indices (TPM_RC ~0xA6) even after a successful `NV_DefineSpace`; fall back to caller
/// hints or default owner attributes so read/write still work.
fn nv_index_info(index: u32, hint: Option<NvIndexInfo>) -> TpmResult<NvIndexInfo> {
    if let Some(info) = hint {
        return Ok(info);
    }
    match nv_read_public(index) {
        Ok(info) => Ok(info),
        Err(e) if owner_nv_read_public_fallback(index, &e) => Ok(NvIndexInfo {
            data_size: u16::MAX,
            attributes: DEFAULT_NV_DEFINE_ATTRIBUTES,
        }),
        Err(e) => Err(e),
    }
}

fn owner_nv_read_public_fallback(index: u32, err: &TpmOpError) -> bool {
    if !(OWNER_NV_INDEX_MIN..=OWNER_NV_INDEX_MAX).contains(&index) {
        return false;
    }
    #[cfg(windows)]
    {
        if err.code() == crate::tbs::codes::MARSHALLING_ERROR {
            return true;
        }
        if err.code() == crate::tbs::codes::TPM_RC {
            return matches!(err.tpm_rc(), Some(0x0000_00A6) | Some(0x0000_018B));
        }
    }
    #[cfg(not(windows))]
    let _ = err;
    false
}

fn validate_nv_bounds(
    info: &NvIndexInfo,
    offset: u16,
    len: u32,
    op: &str,
) -> TpmResult<()> {
    if info.data_size == u16::MAX {
        return Ok(());
    }
    if offset as u32 + len > info.data_size as u32 {
        return Err(TpmOpError::invalid_argument(format!(
            "NV {op} range {}..{} exceeds index data size {}",
            offset,
            offset as u32 + len,
            info.data_size
        )));
    }
    Ok(())
}

fn nv_auth_handle(index: u32, attributes: u32, for_write: bool) -> u32 {
    let auth_bit = if for_write {
        TPMA_NV_AUTHWRITE
    } else {
        TPMA_NV_AUTHREAD
    };
    let owner_bit = if for_write {
        TPMA_NV_OWNERWRITE
    } else {
        TPMA_NV_OWNERREAD
    };
    let pp_bit = if for_write {
        TPMA_NV_PPWRITE
    } else {
        TPMA_NV_PPREAD
    };
    if attributes & auth_bit != 0 {
        index
    } else if attributes & (owner_bit | pp_bit) != 0 {
        TPM_RH_OWNER
    } else {
        index
    }
}

fn validate_owner_nv_index(index: u32) -> TpmResult<()> {
    if !(OWNER_NV_INDEX_MIN..=OWNER_NV_INDEX_MAX).contains(&index) {
        return Err(TpmOpError::invalid_argument(format!(
            "NV index must be in owner range 0x{OWNER_NV_INDEX_MIN:08X}..=0x{OWNER_NV_INDEX_MAX:08X}, got 0x{index:08X}"
        )));
    }
    if EK_CERT_INDICES.contains(&index) {
        return Err(TpmOpError::invalid_argument(
            "refusing to modify well-known EK certificate NV index",
        ));
    }
    Ok(())
}

fn marshal_nv_public(index: u32, attributes: u32, data_size: u16) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&index.to_be_bytes());
    inner.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    inner.extend_from_slice(&attributes.to_be_bytes());
    inner.extend(tpm2b_empty()); // authPolicy
    inner.extend_from_slice(&data_size.to_be_bytes());
    tpm2b(&inner)
}

pub struct NvDefineOptions {
    pub index: u32,
    pub size: u16,
    pub attributes: Option<u32>,
    /// Password for the NV index (`TPMA_NV_AUTHREAD` / `AUTHWRITE` indices).
    pub index_auth: Option<Vec<u8>>,
    /// Owner hierarchy password (often empty on consumer TPMs).
    pub owner_auth: Option<Vec<u8>>,
}

/// Create an owner NV index (`TPM2_NV_DefineSpace`). Requires owner authorization.
pub fn nv_define(opts: &NvDefineOptions) -> TpmResult<()> {
    validate_owner_nv_index(opts.index)?;
    if opts.size == 0 {
        return Err(TpmOpError::invalid_argument("NV define size must be > 0"));
    }
    let attributes = opts.attributes.unwrap_or(DEFAULT_NV_DEFINE_ATTRIBUTES);
    let mut params = Vec::new();
    params.extend(tpm2b(opts.index_auth.as_deref().unwrap_or(&[])));
    params.extend(marshal_nv_public(opts.index, attributes, opts.size));
    let session = password_session_auth(opts.owner_auth.as_deref().unwrap_or(&[]));
    let cmd = command_with_handles_and_session(
        &[TPM_RH_OWNER],
        &session,
        TPM_CC_NV_DEFINE_SPACE,
        &params,
    );
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    crate::tbs::error::check_nv_owner_rc(&resp, "NV_DefineSpace")?;
    Ok(())
}

/// Delete an owner NV index (`TPM2_NV_UndefineSpace`). Requires owner authorization.
pub fn nv_undefine(index: u32, owner_auth: Option<&[u8]>) -> TpmResult<()> {
    validate_owner_nv_index(index)?;
    let session = password_session_auth(owner_auth.unwrap_or(&[]));
    // Part 3: two handles (authHandle + nvIndex), no command parameters.
    let cmd = command_with_handles_and_session(
        &[TPM_RH_OWNER, index],
        &session,
        TPM_CC_NV_UNDEFINE_SPACE,
        &[],
    );
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    match crate::tbs::error::check_nv_owner_rc(&resp, "NV_UndefineSpace") {
        Ok(()) => Ok(()),
        Err(e) if nv_undefine_absent_ok(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

const TPM_RC_HANDLE_FMT1: u32 = 0x0000_008B;

fn nv_undefine_absent_ok(err: &TpmOpError) -> bool {
    matches!(err.tpm_rc(), Some(TPM_RC_HANDLE_FMT1) | Some(0x0000_018B))
}

fn nv_session_auth(
    auth_handle: u32,
    index_auth: Option<&[u8]>,
    owner_auth: Option<&[u8]>,
) -> Vec<u8> {
    if auth_handle == TPM_RH_OWNER {
        password_session_auth(owner_auth.unwrap_or(&[]))
    } else {
        password_session_auth(index_auth.unwrap_or(&[]))
    }
}

/// Handles + parameters for NV_Read / NV_Write.
///
/// Wire layout matches tpm2-tss Sys Prepare + CommonPrepareEpilogue:
/// - Two handles when authHandle != nvIndex: `[authHandle, nvIndex]`, then auth area, then params.
/// - NV_Read params: `size` (u16), `offset` (u16).
/// - NV_Write params: `data` (TPM2B), `offset` (u16).
fn nv_access_handles_and_params(
    auth_handle: u32,
    index: u32,
    params: Vec<u8>,
) -> (Vec<u32>, Vec<u8>) {
    if auth_handle == index {
        (vec![index], params)
    } else {
        (vec![auth_handle, index], params)
    }
}

pub fn nv_read(
    index: u32,
    offset: u16,
    size: u16,
    index_auth: Option<&[u8]>,
    owner_auth: Option<&[u8]>,
    info_hint: Option<NvIndexInfo>,
) -> TpmResult<Vec<u8>> {
    if size == 0 {
        return Err(TpmOpError::invalid_argument("NV read size must be > 0"));
    }
    let info = nv_index_info(index, info_hint)?;
    validate_nv_bounds(&info, offset, size as u32, "read")?;

    let auth_handle = nv_auth_handle(index, info.attributes, false);
    // tpm2-tss NV_Read Prepare: size then offset (after authHandle + nvIndex handles).
    let mut params = Vec::new();
    params.extend_from_slice(&size.to_be_bytes());
    params.extend_from_slice(&offset.to_be_bytes());
    let (handles, params) = nv_access_handles_and_params(auth_handle, index, params);
    let session = nv_session_auth(auth_handle, index_auth, owner_auth);
    let cmd = command_with_handles_and_session(&handles, &session, TPM_CC_NV_READ, &params);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "NV_Read")?;
    parse_nv_read_response(&resp)
}

fn parse_nv_read_response(resp: &[u8]) -> TpmResult<Vec<u8>> {
    parse_nv_read_response_via_parameters(resp).or_else(|_| {
        let mut parser = ResponseParser::after_rc(resp)?;
        parser.read_tpm2b()
    })
}

fn parse_nv_read_response_via_parameters(resp: &[u8]) -> TpmResult<Vec<u8>> {
    let mut parser = parameters_after_rc(resp)?;
    parser.read_tpm2b()
}

pub fn nv_write(
    index: u32,
    offset: u16,
    data: &[u8],
    index_auth: Option<&[u8]>,
    owner_auth: Option<&[u8]>,
    info_hint: Option<NvIndexInfo>,
) -> TpmResult<()> {
    if data.is_empty() {
        return Err(TpmOpError::invalid_argument("NV write data must not be empty"));
    }
    let info = nv_index_info(index, info_hint)?;
    validate_nv_bounds(&info, offset, data.len() as u32, "write")?;

    let auth_handle = nv_auth_handle(index, info.attributes, true);
    // tpm2-tss NV_Write: data then offset (after handles).
    let mut params = Vec::new();
    params.extend(tpm2b(data));
    params.extend_from_slice(&offset.to_be_bytes());
    let (handles, params) = nv_access_handles_and_params(auth_handle, index, params);
    let session = nv_session_auth(auth_handle, index_auth, owner_auth);
    let cmd = command_with_handles_and_session(&handles, &session, TPM_CC_NV_WRITE, &params);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "NV_Write")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tbs::wire::{password_session_null_auth, tpm2b_empty};

    #[test]
    fn nv_read_public_command_golden() {
        let cmd = command_with_handles_no_session(&[0x01c0_0002], TPM_CC_NV_READ_PUBLIC, &[]);
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x78]);
        assert_eq!(&cmd[10..14], &[0x01, 0xc0, 0x00, 0x02]);
    }

    #[test]
    fn owner_nv_read_public_fallback_rejects_ek_index() {
        let err = TpmOpError::marshalling_tpm_rc("NV_ReadPublic", "format", 0x0000_00A6);
        assert!(!owner_nv_read_public_fallback(0x01c0_0002, &err));
        #[cfg(windows)]
        assert!(owner_nv_read_public_fallback(0x0180_0042, &err));
    }

    #[test]
    fn nv_read_command_golden_full_owner_index() {
        let mut params = Vec::new();
        params.extend_from_slice(&32u16.to_be_bytes());
        params.extend_from_slice(&0u16.to_be_bytes());
        let cmd = command_with_handles_and_session(
            &[TPM_RH_OWNER, 0x0180_0042],
            &password_session_null_auth(),
            TPM_CC_NV_READ,
            &params,
        );
        // Header
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        assert_eq!(u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]), cmd.len() as u32);
        assert_eq!(&cmd[6..10], &TPM_CC_NV_READ.to_be_bytes());
        // Handles
        assert_eq!(&cmd[10..14], &TPM_RH_OWNER.to_be_bytes());
        assert_eq!(&cmd[14..18], &0x0180_0042u32.to_be_bytes());
        // Auth area: count=1, password session (9 bytes)
        assert_eq!(&cmd[18..22], &[0, 0, 0, 9]);
        assert_eq!(&cmd[22..31], password_session_null_auth().as_slice());
        // Params: size=32, offset=0
        assert_eq!(&cmd[31..35], &[0x00, 0x20, 0x00, 0x00]);
        assert_eq!(cmd.len(), 35);
    }

    #[test]
    fn nv_read_command_golden_prefix() {
        let mut params = Vec::new();
        params.extend_from_slice(&64u16.to_be_bytes());
        params.extend_from_slice(&0u16.to_be_bytes());
        let cmd = command_with_handles_and_session(
            &[TPM_RH_OWNER, 0x01c0_0002],
            &password_session_null_auth(),
            TPM_CC_NV_READ,
            &params,
        );
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        assert_eq!(&cmd[6..10], &TPM_CC_NV_READ.to_be_bytes());
        assert_eq!(&cmd[10..14], &TPM_RH_OWNER.to_be_bytes());
        assert_eq!(&cmd[14..18], &0x01c0_0002u32.to_be_bytes());
    }

    #[test]
    fn parse_nv_read_response_sessions_no_auth_area() {
        let payload = b"node-tpm2-nv-read-test!!";
        let body: u32 = (2 + payload.len()) as u32;
        let total: u32 = 10 + 4 + body;
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x80, 0x02]);
        resp.extend_from_slice(&total.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        resp.extend_from_slice(&body.to_be_bytes());
        resp.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        resp.extend_from_slice(payload);
        let got = parse_nv_read_response(&resp).expect("parse");
        assert_eq!(got, payload);
    }

    #[test]
    fn nv_write_command_golden_prefix() {
        let data = b"test";
        let mut params = Vec::new();
        params.extend(tpm2b(data));
        params.extend_from_slice(&0u16.to_be_bytes());
        let cmd = command_with_handles_and_session(
            &[TPM_RH_OWNER, 0x0180_0001],
            &password_session_null_auth(),
            TPM_CC_NV_WRITE,
            &params,
        );
        assert_eq!(&cmd[6..10], &TPM_CC_NV_WRITE.to_be_bytes());
        assert_eq!(&cmd[10..14], &TPM_RH_OWNER.to_be_bytes());
        assert_eq!(&cmd[14..18], &0x0180_0001u32.to_be_bytes());
    }

    #[test]
    fn nv_write_index_auth_uses_single_handle() {
        let data = b"x";
        let mut params = Vec::new();
        params.extend(tpm2b(data));
        params.extend_from_slice(&0u16.to_be_bytes());
        let cmd = command_with_handles_and_session(
            &[0x0180_0001],
            &password_session_null_auth(),
            TPM_CC_NV_WRITE,
            &params,
        );
        assert_eq!(&cmd[10..14], &0x0180_0001u32.to_be_bytes());
        assert_eq!(cmd.len(), 10 + 4 + 4 + 9 + params.len());
    }

    #[test]
    fn parse_nv_handle_accepts_hex_prefix() {
        assert_eq!(parse_nv_handle("0x01c00002").unwrap(), 0x01c0_0002);
        assert_eq!(parse_nv_handle("01c00002").unwrap(), 0x01c0_0002);
    }

    #[test]
    fn nv_read_rejects_zero_size() {
        let err = nv_read(0x01c0_0002, 0, 0, None, None, None).unwrap_err();
        assert_eq!(err.code(), crate::tbs::codes::INVALID_ARGUMENT);
    }

    #[test]
    fn nv_auth_handle_selects_owner_for_ppread() {
        let attrs = TPMA_NV_PPREAD;
        assert_eq!(nv_auth_handle(0x01c0_0002, attrs, false), TPM_RH_OWNER);
    }

    #[test]
    fn nv_auth_handle_selects_owner_for_ownerwrite() {
        let attrs = TPMA_NV_OWNERWRITE;
        assert_eq!(nv_auth_handle(0x0180_0001, attrs, true), TPM_RH_OWNER);
    }

    #[test]
    fn nv_undefine_command_golden_prefix() {
        let cmd = command_with_handles_and_session(
            &[TPM_RH_OWNER, 0x0180_0042],
            &password_session_null_auth(),
            TPM_CC_NV_UNDEFINE_SPACE,
            &[],
        );
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        assert_eq!(&cmd[6..10], &TPM_CC_NV_UNDEFINE_SPACE.to_be_bytes());
        assert_eq!(&cmd[10..14], &TPM_RH_OWNER.to_be_bytes());
        assert_eq!(&cmd[14..18], &0x0180_0042u32.to_be_bytes());
    }

    #[test]
    fn nv_undefine_absent_index_is_ok() {
        let err = TpmOpError::from_tpm_rc(TPM_RC_HANDLE_FMT1, "NV_UndefineSpace");
        assert!(nv_undefine_absent_ok(&err));
    }

    #[test]
    fn nv_define_command_golden_prefix() {
        let attributes = DEFAULT_NV_DEFINE_ATTRIBUTES;
        let mut params = Vec::new();
        params.extend(tpm2b_empty());
        params.extend(marshal_nv_public(0x0180_0001, attributes, 64));
        let cmd = command_with_handles_and_session(
            &[TPM_RH_OWNER],
            &password_session_null_auth(),
            TPM_CC_NV_DEFINE_SPACE,
            &params,
        );
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        assert_eq!(&cmd[6..10], &TPM_CC_NV_DEFINE_SPACE.to_be_bytes());
        assert_eq!(&cmd[10..14], &TPM_RH_OWNER.to_be_bytes());
    }

    #[test]
    fn nv_define_rejects_ek_index() {
        let opts = NvDefineOptions {
            index: 0x01c0_0002,
            size: 64,
            attributes: None,
            index_auth: None,
            owner_auth: None,
        };
        let err = nv_define(&opts).unwrap_err();
        assert_eq!(err.code(), crate::tbs::codes::INVALID_ARGUMENT);
    }

    #[test]
    fn nv_define_rejects_out_of_range_index() {
        let opts = NvDefineOptions {
            index: 0x0100_0001,
            size: 64,
            attributes: None,
            index_auth: None,
            owner_auth: None,
        };
        let err = nv_define(&opts).unwrap_err();
        assert_eq!(err.code(), crate::tbs::codes::INVALID_ARGUMENT);
    }

    #[test]
    fn nv_auth_handle_selects_index_for_authread() {
        let attrs = TPMA_NV_AUTHREAD;
        assert_eq!(nv_auth_handle(0x0180_0001, attrs, false), 0x0180_0001);
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn hw_read_ek_certificate() {
        if !crate::tbs::hw_test::enabled() {
            return;
        }
        let _ = read_ek_certificate();
    }
}

//! TPM2 NV_ReadPublic / NV_Read / NV_Write.

use crate::tbs::commands::tpm_rc_from_response;
use crate::tbs::error::{check_tpm_rc, TpmOpError, TpmResult};
use crate::tbs::parse::ResponseParser;
use crate::tbs::read_public::parse_handle;
use crate::tbs::wire::{
    command, command_with_handles_and_session, password_session_auth, tpm2b, tpm2b_empty, u32,
};
use crate::tbs::submit_tpm_command;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
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
const DEFAULT_NV_DEFINE_ATTRIBUTES: u32 =
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
            nv_read(index, 0, info.data_size, None).map(Some)
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
    let cmd = command(TPM_ST_NO_SESSIONS, TPM_CC_NV_READ_PUBLIC, &u32(index));
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    let rc = tpm_rc_from_response(&resp)
        .ok_or_else(|| TpmOpError::other("NV_ReadPublic: short response"))?;
    if rc != 0 {
        return Err(TpmOpError::from_tpm_rc(rc, "NV_ReadPublic"));
    }

    let mut parser = ResponseParser::after_rc(&resp)?;
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
    check_tpm_rc(&resp, "NV_DefineSpace")?;
    Ok(())
}

/// Delete an owner NV index (`TPM2_NV_UndefineSpace`). Requires owner authorization.
pub fn nv_undefine(index: u32, owner_auth: Option<&[u8]>) -> TpmResult<()> {
    validate_owner_nv_index(index)?;
    let session = password_session_auth(owner_auth.unwrap_or(&[]));
    let cmd = command_with_handles_and_session(
        &[TPM_RH_OWNER],
        &session,
        TPM_CC_NV_UNDEFINE_SPACE,
        &u32(index),
    );
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "NV_UndefineSpace")?;
    Ok(())
}

pub fn nv_read(
    index: u32,
    offset: u16,
    size: u16,
    auth: Option<&[u8]>,
) -> TpmResult<Vec<u8>> {
    if size == 0 {
        return Err(TpmOpError::invalid_argument("NV read size must be > 0"));
    }
    let info = nv_read_public(index)?;
    if offset as u32 + size as u32 > info.data_size as u32 {
        return Err(TpmOpError::invalid_argument(format!(
            "NV read range {}..{} exceeds index data size {}",
            offset,
            offset as u32 + size as u32,
            info.data_size
        )));
    }

    let auth_handle = nv_auth_handle(index, info.attributes, false);
    let mut body = Vec::new();
    body.extend_from_slice(&u32(index));
    body.extend_from_slice(&offset.to_be_bytes());
    body.extend_from_slice(&size.to_be_bytes());
    let session = password_session_auth(auth.unwrap_or(&[]));
    let cmd = command_with_handles_and_session(&[auth_handle], &session, TPM_CC_NV_READ, &body);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "NV_Read")?;
    let mut parser = ResponseParser::after_rc(&resp)?;
    Ok(parser.read_tpm2b()?)
}

pub fn nv_write(
    index: u32,
    offset: u16,
    data: &[u8],
    auth: Option<&[u8]>,
) -> TpmResult<()> {
    if data.is_empty() {
        return Err(TpmOpError::invalid_argument("NV write data must not be empty"));
    }
    let info = nv_read_public(index)?;
    if offset as u32 + data.len() as u32 > info.data_size as u32 {
        return Err(TpmOpError::invalid_argument(format!(
            "NV write range {}..{} exceeds index data size {}",
            offset,
            offset as u32 + data.len() as u32,
            info.data_size
        )));
    }

    let auth_handle = nv_auth_handle(index, info.attributes, true);
    let mut body = Vec::new();
    body.extend_from_slice(&u32(index));
    body.extend_from_slice(&offset.to_be_bytes());
    body.extend(tpm2b(data));
    let session = password_session_auth(auth.unwrap_or(&[]));
    let cmd = command_with_handles_and_session(&[auth_handle], &session, TPM_CC_NV_WRITE, &body);
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
        let cmd = command(TPM_ST_NO_SESSIONS, TPM_CC_NV_READ_PUBLIC, &u32(0x01c0_0002));
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x78]);
        assert_eq!(&cmd[10..14], &[0x01, 0xc0, 0x00, 0x02]);
    }

    #[test]
    fn nv_read_command_golden_prefix() {
        let mut body = Vec::new();
        body.extend_from_slice(&u32(0x01c0_0002));
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&64u16.to_be_bytes());
        let cmd = command_with_handles_and_session(
            &[TPM_RH_OWNER],
            &password_session_null_auth(),
            TPM_CC_NV_READ,
            &body,
        );
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        assert_eq!(&cmd[6..10], &TPM_CC_NV_READ.to_be_bytes());
        assert_eq!(&cmd[10..14], &TPM_RH_OWNER.to_be_bytes());
    }

    #[test]
    fn nv_write_command_golden_prefix() {
        let data = b"test";
        let mut body = Vec::new();
        body.extend_from_slice(&u32(0x0180_0001));
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend(tpm2b(data));
        let cmd = command_with_handles_and_session(
            &[0x0180_0001],
            &password_session_null_auth(),
            TPM_CC_NV_WRITE,
            &body,
        );
        assert_eq!(&cmd[6..10], &TPM_CC_NV_WRITE.to_be_bytes());
        assert_eq!(&cmd[10..14], &0x0180_0001u32.to_be_bytes());
    }

    #[test]
    fn parse_nv_handle_accepts_hex_prefix() {
        assert_eq!(parse_nv_handle("0x01c00002").unwrap(), 0x01c0_0002);
        assert_eq!(parse_nv_handle("01c00002").unwrap(), 0x01c0_0002);
    }

    #[test]
    fn nv_read_rejects_zero_size() {
        let err = nv_read(0x01c0_0002, 0, 0, None).unwrap_err();
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

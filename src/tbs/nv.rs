//! TPM2_NV_ReadPublic / TPM2_NV_Read for the EK certificate index.

use crate::tbs::commands::tpm_rc_from_response;
use crate::tbs::error::{check_tpm_rc, TpmOpError, TpmResult};
use crate::tbs::parse::ResponseParser;
use crate::tbs::wire::{command, command_with_password_session, u32};
use crate::tbs::submit_tpm_command;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_CC_NV_READ: u32 = 0x0000_014E;
const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0178;
const TPM_RH_OWNER: u32 = 0x4000_0001;

/// Standard EK certificate NV indices (TCG provisioning).
const EK_CERT_INDICES: [u32; 2] = [0x01c0_0002, 0x01c0_000A];

pub fn read_ek_certificate() -> TpmResult<Option<Vec<u8>>> {
    for &index in &EK_CERT_INDICES {
        match read_nv_index(index) {
            Ok(Some(data)) if !data.is_empty() => return Ok(Some(data)),
            Ok(_) => continue,
            Err(e) if e.code == "TPM_RC" => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

fn read_nv_index(index: u32) -> TpmResult<Option<Vec<u8>>> {
    let size = match nv_index_data_size(index)? {
        Some(s) if s > 0 => s,
        _ => return Ok(None),
    };
    let data = nv_read(index, 0, size)?;
    Ok(Some(data))
}

fn nv_index_data_size(index: u32) -> TpmResult<Option<u16>> {
    let cmd = command(TPM_ST_NO_SESSIONS, TPM_CC_NV_READ_PUBLIC, &u32(index));
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    let rc = tpm_rc_from_response(&resp).ok_or_else(|| TpmOpError::other("NV_ReadPublic: short response"))?;
    if rc != 0 {
        return Err(TpmOpError::tpm_rc(rc, "NV_ReadPublic"));
    }

    let mut parser = ResponseParser::after_rc(&resp)?;
    let _nv_public = parser.read_tpm2b()?;
    let nv_public = _nv_public;
    if nv_public.len() < 14 {
        return Ok(None);
    }
    let data_size = u16::from_be_bytes([nv_public[12], nv_public[13]]);
    Ok(Some(data_size))
}

fn nv_read(index: u32, offset: u16, size: u16) -> TpmResult<Vec<u8>> {
    let mut body = Vec::new();
    body.extend_from_slice(&u32(index));
    body.extend_from_slice(&offset.to_be_bytes());
    body.extend_from_slice(&size.to_be_bytes());
    let cmd = command_with_password_session(TPM_RH_OWNER, TPM_CC_NV_READ, &body);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "NV_Read")?;
    let mut parser = ResponseParser::after_rc(&resp)?;
    Ok(parser.read_tpm2b()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn nv_read_public_command_golden() {
        let cmd = command(TPM_ST_NO_SESSIONS, TPM_CC_NV_READ_PUBLIC, &u32(0x01c0_0002));
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x78]);
        assert_eq!(&cmd[10..14], &[0x01, 0xc0, 0x00, 0x02]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_read_ek_certificate() {
        if !Path::new("/dev/tpmrm0").exists() {
            return;
        }
        let _ = read_ek_certificate();
    }
}

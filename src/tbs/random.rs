//! TPM2_GetRandom — entropy from the TPM.

use crate::tbs::commands::get_random_cmd;
use crate::tbs::error::{check_tpm_rc, TpmOpError, TpmResult};
use crate::tbs::parse::ResponseParser;
use crate::tbs::submit_tpm_command;

/// TPM 2.0 Part 3: at most 64 bytes per GetRandom call.
const MAX_BYTES_PER_CALL: u32 = 64;

pub fn random_bytes(count: u32) -> TpmResult<Vec<u8>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(count as usize);
    while (out.len() as u32) < count {
        let remaining = count - out.len() as u32;
        let chunk_len = remaining.min(MAX_BYTES_PER_CALL) as u16;
        out.extend_from_slice(&random_chunk(chunk_len)?);
    }
    Ok(out)
}

fn random_chunk(bytes_requested: u16) -> TpmResult<Vec<u8>> {
    if bytes_requested == 0 {
        return Ok(Vec::new());
    }
    let cmd = get_random_cmd(bytes_requested);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "GetRandom")?;
    let mut parser = ResponseParser::after_rc(&resp)?;
    parser.read_tpm2b()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tbs::commands::get_random_8;

    #[test]
    fn get_random_cmd_golden_8() {
        assert_eq!(get_random_8(), [0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B, 0x00, 0x08]);
    }

    #[test]
    fn get_random_cmd_golden_32() {
        let cmd = get_random_cmd(32);
        assert_eq!(cmd.len(), 12);
        assert_eq!(&cmd[10..12], &[0x00, 0x20]);
    }

    #[test]
    fn random_bytes_zero_is_empty() {
        assert!(random_bytes(0).unwrap().is_empty());
    }

    #[test]
    fn parse_get_random_response_golden() {
        let resp = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07,
        ];
        check_tpm_rc(&resp, "GetRandom").unwrap();
        let mut parser = ResponseParser::after_rc(&resp).unwrap();
        assert_eq!(parser.read_tpm2b().unwrap(), vec![1, 2, 3, 4, 5, 6, 7]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn random_bytes_hw_smoke() {
        if !crate::tbs::hw_test::enabled() {
            return;
        }
        let bytes = random_bytes(32).expect("GetRandom");
        assert_eq!(bytes.len(), 32);
    }
}

//! TPM2_PCR_Read — SHA-256 bank by default.

use std::collections::HashMap;

use crate::tbs::error::{check_tpm_rc, TpmOpError, TpmResult};
use crate::tbs::parse::{hex_encode, read_pml_digest, read_pml_pcr_selection, ResponseParser};
use crate::tbs::wire::{command, u16, u32};
use crate::tbs::submit_tpm_command;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_CC_PCR_READ: u32 = 0x0000_017E;
const TPM_ALG_SHA256: u16 = 0x000B;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcrBank {
    Sha256,
}

impl PcrBank {
    pub fn parse(s: Option<&str>) -> TpmResult<Self> {
        match s {
            None | Some("sha256") => Ok(PcrBank::Sha256),
            Some(other) => Err(TpmOpError::other(format!("unsupported PCR bank: {other}"))),
        }
    }
}

pub fn pcr_selection_list(bank: PcrBank, indices: &[u32]) -> Vec<u8> {
    match bank {
        PcrBank::Sha256 => {
            let mut pcr_select = [0u8; 3];
            for &idx in indices {
                if idx >= 24 {
                    continue;
                }
                let byte = (idx / 8) as usize;
                let bit = idx % 8;
                pcr_select[byte] |= 1 << bit;
            }
            let mut sel = Vec::new();
            sel.extend_from_slice(&u16(TPM_ALG_SHA256));
            sel.push(3);
            sel.extend_from_slice(&pcr_select);
            let mut list = Vec::new();
            list.extend_from_slice(&u32(1));
            list.extend(sel);
            list
        }
    }
}

pub fn pcr_read(selection: &[u32], bank: PcrBank) -> TpmResult<HashMap<u32, String>> {
    if selection.is_empty() {
        return Err(TpmOpError::other("PCR selection must not be empty"));
    }
    let body = pcr_selection_list(bank, selection);
    let cmd = command(TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ, &body);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "PCR_Read")?;

    let mut parser = ResponseParser::after_rc(&resp)?;
    let _update_counter = parser.read_u32()?;
    let pcr_lists = read_pml_pcr_selection(&mut parser)?;
    let digests = read_pml_digest(&mut parser)?;

    let mut ordered_indices = Vec::new();
    for (_hash, indices) in pcr_lists {
        ordered_indices.extend(indices);
    }

    if ordered_indices.len() != digests.len() {
        return Err(TpmOpError::other(format!(
            "PCR_Read digest count mismatch: {} indices, {} digests",
            ordered_indices.len(),
            digests.len()
        )));
    }

    let mut out = HashMap::new();
    for (idx, digest) in ordered_indices.into_iter().zip(digests) {
        out.insert(idx, hex_encode(&digest));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn pcr_read_command_golden_prefix() {
        let body = pcr_selection_list(PcrBank::Sha256, &[0, 1, 7]);
        let cmd = command(TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ, &body);
        assert_eq!(&cmd[0..2], &[0x80, 0x01]);
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x7E]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_pcr_read_roundtrip() {
        if !crate::tbs::hw_test::enabled() {
            return;
        }
        let pcrs = pcr_read(&[0, 1, 7], PcrBank::Sha256).expect("pcr_read");
        for idx in [0u32, 1, 7] {
            let digest = pcrs.get(&idx).expect("pcr digest");
            assert_eq!(digest.len(), 64, "SHA-256 PCR digest is 32 bytes hex");
        }
    }

    #[test]
    fn parse_pcr_read_response_layout() {
        let mut resp = vec![0u8; 10 + 4 + 4 + 7 + 4 + 2 + 32 + 4 + 2 + 32 + 4 + 2 + 32];
        resp[6..10].copy_from_slice(&0u32.to_be_bytes());
        let mut off = 10;
        resp[off..off + 4].copy_from_slice(&1u32.to_be_bytes());
        off += 4;
        resp[off..off + 4].copy_from_slice(&1u32.to_be_bytes());
        off += 4;
        resp[off..off + 2].copy_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        off += 2;
        resp[off] = 3;
        off += 1;
        resp[off..off + 3].copy_from_slice(&[0x83, 0x00, 0x00]);
        off += 3;
        resp[off..off + 4].copy_from_slice(&3u32.to_be_bytes());
        off += 4;
        for _ in 0..3 {
            resp[off..off + 2].copy_from_slice(&32u16.to_be_bytes());
            off += 2;
            for i in 0..32 {
                resp[off + i] = i as u8;
            }
            off += 32;
        }
        check_tpm_rc(&resp, "test").unwrap();
        let pcrs = {
            let mut parser = ResponseParser::after_rc(&resp).unwrap();
            let _ = parser.read_u32().unwrap();
            let lists = read_pml_pcr_selection(&mut parser).unwrap();
            let digests = read_pml_digest(&mut parser).unwrap();
            let mut ordered = Vec::new();
            for (_h, idx) in lists {
                ordered.extend(idx);
            }
            ordered.into_iter().zip(digests).collect::<HashMap<_, _>>()
        };
        assert!(pcrs.contains_key(&0));
        assert!(pcrs.contains_key(&1));
        assert!(pcrs.contains_key(&7));
    }
}

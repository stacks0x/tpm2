//! TPM2 PCR commands — SHA-256 bank by default.

use std::collections::HashMap;

use crate::tbs::error::{check_pcr_extend_rc, check_tpm_rc, TpmOpError, TpmResult};
use crate::tbs::parse::{hex_encode, read_pml_digest, read_pml_pcr_selection, ResponseParser};
use crate::tbs::wire::{command, command_with_password_session, u16, u32};
use crate::tbs::submit_tpm_command;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_CC_PCR_READ: u32 = 0x0000_017E;
const TPM_CC_PCR_EXTEND: u32 = 0x0000_0182;
const TPM_ALG_SHA256: u16 = 0x000B;
const SHA256_DIGEST_LEN: usize = 32;

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

fn digest_values_sha256(digest: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32(1));
    out.extend_from_slice(&u16(TPM_ALG_SHA256));
    out.extend_from_slice(digest);
    out
}

pub fn pcr_extend(index: u32, digest: &[u8]) -> TpmResult<()> {
    if index >= 24 {
        return Err(TpmOpError::invalid_argument(format!(
            "PCR index must be 0–23, got {index}"
        )));
    }
    if digest.len() != SHA256_DIGEST_LEN {
        return Err(TpmOpError::invalid_argument(format!(
            "SHA-256 PCR digest must be {SHA256_DIGEST_LEN} bytes, got {}",
            digest.len()
        )));
    }

    let params = digest_values_sha256(digest);
    let cmd = command_with_password_session(index, TPM_CC_PCR_EXTEND, &params);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_pcr_extend_rc(&resp)?;
    Ok(())
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

    #[test]
    fn pcr_extend_command_golden_prefix() {
        let digest = [0xABu8; SHA256_DIGEST_LEN];
        let params = digest_values_sha256(&digest);
        let cmd = command_with_password_session(7, TPM_CC_PCR_EXTEND, &params);
        assert_eq!(cmd.len(), 65);
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x82]);
        assert_eq!(&cmd[10..14], &7u32.to_be_bytes());
        assert_eq!(&cmd[14..18], &9u32.to_be_bytes());
        assert_eq!(&cmd[18..27], &[0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00]);
        assert_eq!(&cmd[27..31], &1u32.to_be_bytes());
        assert_eq!(&cmd[31..33], &TPM_ALG_SHA256.to_be_bytes());
        assert_eq!(&cmd[33..65], &digest);
    }

    #[test]
    fn pcr_extend_rejects_bad_index() {
        let digest = [0u8; SHA256_DIGEST_LEN];
        let err = pcr_extend(24, &digest).unwrap_err();
        assert!(matches!(err, TpmOpError::InvalidArgument { .. }));
    }

    #[test]
    fn pcr_extend_rejects_bad_digest_length() {
        let err = pcr_extend(7, &[0u8; 16]).unwrap_err();
        assert!(matches!(err, TpmOpError::InvalidArgument { .. }));
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

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_pcr_extend_roundtrip() {
        use sha2::{Digest, Sha256};

        if !crate::tbs::hw_test::mutating_enabled() {
            return;
        }

        let idx = 7u32;
        let before = pcr_read(&[idx], PcrBank::Sha256)
            .expect("pcr_read before")
            .get(&idx)
            .expect("pcr 7")
            .clone();

        let measurement = b"measurement";
        let extend_digest = Sha256::digest(measurement);
        pcr_extend(idx, &extend_digest).expect("pcr_extend");

        let after = pcr_read(&[idx], PcrBank::Sha256)
            .expect("pcr_read after")
            .get(&idx)
            .expect("pcr 7")
            .clone();

        assert_ne!(before, after, "PCR digest should change after extend");

        let prior: Vec<u8> = before
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("hex pair"), 16)
                    .expect("hex byte")
            })
            .collect();
        let mut extended = prior;
        extended.extend_from_slice(&extend_digest);
        let expected = hex_encode(&Sha256::digest(&extended));
        assert_eq!(after, expected, "PCR extend should follow SHA-256 bank formula");
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

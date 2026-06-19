//! TPM2_ReadPublic and SPKI DER extraction.

use crate::tbs::error::{check_tpm_rc, TpmOpError, TpmResult};
use crate::tbs::parse::ResponseParser;
use crate::tbs::wire::{command, u32};
use crate::tbs::submit_tpm_command;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_CC_READ_PUBLIC: u32 = 0x0000_0173;
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_ECC: u16 = 0x0023;

pub struct ReadPublicResult {
    pub public_key_der: Vec<u8>,
    /// TPM2B_PUBLIC wire (size prefix + TPMT_PUBLIC), for LoadExternal.
    pub public_wire: Vec<u8>,
    pub name: Vec<u8>,
}

pub fn parse_handle(handle: &str) -> TpmResult<u32> {
    let s = handle.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u32::from_str_radix(s, 16).map_err(|e| TpmOpError::other(format!("invalid TPM handle {handle:?}: {e}")))
}

pub fn read_public(handle: u32) -> TpmResult<ReadPublicResult> {
    let cmd = command(TPM_ST_NO_SESSIONS, TPM_CC_READ_PUBLIC, &u32(handle));
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "ReadPublic")?;

    let mut parser = ResponseParser::after_rc(&resp)?;
    let out_public = parser.read_tpm2b()?;
    let name = parser.read_tpm2b()?;
    let _qualified_name = parser.read_tpm2b()?;

    let mut public_wire = Vec::with_capacity(2 + out_public.len());
    public_wire.extend_from_slice(&(out_public.len() as u16).to_be_bytes());
    public_wire.extend_from_slice(&out_public);

    let public_key_der = tpm2b_public_to_spki_der(&out_public)?;
    Ok(ReadPublicResult {
        public_key_der,
        public_wire,
        name,
    })
}

/// Decode inner TPMT_PUBLIC from a TPM2B wire blob (size prefix + payload).
pub fn public_wire_to_spki_der(wire: &[u8]) -> TpmResult<Vec<u8>> {
    if wire.len() < 2 {
        return Err(TpmOpError::other("AK public wire blob too short"));
    }
    let size = u16::from_be_bytes([wire[0], wire[1]]) as usize;
    if wire.len() < 2 + size {
        return Err(TpmOpError::other("truncated AK public wire blob"));
    }
    tpm2b_public_to_spki_der(&wire[2..2 + size])
}

pub fn tpm2b_public_to_spki_der(public: &[u8]) -> TpmResult<Vec<u8>> {
    if public.len() < 4 {
        return Err(TpmOpError::other("TPM2B_PUBLIC too short"));
    }
    let mut off = 0usize;
    let alg = u16::from_be_bytes([public[off], public[off + 1]]);
    off += 2;
    let _name_alg = u16::from_be_bytes([public[off], public[off + 1]]);
    off += 2;
    let _attrs = u32::from_be_bytes([public[off], public[off + 1], public[off + 2], public[off + 3]]);
    off += 4;
    off = skip_tpm2b(public, off)?;
    off = skip_public_parms(public, alg, off)?;
    match alg {
        TPM_ALG_RSA => rsa_unique_to_spki(public, off),
        TPM_ALG_ECC => ecc_unique_to_spki(public, off),
        other => Err(TpmOpError::other(format!(
            "unsupported public key algorithm 0x{other:04X}"
        ))),
    }
}

fn skip_tpm2b(data: &[u8], off: usize) -> TpmResult<usize> {
    if off + 2 > data.len() {
        return Err(TpmOpError::other("truncated TPM2B"));
    }
    let size = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
    Ok(off + 2 + size)
}

fn skip_public_parms(data: &[u8], alg: u16, mut off: usize) -> TpmResult<usize> {
    match alg {
        TPM_ALG_RSA => {
            off = skip_sym_def(data, off)?;
            off = skip_rsa_scheme(data, off)?;
            if off + 4 > data.len() {
                return Err(TpmOpError::other("truncated RSA parms"));
            }
            off += 4;
            off = skip_tpm2b(data, off)?;
        }
        TPM_ALG_ECC => {
            off = skip_sym_def(data, off)?;
            off = skip_ecc_scheme(data, off)?;
            if off + 2 > data.len() {
                return Err(TpmOpError::other("truncated ECC parms"));
            }
            off += 2;
            off = skip_kdf_scheme(data, off)?;
        }
        _ => {}
    }
    Ok(off)
}

fn skip_sym_def(data: &[u8], off: usize) -> TpmResult<usize> {
    if off + 2 > data.len() {
        return Err(TpmOpError::other("truncated sym def"));
    }
    let alg = u16::from_be_bytes([data[off], data[off + 1]]);
    if alg == 0x0010 {
        return Ok(off + 2);
    }
    if off + 6 > data.len() {
        return Err(TpmOpError::other("truncated sym def"));
    }
    Ok(off + 6)
}

fn skip_rsa_scheme(data: &[u8], off: usize) -> TpmResult<usize> {
    if off + 2 > data.len() {
        return Err(TpmOpError::other("truncated RSA scheme"));
    }
    let scheme = u16::from_be_bytes([data[off], data[off + 1]]);
    if scheme == 0x0010 {
        return Ok(off + 2);
    }
    if off + 4 > data.len() {
        return Err(TpmOpError::other("truncated RSA scheme"));
    }
    Ok(off + 4)
}

fn skip_ecc_scheme(data: &[u8], off: usize) -> TpmResult<usize> {
    if off + 2 > data.len() {
        return Err(TpmOpError::other("truncated ECC scheme"));
    }
    let scheme = u16::from_be_bytes([data[off], data[off + 1]]);
    if scheme == 0x0010 {
        return Ok(off + 2);
    }
    if off + 4 > data.len() {
        return Err(TpmOpError::other("truncated ECC scheme"));
    }
    Ok(off + 4)
}

fn skip_kdf_scheme(data: &[u8], off: usize) -> TpmResult<usize> {
    if off + 2 > data.len() {
        return Err(TpmOpError::other("truncated KDF scheme"));
    }
    let scheme = u16::from_be_bytes([data[off], data[off + 1]]);
    if scheme == 0x0010 {
        return Ok(off + 2);
    }
    Err(TpmOpError::other("unsupported KDF scheme in public area"))
}

fn read_tpm2b_at(data: &[u8], off: usize) -> TpmResult<(Vec<u8>, usize)> {
    if off + 2 > data.len() {
        return Err(TpmOpError::other("truncated TPM2B"));
    }
    let size = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
    if off + 2 + size > data.len() {
        return Err(TpmOpError::other("truncated TPM2B payload"));
    }
    Ok((data[off + 2..off + 2 + size].to_vec(), off + 2 + size))
}

fn rsa_unique_to_spki(data: &[u8], off: usize) -> TpmResult<Vec<u8>> {
    let (modulus, _) = read_tpm2b_at(data, off)?;
    let rsa_seq = der_sequence(&[
        der_integer(&modulus),
        der_integer(&[0x01, 0x00, 0x01]),
    ]);
    let bit_string = der_bit_string(&rsa_seq);
    let alg_id = der_sequence(&[
        der_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]),
        der_null(),
    ]);
    Ok(der_sequence(&[alg_id, bit_string]))
}

fn ecc_unique_to_spki(data: &[u8], off: usize) -> TpmResult<Vec<u8>> {
    let (x_bytes, off) = read_tpm2b_at(data, off)?;
    let (y_bytes, _) = read_tpm2b_at(data, off)?;
    let mut point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
    point.push(0x04);
    point.extend_from_slice(&x_bytes);
    point.extend_from_slice(&y_bytes);
    let bit_string = der_bit_string(&point);
    let alg_id = der_sequence(&[
        der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]),
        der_oid(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
    ]);
    Ok(der_sequence(&[alg_id, bit_string]))
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

fn der_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let content: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    der_tag(0x30, &content)
}

fn der_oid(oid: &[u8]) -> Vec<u8> {
    der_tag(0x06, oid)
}

fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    if !v.is_empty() && v[0] & 0x80 != 0 {
        v.insert(0, 0x00);
    }
    der_tag(0x02, &v)
}

fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = vec![0x00];
    content.extend_from_slice(bytes);
    der_tag(0x03, &content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_handle_hex() {
        assert_eq!(parse_handle("0x81000001").unwrap(), 0x8100_0001);
        assert_eq!(parse_handle("81000001").unwrap(), 0x8100_0001);
    }

    #[test]
    fn read_public_command_golden() {
        let cmd = command(TPM_ST_NO_SESSIONS, TPM_CC_READ_PUBLIC, &u32(0x8101_0001));
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x73]);
    }
}

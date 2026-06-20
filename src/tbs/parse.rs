//! TPM 2.0 response parsing helpers (big-endian wire format).

use crate::tbs::error::{TpmOpError, TpmResult};

const TPM_ST_SESSIONS: u16 = 0x8002;

pub struct ResponseParser<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ResponseParser<'a> {
    pub fn after_rc(resp: &'a [u8]) -> TpmResult<Self> {
        if resp.len() < 10 {
            return Err(TpmOpError::other("TPM response too short"));
        }
        Ok(Self { data: resp, offset: 10 })
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    pub fn read_u8(&mut self) -> TpmResult<u8> {
        if self.offset >= self.data.len() {
            return Err(TpmOpError::other("unexpected end of TPM response"));
        }
        let v = self.data[self.offset];
        self.offset += 1;
        Ok(v)
    }

    pub fn read_u16(&mut self) -> TpmResult<u16> {
        if self.offset + 2 > self.data.len() {
            return Err(TpmOpError::other("unexpected end of TPM response"));
        }
        let v = u16::from_be_bytes([
            self.data[self.offset],
            self.data[self.offset + 1],
        ]);
        self.offset += 2;
        Ok(v)
    }

    pub fn read_u32(&mut self) -> TpmResult<u32> {
        if self.offset + 4 > self.data.len() {
            return Err(TpmOpError::other("unexpected end of TPM response"));
        }
        let v = u32::from_be_bytes([
            self.data[self.offset],
            self.data[self.offset + 1],
            self.data[self.offset + 2],
            self.data[self.offset + 3],
        ]);
        self.offset += 4;
        Ok(v)
    }

    pub fn read_bytes(&mut self, len: usize) -> TpmResult<&'a [u8]> {
        if self.offset + len > self.data.len() {
            return Err(TpmOpError::other("unexpected end of TPM response"));
        }
        let slice = &self.data[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }

    pub fn read_tpm2b(&mut self) -> TpmResult<Vec<u8>> {
        let size = self.read_u16()? as usize;
        Ok(self.read_bytes(size)?.to_vec())
    }

    pub fn skip_tpm2b(&mut self) -> TpmResult<()> {
        let _ = self.read_tpm2b()?;
        Ok(())
    }
}

const MIN_SESSION_AUTH_BYTES: usize = 9;

fn looks_like_session_auth_area(resp: &[u8], offset: usize, size: usize) -> bool {
    if size < MIN_SESSION_AUTH_BYTES || offset + 4 > resp.len() {
        return false;
    }
    let handle = u32::from_be_bytes([
        resp[offset],
        resp[offset + 1],
        resp[offset + 2],
        resp[offset + 3],
    ]);
    matches!((handle >> 24) & 0xFF, 0x02 | 0x03)
}

/// `nonceTPM` from a successful `StartAuthSession` response (handle + param size + TPM2B).
pub fn start_auth_session_nonce_tpm(resp: &[u8]) -> TpmResult<Vec<u8>> {
    if resp.len() < 18 {
        return Err(TpmOpError::other("StartAuthSession response too short"));
    }
    let mut parser = ResponseParser::after_rc(resp)?;
    let _ = parser.read_u32()?; // session handle
    let _ = parser.read_u32()?; // parameter area size
    parser.read_tpm2b()
}

/// Parameter area for responses with **no** response handles.
///
/// Windows TBS often uses `TPM_ST_SESSIONS` without marshaling a response auth area
/// (Quote). When an auth area is present (ActivateCredential), it precedes the parameter
/// size and starts with a session handle (`0x02…` / `0x03…`).
pub fn parameters_after_rc(resp: &[u8]) -> TpmResult<ResponseParser<'_>> {
    if resp.len() < 14 {
        return Err(TpmOpError::other("TPM response too short"));
    }
    let tag = u16::from_be_bytes([resp[0], resp[1]]);
    let mut parser = ResponseParser::after_rc(resp)?;
    if tag == TPM_ST_SESSIONS {
        let first = parser.read_u32()? as usize;
        if first >= MIN_SESSION_AUTH_BYTES
            && first <= parser.remaining()
            && looks_like_session_auth_area(resp, parser.offset, first)
        {
            let _ = parser.read_bytes(first)?;
            let _ = parser.read_u32()?;
        } else {
            parser.offset = 14;
        }
    } else {
        let _ = parser.read_u32()?;
    }
    Ok(parser)
}

pub fn pcr_indices_from_bitmap(pcr_select: &[u8]) -> Vec<u32> {
    let mut indices = Vec::new();
    for (byte_idx, &byte) in pcr_select.iter().enumerate() {
        for bit in 0..8u32 {
            if byte & (1 << bit) != 0 {
                indices.push((byte_idx as u32) * 8 + bit);
            }
        }
    }
    indices
}

pub fn read_pml_pcr_selection(parser: &mut ResponseParser) -> TpmResult<Vec<(u16, Vec<u32>)>> {
    let count = parser.read_u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let hash = parser.read_u16()?;
        let size_of_select = parser.read_u8()? as usize;
        let pcr_select = parser.read_bytes(size_of_select)?.to_vec();
        let indices = pcr_indices_from_bitmap(&pcr_select);
        out.push((hash, indices));
    }
    Ok(out)
}

pub fn read_pml_digest(parser: &mut ResponseParser) -> TpmResult<Vec<Vec<u8>>> {
    let count = parser.read_u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(parser.read_tpm2b()?);
    }
    Ok(out)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn attest_extra_data(message: &[u8]) -> Option<&[u8]> {
    if message.len() < 6 {
        return None;
    }
    let mut off = skip_tpm2b_wire(message, 6)?;
    if off + 2 > message.len() {
        return None;
    }
    let size = u16::from_be_bytes([message[off], message[off + 1]]) as usize;
    off += 2;
    message.get(off..off + size)
}

fn skip_tpm2b_wire(data: &[u8], off: usize) -> Option<usize> {
    if off + 2 > data.len() {
        return None;
    }
    let size = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
    if off + 2 + size > data.len() {
        return None;
    }
    Some(off + 2 + size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcr_bitmap_indices() {
        assert_eq!(pcr_indices_from_bitmap(&[0x83, 0x00, 0x00]), vec![0, 1, 7]);
    }

    #[test]
    fn parameters_after_rc_sessions_tag_no_auth_area() {
        // Quote-style: TPM_ST_SESSIONS but param size immediately at offset 10.
        let body: u32 = 6;
        let total: u32 = 10 + 4 + 2 + 2;
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x80, 0x02]);
        resp.extend_from_slice(&total.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        resp.extend_from_slice(&body.to_be_bytes()); // param size
        resp.extend_from_slice(&[0x00, 0x02, b'h', b'i']);
        let mut p = parameters_after_rc(&resp).expect("params");
        assert_eq!(p.read_tpm2b().expect("tpm2b"), b"hi");
    }

    #[test]
    fn start_auth_session_nonce_no_sessions_tag() {
        let body_len = 4 + 4 + 2 + 32; // handle + param size + TPM2B nonce
        let total = 10 + body_len;
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x80, 0x01]); // TPM_ST_NO_SESSIONS
        resp.extend_from_slice(&(total as u32).to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes()); // rc
        resp.extend_from_slice(&0x0300_0014u32.to_be_bytes()); // handle
        resp.extend_from_slice(&(body_len as u32).to_be_bytes()); // param size
        resp.extend_from_slice(&[0x00, 0x20]); // TPM2B size
        resp.extend_from_slice(&[0xAAu8; 32]); // nonce
        let nonce = start_auth_session_nonce_tpm(&resp).expect("nonce");
        assert_eq!(nonce, vec![0xAA; 32]);
    }
}

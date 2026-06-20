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

fn parse_nonce_from_session_auth_bytes(auth: &[u8], session_handle: u32) -> TpmResult<Vec<u8>> {
    let mut offset = 0usize;
    while offset + 9 <= auth.len() {
        let handle = u32::from_be_bytes([
            auth[offset],
            auth[offset + 1],
            auth[offset + 2],
            auth[offset + 3],
        ]);
        offset += 4;
        if offset + 2 > auth.len() {
            break;
        }
        let nonce_len = u16::from_be_bytes([auth[offset], auth[offset + 1]]) as usize;
        offset += 2;
        if offset + nonce_len + 1 + 2 > auth.len() {
            break;
        }
        let nonce = auth[offset..offset + nonce_len].to_vec();
        offset += nonce_len;
        let _attrs = auth[offset];
        offset += 1;
        if offset + 2 > auth.len() {
            break;
        }
        let hmac_len = u16::from_be_bytes([auth[offset], auth[offset + 1]]) as usize;
        offset += 2 + hmac_len;
        if crate::tbs::session_hmac::session_handles_match(handle, session_handle) && !nonce.is_empty()
        {
            return Ok(nonce);
        }
    }
    Err(TpmOpError::other("session nonce not found in response auth area"))
}

fn read_session_nonce_from_auth_parser(
    parser: &mut ResponseParser<'_>,
    session_handle: u32,
) -> TpmResult<Vec<u8>> {
    let auth_size = parser.read_u32()? as usize;
    if auth_size == 0 {
        return Err(TpmOpError::other("empty session auth area"));
    }
    let auth = parser.read_bytes(auth_size)?;
    parse_nonce_from_session_auth_bytes(auth, session_handle)
}

/// Updated `nonceTPM` from a `TPM_ST_SESSIONS` response auth area (for the next command HMAC).
pub fn session_nonce_from_response(resp: &[u8], session_handle: u32) -> TpmResult<Vec<u8>> {
    if resp.len() < 14 {
        return Err(TpmOpError::other("TPM response too short"));
    }
    if u16::from_be_bytes([resp[0], resp[1]]) != TPM_ST_SESSIONS {
        return Err(TpmOpError::other("response has no session area"));
    }
    let mut parser = ResponseParser::after_rc(resp)?;
    read_session_nonce_from_auth_parser(&mut parser, session_handle)
}

/// `nonceTPM` from a successful `StartAuthSession` response.
pub fn start_auth_session_nonce_tpm(resp: &[u8]) -> TpmResult<Vec<u8>> {
    if resp.len() < 16 {
        return Err(TpmOpError::other("StartAuthSession response too short"));
    }
    let handle = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]);
    let tag = u16::from_be_bytes([resp[0], resp[1]]);

    // Layout C: handle + session auth area (Windows TBS often uses TPM_ST_SESSIONS here).
    if tag == TPM_ST_SESSIONS {
        if let Ok(n) = start_auth_session_nonce_after_handle(resp, handle) {
            return Ok(n);
        }
    }

    // Layout A/B: nonce in parameter area (with or without param-size prefix).
    let skip = start_auth_session_skip_param_size(resp);
    parse_start_auth_session_nonce(resp, skip)
        .or_else(|_| parse_start_auth_session_nonce(resp, !skip))
}

fn start_auth_session_nonce_after_handle(resp: &[u8], handle: u32) -> TpmResult<Vec<u8>> {
    let mut parser = ResponseParser::after_rc(resp)?;
    let _ = parser.read_u32()?; // response session handle
    read_session_nonce_from_auth_parser(&mut parser, handle)
}

fn start_auth_session_skip_param_size(resp: &[u8]) -> bool {
    if resp.len() < 16 {
        return true;
    }
    let u16_at_14 = u16::from_be_bytes([resp[14], resp[15]]);
    // nonceTPM is 16–32 bytes; at offset 14 a TPM2B size is 0x0010–0x0020.
    !(u16_at_14 >= 16 && u16_at_14 <= 32 && 16 + u16_at_14 as usize <= resp.len())
}

fn parse_start_auth_session_nonce(resp: &[u8], skip_param_size: bool) -> TpmResult<Vec<u8>> {
    let mut parser = ResponseParser::after_rc(resp)?;
    let _ = parser.read_u32()?; // session handle
    if skip_param_size {
        let _ = parser.read_u32()?;
    }
    let nonce = parser.read_tpm2b()?;
    if nonce.is_empty() {
        return Err(TpmOpError::other("StartAuthSession: empty nonceTPM"));
    }
    Ok(nonce)
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
    fn session_nonce_from_auth_area() {
        let session_handle = 0x0300_0014u32;
        let nonce = [0xCCu8; 32];
        let mut auth = Vec::new();
        auth.extend_from_slice(&session_handle.to_be_bytes());
        auth.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        auth.extend_from_slice(&nonce);
        auth.push(0x01); // continueSession
        auth.extend_from_slice(&[0x00, 0x20]); // hmac size
        auth.extend_from_slice(&[0u8; 32]);
        let auth_size = auth.len() as u32;
        let total: u32 = (10 + 4 + auth.len()) as u32;
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x80, 0x02]); // TPM_ST_SESSIONS
        resp.extend_from_slice(&total.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        resp.extend_from_slice(&auth_size.to_be_bytes());
        resp.extend_from_slice(&auth);
        let got = session_nonce_from_response(&resp, session_handle).expect("nonce");
        assert_eq!(got, nonce);
    }

    #[test]
    fn start_auth_session_nonce_direct_tpm2b() {
        let total: u32 = 10 + 4 + 2 + 32;
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x80, 0x01]);
        resp.extend_from_slice(&total.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        resp.extend_from_slice(&0x0300_0014u32.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x20]);
        resp.extend_from_slice(&[0xBBu8; 32]);
        let nonce = start_auth_session_nonce_tpm(&resp).expect("nonce");
        assert_eq!(nonce, vec![0xBB; 32]);
    }

    #[test]
    fn start_auth_session_nonce_with_param_size() {
        let body: u32 = 2 + 32;
        let total: u32 = 10 + 4 + 4 + body;
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x80, 0x01]);
        resp.extend_from_slice(&total.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes());
        resp.extend_from_slice(&0x0300_0014u32.to_be_bytes());
        resp.extend_from_slice(&body.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x20]);
        resp.extend_from_slice(&[0xAAu8; 32]);
        let nonce = start_auth_session_nonce_tpm(&resp).expect("nonce");
        assert_eq!(nonce, vec![0xAA; 32]);
    }
}

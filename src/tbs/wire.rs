//! TPM 2.0 wire-format marshalling (big-endian).

pub fn u16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

pub fn u32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// TPM2B_* : UINT16 size + buffer (size bytes only, no padding).
pub fn tpm2b(data: &[u8]) -> Vec<u8> {
    let len = u16::try_from(data.len()).expect("TPM2B size fits u16");
    let mut out = Vec::with_capacity(2 + data.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    out
}

pub fn tpm2b_empty() -> Vec<u8> {
    vec![0x00, 0x00]
}

/// TPM2 command header + body.
pub fn command(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
    let size = u32::try_from(10 + body.len()).expect("command fits u32");
    let mut cmd = Vec::with_capacity(size as usize);
    cmd.extend_from_slice(&tag.to_be_bytes());
    cmd.extend_from_slice(&size.to_be_bytes());
    cmd.extend_from_slice(&code.to_be_bytes());
    cmd.extend_from_slice(body);
    debug_assert_eq!(cmd.len(), size as usize);
    cmd
}

/// Default symmetric wrapper for restricted storage keys: AES-128-CFB.
pub fn sym_def_aes128_cfb() -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&u16(0x0006)); // TPM_ALG_AES
    s.extend_from_slice(&u16(128)); // AES-128
    s.extend_from_slice(&u16(0x0043)); // TPM_ALG_CFB
    s
}

/// TPMT_ASYM_SCHEME / TPMT_RSA_SCHEME / TPMT_ECC_SCHEME with NULL algorithm.
pub fn asym_scheme_null() -> Vec<u8> {
    u16(0x0010).to_vec() // TPM_ALG_NULL
}

/// TPMT_KDF_SCHEME with NULL algorithm.
pub fn kdf_scheme_null() -> Vec<u8> {
    u16(0x0010).to_vec()
}

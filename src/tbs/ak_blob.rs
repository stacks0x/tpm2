//! Cross-platform AK blob encoding.
//!
//! Linux: `public` = TPM2B_PUBLIC wire, `private` = TPM2B_PRIVATE wire.
//! Windows PCP: `public` = magic-prefixed PCP metadata, `private` = empty.
//!   - `PCP1` — user-scoped persisted key (default dev/probe)
//!   - `PCP2` — machine-scoped persisted key (fleet enrollment)

use crate::tbs::error::{TpmOpError, TpmResult};
use crate::tbs::keys::AkBlob;

const PCP_BLOB_MAGIC_USER: &[u8; 4] = b"PCP1";
const PCP_BLOB_MAGIC_MACHINE: &[u8; 4] = b"PCP2";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PcpKeyScope {
    #[default]
    User,
    Machine,
}

#[derive(Debug, Clone)]
pub struct PcpAkMetadata {
    pub key_name: String,
    pub scope: PcpKeyScope,
    pub raw_public: Vec<u8>,
    pub raw_creation_data: Vec<u8>,
    pub raw_attest: Vec<u8>,
    pub raw_signature: Vec<u8>,
}

pub fn is_pcp_blob(blob: &AkBlob) -> bool {
    blob.public.starts_with(PCP_BLOB_MAGIC_USER) || blob.public.starts_with(PCP_BLOB_MAGIC_MACHINE)
}

pub fn pcp_key_scope(blob: &AkBlob) -> Option<PcpKeyScope> {
    if blob.public.starts_with(PCP_BLOB_MAGIC_MACHINE) {
        Some(PcpKeyScope::Machine)
    } else if blob.public.starts_with(PCP_BLOB_MAGIC_USER) {
        Some(PcpKeyScope::User)
    } else {
        None
    }
}

pub fn encode_pcp_blob(meta: &PcpAkMetadata) -> AkBlob {
    let magic = match meta.scope {
        PcpKeyScope::User => PCP_BLOB_MAGIC_USER,
        PcpKeyScope::Machine => PCP_BLOB_MAGIC_MACHINE,
    };
    let mut public = Vec::new();
    public.extend_from_slice(magic);
    write_len_prefixed_str(&mut public, &meta.key_name);
    write_len_prefixed_bytes(&mut public, &meta.raw_public);
    write_len_prefixed_bytes(&mut public, &meta.raw_creation_data);
    write_len_prefixed_bytes(&mut public, &meta.raw_attest);
    write_len_prefixed_bytes(&mut public, &meta.raw_signature);
    AkBlob {
        public,
        private: Vec::new(),
    }
}

pub fn decode_pcp_blob(blob: &AkBlob) -> TpmResult<PcpAkMetadata> {
    let (magic_len, scope) = if blob.public.starts_with(PCP_BLOB_MAGIC_MACHINE) {
        (PCP_BLOB_MAGIC_MACHINE.len(), PcpKeyScope::Machine)
    } else if blob.public.starts_with(PCP_BLOB_MAGIC_USER) {
        (PCP_BLOB_MAGIC_USER.len(), PcpKeyScope::User)
    } else {
        return Err(TpmOpError::other("AK blob is not a Windows PCP blob"));
    };
    let mut cursor = &blob.public[magic_len..];
    Ok(PcpAkMetadata {
        key_name: read_len_prefixed_str(&mut cursor)?,
        scope,
        raw_public: read_len_prefixed_bytes(&mut cursor)?,
        raw_creation_data: read_len_prefixed_bytes(&mut cursor)?,
        raw_attest: read_len_prefixed_bytes(&mut cursor)?,
        raw_signature: read_len_prefixed_bytes(&mut cursor)?,
    })
}

pub fn public_wire_from_pcp_meta(meta: &PcpAkMetadata) -> Vec<u8> {
    let mut wire = Vec::with_capacity(2 + meta.raw_public.len());
    wire.extend_from_slice(&(meta.raw_public.len() as u16).to_be_bytes());
    wire.extend_from_slice(&meta.raw_public);
    wire
}

fn write_len_prefixed_str(out: &mut Vec<u8>, s: &str) {
    write_len_prefixed_bytes(out, s.as_bytes());
}

fn write_len_prefixed_bytes(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

fn read_len_prefixed_str(cursor: &mut &[u8]) -> TpmResult<String> {
    let bytes = read_len_prefixed_bytes(cursor)?;
    String::from_utf8(bytes).map_err(|e| TpmOpError::other(format!("invalid PCP key name UTF-8: {e}")))
}

fn read_len_prefixed_bytes(cursor: &mut &[u8]) -> TpmResult<Vec<u8>> {
    if cursor.len() < 4 {
        return Err(TpmOpError::other("truncated PCP AK blob"));
    }
    let len = u32::from_le_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
    *cursor = &cursor[4..];
    if cursor.len() < len {
        return Err(TpmOpError::other("truncated PCP AK blob field"));
    }
    let out = cursor[..len].to_vec();
    *cursor = &cursor[len..];
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcp_blob_roundtrip_user() {
        let meta = PcpAkMetadata {
            key_name: "node-tpm2-ak-deadbeef".to_string(),
            scope: PcpKeyScope::User,
            raw_public: vec![1, 2, 3, 4],
            raw_creation_data: vec![5, 6],
            raw_attest: vec![7],
            raw_signature: vec![8, 9],
        };
        let blob = encode_pcp_blob(&meta);
        assert!(is_pcp_blob(&blob));
        assert_eq!(pcp_key_scope(&blob), Some(PcpKeyScope::User));
        assert!(blob.private.is_empty());
        let decoded = decode_pcp_blob(&blob).expect("decode");
        assert_eq!(decoded.key_name, meta.key_name);
        assert_eq!(decoded.scope, PcpKeyScope::User);
        assert_eq!(decoded.raw_public, meta.raw_public);
    }

    #[test]
    fn pcp_blob_roundtrip_machine() {
        let meta = PcpAkMetadata {
            key_name: "hardproof-device-ak".to_string(),
            scope: PcpKeyScope::Machine,
            raw_public: vec![1],
            raw_creation_data: vec![2],
            raw_attest: vec![3],
            raw_signature: vec![4],
        };
        let blob = encode_pcp_blob(&meta);
        assert_eq!(pcp_key_scope(&blob), Some(PcpKeyScope::Machine));
        assert!(blob.public.starts_with(b"PCP2"));
        let decoded = decode_pcp_blob(&blob).expect("decode");
        assert_eq!(decoded.scope, PcpKeyScope::Machine);
    }
}

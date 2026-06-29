//! General device-bound keys: Create, Load, Sign (TBS wrapped blobs, both OSes).

use crate::tbs::error::{check_tpm_rc, TpmOpError, TpmResult};
use crate::tbs::keys::{
    create_storage_primary, load_ak, read_tpm2b_wire, AkBlob,
};
use crate::tbs::parse::{parameters_after_rc, ResponseParser};
use crate::tbs::read_public::public_wire_to_spki_der;
use crate::tbs::wire::{
    asym_scheme_null, command_with_password_session, kdf_scheme_null, scheme_ecdsa_sha256,
    scheme_rsa_oaep_sha256, scheme_rsassa_sha256, tpm2b, tpm2b_empty, u16, u32,
};
use crate::tbs::submit_tpm_command;

const TPM_CC_CREATE: u32 = 0x0000_0153;
const TPM_CC_SIGN: u32 = 0x0000_015D;
const TPM_CC_RSA_DECRYPT: u32 = 0x0000_015E;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ECC_NIST_P256: u16 = 0x0003;
const TPM_ST_HASHCHECK: u16 = 0x8024;
const TPM_RH_NULL: u32 = 0x4000_0007;

/// fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign
const SIGNING_KEY_ATTRIBUTES: u32 = 0x0004_0072;
/// signing attributes + decrypt (RSA only)
const SIGNING_DECRYPT_KEY_ATTRIBUTES: u32 = 0x0006_0072;
const TPMA_OBJECT_DECRYPT: u32 = 0x0002_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ecc,
    Rsa,
}

#[derive(Debug, Clone)]
pub struct KeyCreateOptions {
    pub key_type: KeyType,
    pub sign: bool,
    pub decrypt: bool,
}

impl Default for KeyCreateOptions {
    fn default() -> Self {
        Self {
            key_type: KeyType::Ecc,
            sign: true,
            decrypt: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyCreateResult {
    pub public_key_der: Vec<u8>,
    pub key_blob: AkBlob,
}

pub fn parse_key_create_options(
    key_type: Option<&str>,
    sign: Option<bool>,
    decrypt: Option<bool>,
) -> TpmResult<KeyCreateOptions> {
    let key_type = match key_type.unwrap_or("ecc") {
        "ecc" => KeyType::Ecc,
        "rsa" => KeyType::Rsa,
        other => {
            return Err(TpmOpError::invalid_argument(format!(
                "unsupported key type {other:?}; use 'ecc' or 'rsa'"
            )));
        }
    };
    let sign = sign.unwrap_or(true);
    let decrypt = decrypt.unwrap_or(false);
    if !sign && !decrypt {
        return Err(TpmOpError::invalid_argument(
            "keys.create requires sign and/or decrypt",
        ));
    }
    if decrypt && key_type == KeyType::Ecc {
        return Err(TpmOpError::invalid_argument(
            "decrypt is only supported for RSA keys",
        ));
    }
    Ok(KeyCreateOptions {
        key_type,
        sign,
        decrypt,
    })
}

fn object_attributes(opts: &KeyCreateOptions) -> u32 {
    if opts.decrypt {
        SIGNING_DECRYPT_KEY_ATTRIBUTES
    } else {
        SIGNING_KEY_ATTRIBUTES
    }
}

fn sensitive_create_null_auth() -> Vec<u8> {
    tpm2b(&[0x00, 0x00, 0x00, 0x00])
}

fn public_key_template(opts: &KeyCreateOptions) -> TpmResult<Vec<u8>> {
    let attrs = object_attributes(opts);
    let mut t = Vec::new();
    match opts.key_type {
        KeyType::Ecc => {
            t.extend_from_slice(&u16(TPM_ALG_ECC));
            t.extend_from_slice(&u16(TPM_ALG_SHA256));
            t.extend_from_slice(&u32(attrs));
            t.extend(tpm2b_empty());
            t.extend(asym_scheme_null());
            t.extend(scheme_ecdsa_sha256());
            t.extend_from_slice(&u16(TPM_ECC_NIST_P256));
            t.extend(kdf_scheme_null());
            t.extend(tpm2b_empty());
            t.extend(tpm2b_empty());
        }
        KeyType::Rsa => {
            t.extend_from_slice(&u16(TPM_ALG_RSA));
            t.extend_from_slice(&u16(TPM_ALG_SHA256));
            t.extend_from_slice(&u32(attrs));
            t.extend(tpm2b_empty());
            t.extend(asym_scheme_null());
            t.extend(scheme_rsassa_sha256());
            t.extend_from_slice(&u16(2048));
            t.extend_from_slice(&u32(0)); // exponent 0 => 65537
            t.extend(tpm2b_empty());
        }
    }
    Ok(tpm2b(&t))
}

fn create_key_under_parent(parent: u32, opts: &KeyCreateOptions) -> TpmResult<AkBlob> {
    let mut params = Vec::new();
    params.extend(sensitive_create_null_auth());
    params.extend(public_key_template(opts)?);
    params.extend(tpm2b_empty());
    params.extend_from_slice(&u32(0));

    let cmd = command_with_password_session(parent, TPM_CC_CREATE, &params);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "Create")?;

    let mut parser = ResponseParser::after_rc(&resp)?;
    let _param_size = parser.read_u32()?;
    let private = read_tpm2b_wire(&mut parser)?;
    let public = read_tpm2b_wire(&mut parser)?;
    Ok(AkBlob { public, private })
}

fn external_digest_validation_ticket() -> Vec<u8> {
    // Unrestricted signing keys: TPM_ST_HASHCHECK + TPM_RH_NULL + empty digest
    // (Part 3 Sign; same as tpm2_sign -d without -t).
    let mut t = Vec::new();
    t.extend_from_slice(&u16(TPM_ST_HASHCHECK));
    t.extend_from_slice(&u32(TPM_RH_NULL));
    t.extend(tpm2b_empty());
    t
}

pub fn sign_digest(sign_handle: u32, digest: &[u8]) -> TpmResult<Vec<u8>> {
    if digest.len() != 32 {
        return Err(TpmOpError::invalid_argument(
            "digest must be 32 bytes (SHA-256)",
        ));
    }
    let mut params = Vec::new();
    params.extend(tpm2b(digest));
    params.extend(asym_scheme_null()); // inScheme: use key default
    params.extend(external_digest_validation_ticket());

    let cmd = command_with_password_session(sign_handle, TPM_CC_SIGN, &params);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "Sign")?;

    let mut parser = parameters_after_rc(&resp)?;
    parser.read_tpm2b()
}

fn ensure_tbs_key_blob(blob: &AkBlob) -> TpmResult<()> {
    if crate::tbs::ak_blob::is_pcp_blob(blob) {
        return Err(TpmOpError::not_supported(
            "PCP attestation blobs cannot be used with tpm.keys; use tpm.attest instead",
            None,
        ));
    }
    Ok(())
}

pub fn key_blob_spki(blob: &AkBlob) -> TpmResult<Vec<u8>> {
    ensure_tbs_key_blob(blob)?;
    public_wire_to_spki_der(&blob.public)
}

pub fn create_key(opts: &KeyCreateOptions) -> TpmResult<KeyCreateResult> {
    let primary = create_storage_primary()?;
    let blob = create_key_under_parent(primary.handle, opts)?;
    let public_key_der = public_wire_to_spki_der(&blob.public)?;
    primary.flush()?;
    Ok(KeyCreateResult {
        public_key_der,
        key_blob: blob,
    })
}

fn with_loaded_key<F>(blob: &AkBlob, f: F) -> TpmResult<Vec<u8>>
where
    F: FnOnce(u32) -> TpmResult<Vec<u8>>,
{
    ensure_tbs_key_blob(blob)?;
    let primary = create_storage_primary()?;
    let key = load_ak(primary.handle, blob)?;
    let result = match f(key.handle) {
        Ok(v) => v,
        Err(e) => {
            let _ = key.flush();
            let _ = primary.flush();
            return Err(e);
        }
    };
    key.flush()?;
    primary.flush()?;
    Ok(result)
}

pub fn sign_with_key_blob(blob: &AkBlob, digest: &[u8]) -> TpmResult<Vec<u8>> {
    with_loaded_key(blob, |handle| sign_digest(handle, digest))
}

fn key_blob_has_decrypt(blob: &AkBlob) -> TpmResult<bool> {
    ensure_tbs_key_blob(blob)?;
    let wire = &blob.public;
    if wire.len() < 2 + 8 {
        return Err(TpmOpError::other("invalid key blob public area"));
    }
    let size = u16::from_be_bytes([wire[0], wire[1]]) as usize;
    if wire.len() < 2 + size {
        return Err(TpmOpError::other("invalid key blob public area"));
    }
    // TPMT_PUBLIC: type(2) + nameAlg(2) + objectAttributes(4)
    let attrs = u32::from_be_bytes([wire[6], wire[7], wire[8], wire[9]]);
    Ok(attrs & TPMA_OBJECT_DECRYPT != 0)
}

pub fn rsa_decrypt(decrypt_handle: u32, cipher: &[u8]) -> TpmResult<Vec<u8>> {
    if cipher.is_empty() {
        return Err(TpmOpError::invalid_argument("cipher must not be empty"));
    }
    let mut params = Vec::new();
    params.extend(scheme_rsa_oaep_sha256());
    params.extend(tpm2b(cipher));
    params.extend(tpm2b_empty()); // label

    let cmd = command_with_password_session(decrypt_handle, TPM_CC_RSA_DECRYPT, &params);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "RSA_Decrypt")?;

    let mut parser = parameters_after_rc(&resp)?;
    parser.read_tpm2b()
}

pub fn decrypt_with_key_blob(blob: &AkBlob, cipher: &[u8]) -> TpmResult<Vec<u8>> {
    if !key_blob_has_decrypt(blob)? {
        return Err(TpmOpError::invalid_argument(
            "key was not created with decrypt: true",
        ));
    }
    with_loaded_key(blob, |handle| rsa_decrypt(handle, cipher))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tbs::wire::command_with_password_session;

    #[test]
    fn ecc_signing_public_template_starts_with_ecc_alg() {
        let opts = KeyCreateOptions::default();
        let t = public_key_template(&opts).expect("template");
        assert_eq!(&t[2..4], &TPM_ALG_ECC.to_be_bytes());
    }

    #[test]
    fn rsa_signing_public_template_starts_with_rsa_alg() {
        let opts = KeyCreateOptions {
            key_type: KeyType::Rsa,
            sign: true,
            decrypt: false,
        };
        let t = public_key_template(&opts).expect("template");
        assert_eq!(&t[2..4], &TPM_ALG_RSA.to_be_bytes());
    }

    #[test]
    fn sign_command_uses_sessions_tag() {
        let digest = [0u8; 32];
        let mut params = Vec::new();
        params.extend(tpm2b(&digest));
        params.extend(asym_scheme_null());
        params.extend(external_digest_validation_ticket());
        let cmd = command_with_password_session(0x80FF_FFFF, TPM_CC_SIGN, &params);
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        assert_eq!(&cmd[6..10], &TPM_CC_SIGN.to_be_bytes());
    }

    #[test]
    fn external_digest_validation_ticket_is_hashcheck_null_empty() {
        let ticket = external_digest_validation_ticket();
        assert_eq!(&ticket[0..2], &TPM_ST_HASHCHECK.to_be_bytes());
        assert_eq!(&ticket[2..6], &TPM_RH_NULL.to_be_bytes());
        assert_eq!(&ticket[6..8], &0u16.to_be_bytes()); // empty TPM2B_DIGEST
    }

    #[test]
    fn rsa_decrypt_command_golden_prefix() {
        let cipher = [0xABu8; 16];
        let mut params = Vec::new();
        params.extend(scheme_rsa_oaep_sha256());
        params.extend(tpm2b(&cipher));
        params.extend(tpm2b_empty());
        let cmd = command_with_password_session(0x80FF_FFFF, TPM_CC_RSA_DECRYPT, &params);
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        assert_eq!(&cmd[6..10], &TPM_CC_RSA_DECRYPT.to_be_bytes());
    }

    #[test]
    fn parse_options_rejects_ecc_decrypt() {
        let err = parse_key_create_options(Some("ecc"), Some(true), Some(true)).unwrap_err();
        assert_eq!(err.code(), crate::tbs::codes::INVALID_ARGUMENT);
    }

    #[test]
    fn decrypt_rejects_non_decrypt_key() {
        let opts = KeyCreateOptions::default();
        let template = public_key_template(&opts).expect("template");
        let blob = AkBlob {
            public: template,
            private: vec![0x00, 0x00],
        };
        let err = decrypt_with_key_blob(&blob, &[0u8; 16]).unwrap_err();
        assert_eq!(err.code(), crate::tbs::codes::INVALID_ARGUMENT);
    }

    #[test]
    fn parse_options_defaults_ecc_sign() {
        let opts = parse_key_create_options(None, None, None).unwrap();
        assert_eq!(opts.key_type, KeyType::Ecc);
        assert!(opts.sign);
        assert!(!opts.decrypt);
    }

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn create_and_sign_ecc_roundtrip() {
        if !crate::tbs::hw_test::mutating_enabled() {
            return;
        }
        let opts = KeyCreateOptions::default();
        let created = create_key(&opts).expect("create_key");
        let digest = sha256(b"node-tpm2-keys-sign-test");
        let sig = sign_with_key_blob(&created.key_blob, &digest).expect("sign");
        assert!(!sig.is_empty());
        let spki = key_blob_spki(&created.key_blob).expect("spki");
        assert_eq!(spki, created.public_key_der);
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }
}

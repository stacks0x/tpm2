//! Hand-marshalled TPM 2.0 command buffers for direct-TBS probes.

use crate::tbs::wire::{asym_scheme_null, command, kdf_scheme_null, sym_def_aes128_cfb, tpm2b, tpm2b_empty, u16, u32};

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM_CC_GET_RANDOM: u32 = 0x0000_017B;
const TPM_RH_OWNER: u32 = 0x4000_0001;

const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ECC_NIST_P256: u16 = 0x0003;

// fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | restricted | decrypt
// tpm2-tools raw for storage primary: 0x30072
const STORAGE_PRIMARY_ATTRIBUTES: u32 = 0x0003_0072;

/// TPM2_GetRandom(8)
pub fn get_random_8() -> [u8; 12] {
    let body = [0x00, 0x08u8]; // bytesRequested
    let cmd = command(TPM_ST_NO_SESSIONS, TPM_CC_GET_RANDOM, &body);
    cmd.try_into().expect("GetRandom is 12 bytes")
}

/// Null-auth TPMS_SENSITIVE_CREATE inside TPM2B_SENSITIVE_CREATE.
fn sensitive_create_null_auth() -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend(tpm2b_empty()); // userAuth (empty = null auth)
    inner.extend(tpm2b_empty()); // data (empty)
    tpm2b(&inner)
}

/// TPMT_PUBLIC for RSA-2048 restricted storage primary (matches `src/tpm/esapi.rs`).
fn public_rsa2048_storage_primary() -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&u16(TPM_ALG_RSA));
    t.extend_from_slice(&u16(TPM_ALG_SHA256));
    t.extend_from_slice(&u32(STORAGE_PRIMARY_ATTRIBUTES));
    t.extend(tpm2b_empty()); // authPolicy
    // TPMS_RSA_PARMS
    t.extend(sym_def_aes128_cfb());
    t.extend(asym_scheme_null()); // scheme
    t.extend_from_slice(&u16(2048)); // keyBits
    t.extend_from_slice(&u32(0)); // exponent 0 => 65537
    // TPM2B_PUBLIC_KEY_RSA unique (empty => TPM generates)
    t.extend(tpm2b_empty());
    tpm2b(&t)
}

/// TPMT_PUBLIC for ECC NIST P256 restricted storage primary.
fn public_ecc_p256_storage_primary() -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&u16(TPM_ALG_ECC));
    t.extend_from_slice(&u16(TPM_ALG_SHA256));
    t.extend_from_slice(&u32(STORAGE_PRIMARY_ATTRIBUTES));
    t.extend(tpm2b_empty()); // authPolicy
    // TPMS_ECC_PARMS
    t.extend(sym_def_aes128_cfb());
    t.extend(asym_scheme_null()); // scheme
    t.extend_from_slice(&u16(TPM_ECC_NIST_P256)); // curveID
    t.extend(kdf_scheme_null()); // kdf
    // TPMS_ECC_POINT unique (empty x, empty y => TPM generates)
    t.extend(tpm2b_empty()); // x
    t.extend(tpm2b_empty()); // y
    tpm2b(&t)
}

fn create_primary_body(public: Vec<u8>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&u32(TPM_RH_OWNER));
    body.extend(sensitive_create_null_auth());
    body.extend(public);
    body.extend(tpm2b_empty()); // outsideInfo
    body.extend_from_slice(&u32(0)); // creationPCR.count = 0
    body
}

/// TPM2_CreatePrimary — RSA-2048 storage primary (library template).
pub fn create_primary_owner_rsa_storage() -> Vec<u8> {
    let body = create_primary_body(public_rsa2048_storage_primary());
    command(TPM_ST_NO_SESSIONS, TPM_CC_CREATE_PRIMARY, &body)
}

/// TPM2_CreatePrimary — ECC P256 storage primary.
pub fn create_primary_owner_ecc_storage() -> Vec<u8> {
    let body = create_primary_body(public_ecc_p256_storage_primary());
    command(TPM_ST_NO_SESSIONS, TPM_CC_CREATE_PRIMARY, &body)
}

/// Default CreatePrimary probe: RSA storage (matches Option B library path).
pub fn create_primary_owner_storage() -> Vec<u8> {
    create_primary_owner_rsa_storage()
}

pub fn tpm_rc_from_response(resp: &[u8]) -> Option<u32> {
    if resp.len() < 10 {
        return None;
    }
    Some(u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_random_golden() {
        assert_eq!(
            get_random_8(),
            [
                0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B, 0x00, 0x08
            ]
        );
    }

    #[test]
    fn rsa_storage_primary_golden() {
        // Every byte verified against TPM 2.0 Part 2 structure layout.
        let cmd = create_primary_owner_rsa_storage();
        assert_eq!(cmd.len(), 54);
        assert_eq!(&cmd[0..2], &[0x80, 0x01]); // TPM_ST_NO_SESSIONS
        assert_eq!(&cmd[2..6], &[0x00, 0x00, 0x00, 0x36]); // commandSize
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x31]); // CreatePrimary
        assert_eq!(&cmd[10..14], &[0x40, 0x00, 0x00, 0x01]); // TPM_RH_OWNER
        // inSensitive TPM2B (size=4, null auth + empty data)
        assert_eq!(&cmd[14..20], &[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);
        // inPublic TPM2B size = 26 (0x001A)
        assert_eq!(&cmd[20..22], &[0x00, 0x1A]);
        // TPMT_PUBLIC: RSA / SHA256 / attributes / empty policy
        assert_eq!(&cmd[22..32], &[
            0x00, 0x01, 0x00, 0x0B, 0x00, 0x03, 0x00, 0x72, 0x00, 0x00
        ]);
        // TPMS_RSA_PARMS + unique
        assert_eq!(&cmd[32..48], &[
            0x00, 0x06, 0x00, 0x80, 0x00, 0x43, // AES-128-CFB
            0x00, 0x10, // scheme NULL
            0x08, 0x00, // 2048 bits
            0x00, 0x00, 0x00, 0x00, // exponent 0
            0x00, 0x00, // empty unique
        ]);
        assert_eq!(&cmd[48..54], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // outside + PCRs
    }

    #[test]
    fn ecc_storage_primary_size() {
        let cmd = create_primary_owner_ecc_storage();
        assert_eq!(cmd.len(), 54);
        assert_eq!(&cmd[22..24], &[0x00, 0x23]); // TPM_ALG_ECC
    }
}

//! Hand-marshalled TPM 2.0 command buffers for direct-TBS probes.

use crate::tbs::wire::{
    asym_scheme_null, command, command_with_password_session, kdf_scheme_null,
    sym_def_aes128_cfb, tpm2b, tpm2b_empty, u16, u32,
};

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM_CC_GET_RANDOM: u32 = 0x0000_017B;
const TPM_RH_OWNER: u32 = 0x4000_0001;

const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ECC_NIST_P256: u16 = 0x0003;

/// tpm2_createprimary storage template attributes (0x30072).
const STORAGE_PRIMARY_ATTRIBUTES: u32 = 0x0003_0072;

#[derive(Debug, Clone, Copy)]
pub enum PrimaryKind {
    Rsa2048,
    EccP256,
}

impl PrimaryKind {
    pub fn label(self) -> &'static str {
        match self {
            PrimaryKind::Rsa2048 => "RSA-2048 storage",
            PrimaryKind::EccP256 => "ECC P256 storage",
        }
    }
}

/// TPM2_GetRandom(8)
pub fn get_random_8() -> [u8; 12] {
    let body = [0x00, 0x08u8];
    let cmd = command(TPM_ST_NO_SESSIONS, TPM_CC_GET_RANDOM, &body);
    cmd.try_into().expect("GetRandom is 12 bytes")
}

/// Null userAuth + empty data inside TPM2B_SENSITIVE_CREATE (what tpm2-tss sends).
fn sensitive_create_null_auth() -> Vec<u8> {
    tpm2b(&[0x00, 0x00, 0x00, 0x00])
}

fn public_rsa2048_storage_primary() -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&u16(TPM_ALG_RSA));
    t.extend_from_slice(&u16(TPM_ALG_SHA256));
    t.extend_from_slice(&u32(STORAGE_PRIMARY_ATTRIBUTES));
    t.extend(tpm2b_empty());
    t.extend(sym_def_aes128_cfb());
    t.extend(asym_scheme_null());
    t.extend_from_slice(&u16(2048));
    t.extend_from_slice(&u32(0)); // exponent 0 => 65537
    t.extend(tpm2b_empty());
    tpm2b(&t)
}

fn public_ecc_p256_storage_primary() -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&u16(TPM_ALG_ECC));
    t.extend_from_slice(&u16(TPM_ALG_SHA256));
    t.extend_from_slice(&u32(STORAGE_PRIMARY_ATTRIBUTES));
    t.extend(tpm2b_empty());
    t.extend(sym_def_aes128_cfb());
    t.extend(asym_scheme_null());
    t.extend_from_slice(&u16(TPM_ECC_NIST_P256));
    t.extend(kdf_scheme_null());
    t.extend(tpm2b_empty());
    t.extend(tpm2b_empty());
    tpm2b(&t)
}

fn create_primary_params(public: Vec<u8>) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend(sensitive_create_null_auth());
    params.extend(public);
    params.extend(tpm2b_empty()); // outsideInfo
    params.extend_from_slice(&u32(0)); // creationPCR.count = 0
    params
}

/// Owner-hierarchy CreatePrimary with null auth via password session.
pub fn create_primary_owner(kind: PrimaryKind) -> Vec<u8> {
    let public = match kind {
        PrimaryKind::Rsa2048 => public_rsa2048_storage_primary(),
        PrimaryKind::EccP256 => public_ecc_p256_storage_primary(),
    };
    let params = create_primary_params(public);
    command_with_password_session(TPM_RH_OWNER, TPM_CC_CREATE_PRIMARY, &params)
}

/// ECC first (swtpm preference), then RSA fallback.
pub fn create_primary_candidates() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "ECC P256 storage primary",
            create_primary_owner(PrimaryKind::EccP256),
        ),
        (
            "RSA-2048 storage primary",
            create_primary_owner(PrimaryKind::Rsa2048),
        ),
    ]
}

pub fn tpm_rc_from_response(resp: &[u8]) -> Option<u32> {
    if resp.len() < 10 {
        return None;
    }
    Some(u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]))
}

pub fn tpm_rc_name(rc: u32) -> &'static str {
    match rc {
        0 => "success",
        0x0000_0100 => "TPM_RC_INITIALIZE",
        0x0000_0125 => "TPM_RC_ASYMMETRIC",
        0x0000_0143 => "TPM_RC_ATTRIBUTES",
        0x0000_017F => "TPM_RC_SIZE",
        0x0000_038E => "TPM_RC_AUTH_FAIL",
        _ => "unknown",
    }
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
    fn ecc_create_primary_golden() {
        let cmd = create_primary_owner(PrimaryKind::EccP256);
        assert_eq!(cmd.len(), 67);
        assert_eq!(&cmd[0..2], &[0x80, 0x02]); // TPM_ST_SESSIONS
        assert_eq!(&cmd[2..6], &[0x00, 0x00, 0x00, 0x43]); // 67 bytes
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x31]);
        assert_eq!(&cmd[10..14], &[0x40, 0x00, 0x00, 0x01]); // TPM_RH_OWNER
        assert_eq!(&cmd[14..18], &[0x00, 0x00, 0x00, 0x09]); // auth area size
        assert_eq!(&cmd[18..22], &[0x40, 0x00, 0x00, 0x09]); // TPM_RH_PW
        assert_eq!(&cmd[22..27], &[0x00, 0x00, 0x01, 0x00, 0x00]); // nonce + attr + empty auth
        assert_eq!(&cmd[27..33], &[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]); // inSensitive
        assert_eq!(&cmd[33..35], &[0x00, 0x1A]); // inPublic size
        assert_eq!(&cmd[35..37], &[0x00, 0x23]); // ECC
        assert_eq!(&cmd[39..43], &STORAGE_PRIMARY_ATTRIBUTES.to_be_bytes());
    }

    #[test]
    fn rsa_create_primary_size() {
        let cmd = create_primary_owner(PrimaryKind::Rsa2048);
        assert_eq!(cmd.len(), 67);
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        assert_eq!(&cmd[35..37], &[0x00, 0x01]); // RSA
    }
}

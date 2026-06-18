//! Hand-marshalled TPM 2.0 command buffers for direct-TBS probes.

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const TPM_RH_OWNER: u32 = 0x4000_0001;

const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_CFB: u16 = 0x0043;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ECC_NIST_P256: u16 = 0x0003;

// fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | restricted | decrypt
// Matches tpm2-tools raw 0x30072 for `-G ecc -a restricted|decrypt|...`
const STORAGE_PRIMARY_ATTRIBUTES: u32 = 0x0003_0072;

/// TPM2_GetRandom(8)
pub fn get_random_8() -> [u8; 12] {
    [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B, 0x00, 0x08,
    ]
}

/// TPM2_CreatePrimary — owner hierarchy, ECC NIST P256 storage template, null auth.
pub fn create_primary_owner_ecc_storage() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());

    // TPM2B_SENSITIVE_CREATE: null userAuth + empty data
    body.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);

    // TPM2B_PUBLIC — ECC storage primary template
    let mut public = Vec::new();
    public.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    public.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    public.extend_from_slice(&STORAGE_PRIMARY_ATTRIBUTES.to_be_bytes());
    public.extend_from_slice(&[0x00, 0x00]); // empty authPolicy

    // TPMS_ECC_PARMS
    public.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
    public.extend_from_slice(&128u16.to_be_bytes());
    public.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
    public.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // scheme
    public.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes());
    public.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // kdf

    // TPMS_ECC_POINT — empty x/y (TPM generates unique)
    public.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let public_len = u16::try_from(public.len()).expect("public area fits u16");
    body.extend_from_slice(&public_len.to_be_bytes());
    body.extend_from_slice(&public);

    // TPM2B_DATA outsideInfo — empty
    body.extend_from_slice(&[0x00, 0x00]);

    // TPML_PCR_SELECTION creationPCR — count 0
    body.extend_from_slice(&0u32.to_be_bytes());

    let param_size = u32::try_from(10 + body.len()).expect("command fits u32");
    let mut cmd = Vec::with_capacity(param_size as usize);
    cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    cmd.extend_from_slice(&param_size.to_be_bytes());
    cmd.extend_from_slice(&TPM_CC_CREATE_PRIMARY.to_be_bytes());
    cmd.extend_from_slice(&body);
    debug_assert_eq!(cmd.len(), param_size as usize);
    cmd
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
    fn create_primary_has_expected_command_code() {
        let cmd = create_primary_owner_ecc_storage();
        assert_eq!(&cmd[6..10], &TPM_CC_CREATE_PRIMARY.to_be_bytes());
        assert_eq!(&cmd[0..2], &TPM_ST_NO_SESSIONS.to_be_bytes());
    }

    #[test]
    fn create_primary_uses_storage_attributes() {
        let cmd = create_primary_owner_ecc_storage();
        // objectAttributes in TPMT_PUBLIC (after type + nameAlg)
        assert_eq!(&cmd[26..30], &STORAGE_PRIMARY_ATTRIBUTES.to_be_bytes());
    }

    #[test]
    fn create_primary_command_size() {
        let cmd = create_primary_owner_ecc_storage();
        let size = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]);
        assert_eq!(size as usize, cmd.len());
        assert_eq!(size, 54); // 0x36
    }
}

//! Software policy digest computation (TPM 2.0 Part 3 §23.2.3–23.11).

use sha2::{Digest, Sha256};

const TPM_CC_POLICY_SECRET: u32 = 0x0000_0151;
const TPM_CC_POLICY_COMMAND_CODE: u32 = 0x0000_016C;
const TPM_CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;

/// Policy digest for `PolicySecret(endorsement)` + `PolicyCommandCode(ActivateCredential)`.
///
/// Matches `tpm2 startauthsession && tpm2 policysecret -c endorsement && tpm2 policycommandcode 0x147`.
pub fn activate_credential_policy_digest() -> [u8; 32] {
    let zero = [0u8; 32];
    let after_secret = policy_update_secret(&zero, TPM_RH_ENDORSEMENT, &[]);
    policy_update_command_code(&after_secret, TPM_CC_ACTIVATE_CREDENTIAL)
}

/// Part 3 §23.2.3 PolicyUpdate for PolicySecret.
fn policy_update_secret(old: &[u8; 32], auth_handle: u32, policy_ref: &[u8]) -> [u8; 32] {
    let name = auth_handle.to_be_bytes();
    let mut step1 = Sha256::new();
    step1.update(old);
    step1.update(TPM_CC_POLICY_SECRET.to_be_bytes());
    step1.update(name);
    let mid: [u8; 32] = step1.finalize().into();

    let mut step2 = Sha256::new();
    step2.update(mid);
    step2.update(policy_ref);
    step2.finalize().into()
}

/// Part 3 §23.11 PolicyCommandCode digest extension.
fn policy_update_command_code(old: &[u8; 32], allowed_code: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(old);
    hasher.update(TPM_CC_POLICY_COMMAND_CODE.to_be_bytes());
    hasher.update(allowed_code.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activate_credential_policy_matches_tpm2_tools() {
        let digest = activate_credential_policy_digest();
        let expected: [u8; 32] = [
            0xcd, 0x99, 0x17, 0xcf, 0x18, 0xc3, 0x84, 0x8c, 0x3a, 0x2e, 0x60, 0x69, 0x86, 0xa0,
            0x66, 0xc6, 0x81, 0x42, 0xf9, 0xbc, 0x27, 0x10, 0xa2, 0x78, 0x28, 0x7a, 0x65, 0x0c,
            0xa3, 0xbb, 0xf2, 0x45,
        ];
        assert_eq!(digest, expected);
    }
}

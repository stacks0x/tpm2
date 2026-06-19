//! TPM2_Quote and the load-parent-quote-flush attestation path.

use crate::tbs::error::{check_tpm_rc, TpmOpError, TpmResult};
use crate::tbs::keys::{create_storage_primary, load_ak, AkBlob};
use crate::tbs::parse::ResponseParser;
use crate::tbs::pcr::{pcr_selection_list, PcrBank};
use crate::tbs::wire::{command_with_password_session, tpm2b, u16};
use crate::tbs::submit_tpm_command;

const TPM_CC_QUOTE: u32 = 0x0000_0158;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_SHA256: u16 = 0x000B;

pub struct QuoteResult {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

fn ecdsa_sha256_scheme() -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&u16(TPM_ALG_ECDSA));
    s.extend_from_slice(&u16(TPM_ALG_SHA256));
    s
}

pub fn quote(
    sign_handle: u32,
    pcr_selection: &[u32],
    qualifying_data: &[u8],
    bank: PcrBank,
) -> TpmResult<QuoteResult> {
    let mut params = Vec::new();
    params.extend(tpm2b(qualifying_data));
    params.extend(ecdsa_sha256_scheme());
    params.extend(pcr_selection_list(bank, pcr_selection));

    let cmd = command_with_password_session(sign_handle, TPM_CC_QUOTE, &params);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "Quote")?;

    let mut parser = ResponseParser::after_rc(&resp)?;
    let _param_size = parser.read_u32()?;
    let message = parser.read_tpm2b()?;
    let signature = parser.read_tpm2b()?;
    Ok(QuoteResult {
        message,
        signature,
    })
}

/// Regenerate storage primary, load AK blob, quote, flush all transients.
pub fn quote_with_ak_blob(
    ak_blob: &AkBlob,
    pcr_selection: &[u32],
    qualifying_data: &[u8],
    bank: PcrBank,
) -> TpmResult<QuoteResult> {
    let primary = create_storage_primary()?;
    let loaded = load_ak(primary.handle, ak_blob)?;
    let result = match quote(loaded.handle, pcr_selection, qualifying_data, bank) {
        Ok(r) => r,
        Err(e) => {
            let _ = loaded.flush();
            let _ = primary.flush();
            return Err(e);
        }
    };
    loaded.flush()?;
    primary.flush()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tbs::keys::create_ak;
    use std::path::Path;

    #[test]
    fn quote_command_has_sessions_tag() {
        let params = {
            let mut p = Vec::new();
            p.extend(tpm2b(b"qualifying"));
            p.extend(ecdsa_sha256_scheme());
            p.extend(pcr_selection_list(PcrBank::Sha256, &[0, 1, 7]));
            p
        };
        let cmd = command_with_password_session(0x80FF_FFFF, TPM_CC_QUOTE, &params);
        assert_eq!(&cmd[0..2], &[0x80, 0x02]);
        assert_eq!(&cmd[6..10], &[0x00, 0x00, 0x01, 0x58]);
    }

    use crate::tbs::parse::attest_extra_data;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_quote_roundtrip() {
        if !crate::tbs::hw_test::enabled() {
            return;
        }
        let primary = create_storage_primary().expect("CreatePrimary");
        let blob = create_ak(primary.handle).expect("Create AK");
        primary.flush().expect("flush primary");

        let qualifying = b"node-tpm2-quote-test-qualifying-data";
        let result = quote_with_ak_blob(&blob, &[0, 1, 7], qualifying, PcrBank::Sha256)
            .expect("quote");
        assert!(!result.message.is_empty());
        assert!(!result.signature.is_empty());

        let extra = attest_extra_data(&result.message).expect("extraData in TPMS_ATTEST");
        assert_eq!(extra, qualifying.as_slice());
    }
}

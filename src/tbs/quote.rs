//! TPM2_Quote and the load-parent-quote-flush attestation path.

use crate::tbs::error::{check_tpm_rc, TpmOpError, TpmResult};
use crate::tbs::keys::{create_storage_primary, load_ak, AkBlob};
use crate::tbs::parse::parameters_after_rc;
use crate::tbs::pcr::{pcr_selection_list, PcrBank};
use crate::tbs::wire::{command_with_password_session, scheme_ecdsa_sha256, scheme_rsassa_sha256, tpm2b, u16};
use crate::tbs::submit_tpm_command;

const TPM_CC_QUOTE: u32 = 0x0000_0158;
const TPM_ALG_NULL: u16 = 0x0010;

pub struct QuoteResult {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

/// ECDSA + SHA256 — Linux TBS-wrapped ECC AK (explicit at Quote time).
fn ecdsa_sha256_scheme() -> Vec<u8> {
    scheme_ecdsa_sha256()
}

/// TPM_ALG_NULL — Windows PCP RSA identity AK uses its baked-in default (RSASSA).
/// Matches go-attestation `tpm2.Quote(..., tpm2.AlgNull)` and Microsoft PCP samples.
pub fn pcp_rsa_quote_scheme() -> Vec<u8> {
    u16(TPM_ALG_NULL).to_vec()
}

/// RSASSA + SHA256 — explicit fallback if NULL scheme is rejected.
pub fn rsassa_sha256_scheme() -> Vec<u8> {
    scheme_rsassa_sha256()
}

pub fn quote(
    sign_handle: u32,
    pcr_selection: &[u32],
    qualifying_data: &[u8],
    bank: PcrBank,
) -> TpmResult<QuoteResult> {
    quote_with_submit(
        sign_handle,
        pcr_selection,
        qualifying_data,
        bank,
        &ecdsa_sha256_scheme(),
        |cmd| submit_tpm_command(cmd),
    )
}

/// Quote using a caller-provided TBS submit function (e.g. PCP-linked context on Windows).
pub fn quote_with_submit(
    sign_handle: u32,
    pcr_selection: &[u32],
    qualifying_data: &[u8],
    bank: PcrBank,
    sig_scheme: &[u8],
    submit: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
) -> TpmResult<QuoteResult> {
    let mut params = Vec::new();
    params.extend(tpm2b(qualifying_data));
    params.extend_from_slice(sig_scheme);
    params.extend(pcr_selection_list(bank, pcr_selection));

    let cmd = command_with_password_session(sign_handle, TPM_CC_QUOTE, &params);
    let resp = submit(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "Quote")?;

    let mut parser = parameters_after_rc(&resp)?;
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
    #[cfg(windows)]
    if crate::tbs::ak_blob::is_pcp_blob(ak_blob) {
        return crate::tbs::pcp::quote_with_pcp_ak_blob(ak_blob, pcr_selection, qualifying_data, bank);
    }

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
        if !crate::tbs::hw_test::mutating_enabled() {
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

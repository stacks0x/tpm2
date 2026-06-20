//! PolicySecret, TPM2_ActivateCredential, and credential roundtrips.
//!
//! MakeCredential is performed in software from the EK public area (same as
//! tpm2-tools with `-T none`); ActivateCredential uses the TPM.

use crate::tbs::commands::{
    create_primary_endorsement, flush_handle, object_handle_from_response, PrimaryKind,
};
use crate::tbs::error::{check_tpm_rc, TpmOpError, TpmResult};
use crate::tbs::keys::{create_storage_primary, load_ak, AkBlob};
use crate::tbs::make_credential_sw;
use crate::tbs::parse::{parameters_after_rc, session_nonce_from_response, start_auth_session_nonce_tpm};
use crate::tbs::read_public::read_public;
use crate::tbs::session_hmac::{
    handle_name_for_cphash, policy_session_auth_area, random_nonce_32,
    unbound_unsalted_session_key, SessionAuthInput,
};
use crate::tbs::wire::{
    command_with_handles_and_session, command_with_handles_and_sessions,
    command_with_handles_no_session, password_session_null_auth, start_auth_session_policy,
    tpm2b,
};
use crate::tbs::submit_tpm_command;

const TPM_CC_POLICY_SECRET: u32 = 0x0000_0151;
const TPM_CC_POLICY_COMMAND_CODE: u32 = 0x0000_016C;
const TPM_CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;
const PERSISTENT_EK_RSA: u32 = 0x8101_0001;
const PERSISTENT_EK_ECC: u32 = 0x8101_0002;
const TPMA_SESSION_CONTINUESESSION: u8 = 0x01;

struct PolicySession {
    handle: u32,
    nonce_tpm: Vec<u8>,
}

impl PolicySession {
    fn flush(self) -> TpmResult<()> {
        flush_handle(self.handle)
    }

    fn apply_response_nonce(&mut self, resp: &[u8]) {
        if let Ok(nonce) = session_nonce_from_response(resp, self.handle) {
            self.nonce_tpm = nonce;
        }
    }

    fn auth_area(
        &self,
        command_code: u32,
        handles: &[u32],
        handle_names: &[&[u8]],
        params: &[u8],
    ) -> Vec<u8> {
        let nonce_caller = random_nonce_32();
        policy_session_auth_area(SessionAuthInput {
            session_handle: self.handle,
            session_key: unbound_unsalted_session_key(),
            nonce_tpm: &self.nonce_tpm,
            nonce_caller: &nonce_caller,
            command_code,
            handles,
            handle_names,
            params,
            session_attributes: TPMA_SESSION_CONTINUESESSION,
        })
    }
}

struct EkHandle {
    handle: u32,
    name: Vec<u8>,
    owned: bool,
}

impl EkHandle {
    fn flush(self) -> TpmResult<()> {
        if self.owned {
            flush_handle(self.handle)?;
        }
        Ok(())
    }
}

fn flush_stale_policy_sessions() {
    for slot in 0x10..0x40u32 {
        let _ = flush_handle(0x0300_0000 | slot);
    }
}

fn start_policy_session() -> TpmResult<PolicySession> {
    flush_stale_policy_sessions();
    start_policy_session_after_flush()
}

fn start_policy_session_after_flush() -> TpmResult<PolicySession> {
    let nonce_caller = random_nonce_32();
    let cmd = start_auth_session_policy(&nonce_caller);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "StartAuthSession")?;
    let handle = object_handle_from_response(&resp)
        .ok_or_else(|| TpmOpError::other("StartAuthSession: missing session handle"))?;
    let nonce_tpm = start_auth_session_nonce_tpm(&resp)?;
    Ok(PolicySession {
        handle,
        nonce_tpm,
    })
}

fn policy_secret(session: &mut PolicySession, auth_handle: u32) -> TpmResult<()> {
    let mut params = Vec::new();
    params.extend(tpm2b_empty()); // nonceTPM (empty: no policy timeout binding)
    params.extend(tpm2b_empty()); // cpHashA
    params.extend(tpm2b_empty()); // policyRef
    params.extend_from_slice(&0i32.to_be_bytes()); // expiration (0 = no timeout)
    // Part 3 §23.4: authHandle Auth Index 1 (USER); policySession Auth Index None.
    // Endorsement hierarchy auth is satisfied via TPM_RH_PW (empty auth), not policy HMAC.
    let cmd = command_with_handles_and_session(
        &[auth_handle, session.handle],
        &password_session_null_auth(),
        TPM_CC_POLICY_SECRET,
        &params,
    );
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "PolicySecret")?;
    session.apply_response_nonce(&resp);
    Ok(())
}

fn policy_command_code(session: &mut PolicySession, command_code: u32) -> TpmResult<()> {
    let mut params = Vec::new();
    params.extend_from_slice(&command_code.to_be_bytes());
    // Part 3 §23.11: policySession Auth Index None → TPM_ST_NO_SESSIONS.
    let cmd = command_with_handles_no_session(
        &[session.handle],
        TPM_CC_POLICY_COMMAND_CODE,
        &params,
    );
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "PolicyCommandCode")?;
    let _ = session; // session nonce unchanged (no session in auth area)
    Ok(())
}

fn tpm2b_empty() -> Vec<u8> {
    vec![0x00, 0x00]
}

fn resolve_ek() -> TpmResult<EkHandle> {
    if let Ok(rp) = read_public(PERSISTENT_EK_RSA) {
        return Ok(EkHandle {
            handle: PERSISTENT_EK_RSA,
            name: rp.name,
            owned: false,
        });
    }
    if let Ok(rp) = read_public(PERSISTENT_EK_ECC) {
        return Ok(EkHandle {
            handle: PERSISTENT_EK_ECC,
            name: rp.name,
            owned: false,
        });
    }
    let cmd = create_primary_endorsement(PrimaryKind::Rsa2048);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "CreatePrimary endorsement")?;
    let handle = object_handle_from_response(&resp)
        .ok_or_else(|| TpmOpError::other("CreatePrimary endorsement: missing handle"))?;
    let name = read_public(handle)?.name;
    Ok(EkHandle {
        handle,
        name,
        owned: true,
    })
}

fn resolve_ek_public_wire() -> TpmResult<Vec<u8>> {
    if let Ok(rp) = read_public(PERSISTENT_EK_RSA) {
        return Ok(rp.public_wire);
    }
    if read_public(PERSISTENT_EK_ECC).is_ok() {
        return Err(TpmOpError::other(
            "software MakeCredential requires RSA EK; only ECC EK is available",
        ));
    }
    let cmd = create_primary_endorsement(PrimaryKind::Rsa2048);
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "CreatePrimary endorsement")?;
    let handle = object_handle_from_response(&resp)
        .ok_or_else(|| TpmOpError::other("CreatePrimary endorsement: missing handle"))?;
    let wire = read_public(handle)?.public_wire;
    let _ = flush_handle(handle);
    Ok(wire)
}

/// Build policy sessions for ActivateCredential.
///
/// Platform EK authPolicy is typically `PolicySecret(endorsement)` only; the AK requires
/// `PolicySecret + PolicyCommandCode(ActivateCredential)` (Part 3 §12.3 auth indices 1 and 2).
fn activate_policy_sessions() -> TpmResult<(PolicySession, PolicySession)> {
    flush_stale_policy_sessions();
    let mut ek = start_policy_session_after_flush()?;
    policy_secret(&mut ek, TPM_RH_ENDORSEMENT)?;

    let mut ak = start_policy_session_after_flush()?;
    policy_secret(&mut ak, TPM_RH_ENDORSEMENT)?;
    policy_command_code(&mut ak, TPM_CC_ACTIVATE_CREDENTIAL)?;

    Ok((ak, ek))
}

fn activate_credential(
    activate_handle: u32,
    activate_name: &[u8],
    key_handle: u32,
    key_name: &[u8],
    ak_session: &PolicySession,
    ek_session: &PolicySession,
    credential_blob: &[u8],
    secret: &[u8],
) -> TpmResult<Vec<u8>> {
    let mut params = Vec::new();
    params.extend(tpm2b(credential_blob));
    params.extend(tpm2b(secret));
    let activate_name = handle_name_for_cphash(activate_handle, Some(activate_name));
    let key_name = handle_name_for_cphash(key_handle, Some(key_name));
    let handles = &[activate_handle, key_handle];
    let names = &[activate_name.as_slice(), key_name.as_slice()];
    let ak_auth = ak_session.auth_area(TPM_CC_ACTIVATE_CREDENTIAL, handles, names, &params);
    let ek_auth = ek_session.auth_area(TPM_CC_ACTIVATE_CREDENTIAL, handles, names, &params);
    // Auth index 1 = AK (full policy); auth index 2 = EK (PolicySecret-only policy).
    let mut auth_area = ak_auth;
    auth_area.extend_from_slice(&ek_auth);
    let cmd = command_with_handles_and_sessions(
        handles,
        &auth_area,
        TPM_CC_ACTIVATE_CREDENTIAL,
        &params,
    );
    let resp = submit_tpm_command(&cmd).map_err(TpmOpError::transport)?;
    check_tpm_rc(&resp, "ActivateCredential")?;
    let mut parser = parameters_after_rc(&resp)?;
    Ok(parser.read_tpm2b()?)
}

/// Activate credential using a wrapped AK blob (regenerates parent, loads AK, flushes all).
pub fn activate_credential_with_ak_blob(
    ak_blob: &AkBlob,
    credential_blob: &[u8],
    secret: &[u8],
) -> TpmResult<Vec<u8>> {
    let primary = create_storage_primary()?;
    let ak = load_ak(primary.handle, ak_blob)?;
    let ak_name = read_public(ak.handle)?.name;
    let ek = resolve_ek()?;
    let (ak_session, ek_session) = activate_policy_sessions()?;

    let result = (|| {
        activate_credential(
            ak.handle,
            &ak_name,
            ek.handle,
            &ek.name,
            &ak_session,
            &ek_session,
            credential_blob,
            secret,
        )
    })();

    let _ = ak.flush();
    let _ = primary.flush();
    let _ = ek.flush();
    let _ = ak_session.flush();
    let _ = ek_session.flush();
    result
}

fn step<T>(label: &str, result: TpmResult<T>) -> TpmResult<T> {
    result.map_err(|e| TpmOpError::other(format!("{label}: {}", e.message)))
}

/// Self-contained roundtrip for probes: MakeCredential then ActivateCredential.
pub fn credential_roundtrip_self_test(ak_blob: &AkBlob) -> TpmResult<Vec<u8>> {
    let primary = step("CreatePrimary storage", create_storage_primary())?;
    let ak = step("Load AK", load_ak(primary.handle, ak_blob))?;
    let ak_name = step("ReadPublic AK", read_public(ak.handle))?.name;
    let ek = step("resolve EK", resolve_ek())?;
    let ek_public_wire = step("ReadPublic EK", resolve_ek_public_wire())?;
    let name = step("ReadPublic AK name", read_public(ak.handle))?.name;
    let credential = b"node-tpm2-credential-self-test";
    let made = step(
        "MakeCredential (software)",
        make_credential_sw::make_credential(&ek_public_wire, credential, &name),
    )?;

    let (ak_session, ek_session) = step("policy sessions", activate_policy_sessions())?;
    let result = (|| {
        step(
            "ActivateCredential",
            activate_credential(
                ak.handle,
                &ak_name,
                ek.handle,
                &ek.name,
                &ak_session,
                &ek_session,
                &made.credential_blob,
                &made.secret,
            ),
        )
    })();

    let _ = ak.flush();
    let _ = primary.flush();
    let _ = ek.flush();
    let _ = ak_session.flush();
    let _ = ek_session.flush();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tbs::keys::provision_ak_blob;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_credential_roundtrip() {
        if !crate::tbs::hw_test::enabled() {
            return;
        }
        let blob = provision_ak_blob().expect("provision");
        let recovered = credential_roundtrip_self_test(&blob).expect("roundtrip");
        assert_eq!(recovered, b"node-tpm2-credential-self-test");
    }
}

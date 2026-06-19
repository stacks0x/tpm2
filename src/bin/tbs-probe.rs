//! Direct-TBS validation probes (Option B). Linux and Windows, non-elevated.

use node_tpm2::tbs::commands::{create_primary_candidates, get_random_8, tpm_rc_from_response, tpm_rc_name};
use node_tpm2::tbs::credential::credential_roundtrip_self_test;
use node_tpm2::tbs::keys::{provision_ak, provision_ak_blob};
use node_tpm2::tbs::parse::attest_extra_data;
use node_tpm2::tbs::pcr::{pcr_read, PcrBank};
use node_tpm2::tbs::quote::quote_with_ak_blob;
use node_tpm2::tbs::rc::{classify_tpm_rc, describe_tpm_rc, RcClass};

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "all".to_string());

    let result = match cmd.as_str() {
        "get-random" => run_get_random(),
        "create-primary" => run_create_primary(),
        "pcr-read" => run_pcr_read(),
        "quote" => run_quote(),
        "provision-ak" => run_provision_ak(),
        "activate-credential" => run_activate_credential(),
        "policy-secret" => run_policy_secret(),
        "all" => run_all(),
        other => {
            eprintln!("unknown command: {other}");
            eprintln!(
                "usage: tbs-probe [get-random|create-primary|pcr-read|quote|provision-ak|activate-credential|all]"
            );
            std::process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("tbs-probe FAILED: {e}");
        std::process::exit(1);
    }
}

fn run_all() -> Result<(), String> {
    run_get_random()?;
    run_create_primary()?;
    run_pcr_read()?;
    run_quote()?;
    run_provision_ak()?;
    run_activate_credential()?;
    println!("\ntbs-probe: all checks passed");
    Ok(())
}

fn run_get_random() -> Result<(), String> {
    println!("== get-random ==");
    let resp = node_tpm2::tbs::submit_tpm_command(&get_random_8())?;
    let rc = tpm_rc_from_response(&resp).ok_or("short TPM response")?;
    report_tpm_rc("GetRandom", rc)
}

fn run_create_primary() -> Result<(), String> {
    println!("== create-primary (owner hierarchy, null auth, password session) ==");

    for (label, cmd) in create_primary_candidates() {
        println!("  try: {label}");

        let resp = match node_tpm2::tbs::submit_tpm_command(&cmd) {
            Ok(r) => r,
            Err(e) => {
                println!("    TBS error: {e}");
                continue;
            }
        };

        let rc = tpm_rc_from_response(&resp).ok_or("short TPM response")?;
        let class = classify_tpm_rc(rc);
        println!(
            "    -> TPM_RC 0x{rc:08X} ({}) ({})",
            tpm_rc_name(rc),
            describe_tpm_rc(rc)
        );

        match class {
            RcClass::Success => {
                if let Some(handle) = node_tpm2::tbs::commands::object_handle_from_response(&resp) {
                    println!("  PASS  unprivileged CreatePrimary succeeded ({label})");
                    println!("  primary handle: 0x{handle:08X}");
                    flush_created_transient(handle)?;
                } else {
                    println!("  PASS  unprivileged CreatePrimary succeeded ({label})");
                }
                return Ok(());
            }
            RcClass::Auth => {
                return Err(format!("CreatePrimary auth failure 0x{rc:08X} ({label})"));
            }
            RcClass::Format | RcClass::Other => continue,
        }
    }

    Err("CreatePrimary failed for all templates".to_string())
}

fn run_pcr_read() -> Result<(), String> {
    println!("== pcr-read ==");
    let pcrs = pcr_read(&[0, 1, 7], PcrBank::Sha256).map_err(|e| e.message)?;
    for idx in [0u32, 1, 7] {
        let digest = pcrs.get(&idx).ok_or_else(|| format!("missing PCR {idx}"))?;
        println!("  PCR {idx}: {digest}");
    }
    println!("  PASS  PCR_Read returned SHA-256 digests for [0, 1, 7]");
    Ok(())
}

fn run_quote() -> Result<(), String> {
    println!("== quote (wrapped AK blob, qualifyingData -> extraData) ==");

    let blob = provision_ak_blob().map_err(|e| e.message)?;
    println!(
        "  ak blob: public={} bytes, private={} bytes",
        blob.public.len(),
        blob.private.len()
    );

    let qualifying = b"node-tpm2-tbs-probe-qualifying-data";
    let result = quote_with_ak_blob(&blob, &[0, 1, 7], qualifying, PcrBank::Sha256)
        .map_err(|e| e.message)?;

    println!("  quote message: {} bytes", result.message.len());
    println!("  quote signature: {} bytes", result.signature.len());

    let extra = attest_extra_data(&result.message).ok_or("extraData not found in TPMS_ATTEST")?;
    if extra != qualifying.as_slice() {
        return Err("qualifyingData does not round-trip in TPMS_ATTEST.extraData".to_string());
    }
    println!("  PASS  qualifyingData round-trips in extraData");
    Ok(())
}

fn run_provision_ak() -> Result<(), String> {
    println!("== provision-ak (wrapped AK blob + SPKI DER) ==");

    let result = provision_ak().map_err(|e| e.message)?;
    println!("  ak public DER: {} bytes", result.ak_public_der.len());
    println!(
        "  ak blob: public={} bytes, private={} bytes",
        result.ak_blob.public.len(),
        result.ak_blob.private.len()
    );
    println!("  PASS  provisionAk returned exportable blob");
    Ok(())
}

fn run_activate_credential() -> Result<(), String> {
    println!("== activate-credential (MakeCredential off-TPM + ActivateCredential) ==");

    let blob = provision_ak_blob().map_err(|e| e.message)?;
    let recovered = credential_roundtrip_self_test(&blob).map_err(|e| e.message)?;
    if recovered != b"node-tpm2-credential-self-test" {
        return Err("credential roundtrip secret mismatch".to_string());
    }
    println!("  PASS  credential roundtrip recovered expected secret");
    Ok(())
}

fn run_policy_secret() -> Result<(), String> {
    use node_tpm2::tbs::session_hmac::{
        handle_name_for_cphash, policy_session_auth_area, random_nonce_32,
        session_key_from_start, SessionAuthInput,
    };

    const TPM_CC_POLICY_SECRET: u32 = 0x0000_0151;
    const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;
    const TPMA_SESSION_CONTINUESESSION: u8 = 0x01;

    println!("== policy-secret (StartAuthSession + PolicySecret endorsement) ==");
    let start_nonce = random_nonce_32();
    let cmd = node_tpm2::tbs::wire::start_auth_session_policy(&start_nonce);
    println!("  StartAuthSession cmd: {} bytes", cmd.len());
    let resp = node_tpm2::tbs::submit_tpm_command(&cmd).map_err(|e| e)?;
    let rc = tpm_rc_from_response(&resp).ok_or("short StartAuthSession response")?;
    if rc != 0 {
        return Err(format!("StartAuthSession failed 0x{rc:08X}"));
    }
    let handle = node_tpm2::tbs::commands::object_handle_from_response(&resp)
        .ok_or("missing session handle")?;
    let nonce_tpm = node_tpm2::tbs::parse::start_auth_session_nonce_tpm(&resp)
        .map_err(|e| e.message)?;
    println!("  session handle: 0x{handle:08X}");
    println!("  nonceTPM: {} bytes", nonce_tpm.len());

    let session_key = session_key_from_start(&nonce_tpm, &start_nonce);

    let mut params = Vec::new();
    params.extend(node_tpm2::tbs::wire::tpm2b_empty());
    params.extend(node_tpm2::tbs::wire::tpm2b_empty());
    params.extend(node_tpm2::tbs::wire::tpm2b_empty());
    params.extend_from_slice(&0i32.to_be_bytes());
    let auth_name = handle_name_for_cphash(TPM_RH_ENDORSEMENT, None);
    let session_name = handle_name_for_cphash(handle, None);
    let cmd_nonce = random_nonce_32();
    let policy_auth = policy_session_auth_area(SessionAuthInput {
        session_handle: handle,
        session_key: &session_key,
        nonce_tpm: &nonce_tpm,
        nonce_caller: &cmd_nonce,
        command_code: TPM_CC_POLICY_SECRET,
        handles: &[TPM_RH_ENDORSEMENT, handle],
        handle_names: &[auth_name.as_slice(), session_name.as_slice()],
        params: &params,
        session_attributes: TPMA_SESSION_CONTINUESESSION,
    });
    let ps_cmd = node_tpm2::tbs::wire::command_with_handles_and_session(
        &[TPM_RH_ENDORSEMENT, handle],
        &policy_auth,
        TPM_CC_POLICY_SECRET,
        &params,
    );
    println!("  PolicySecret cmd: {} bytes", ps_cmd.len());
    if std::env::var_os("TPM2_DUMP_CMD").is_some() {
        println!("  cmd hex: {}", ps_cmd.iter().map(|b| format!("{b:02x}")).collect::<String>());
    }
    let ps_resp = node_tpm2::tbs::submit_tpm_command(&ps_cmd).map_err(|e| e)?;
    let ps_rc = tpm_rc_from_response(&ps_resp).ok_or("short PolicySecret response")?;
    let result = report_tpm_rc("PolicySecret", ps_rc);
    let _ = node_tpm2::tbs::commands::flush_handle(handle);
    result
}

fn flush_created_transient(handle: u32) -> Result<(), String> {
    use node_tpm2::tbs::commands::{
        get_capability_transient_handles, is_transient_object_handle,
        transient_handles_from_getcap,
    };

    if !is_transient_object_handle(handle) {
        return Err(format!(
            "refusing to flush non-transient handle 0x{handle:08X}"
        ));
    }

    let mut flushed = try_flush_handle(handle)?;

    if !flushed {
        if let Ok(cap_resp) = node_tpm2::tbs::submit_tpm_command(&get_capability_transient_handles())
        {
            if let Some(handles) = transient_handles_from_getcap(&cap_resp) {
                for h in handles {
                    if h == handle || is_transient_object_handle(h) {
                        flushed |= try_flush_handle(h)?;
                    }
                }
            }
        }
    }

    if flushed {
        println!("  flushed transient primary 0x{handle:08X}");
    } else {
        eprintln!(
            "  WARN  FlushContext failed for handle 0x{handle:08X} \
             (transient may leak until context closes)"
        );
    }
    Ok(())
}

fn try_flush_handle(handle: u32) -> Result<bool, String> {
    use node_tpm2::tbs::commands::{flush_context, tpm_rc_from_response};

    let resp = node_tpm2::tbs::submit_tpm_command(&flush_context(handle))?;
    let rc = tpm_rc_from_response(&resp).ok_or("short FlushContext response")?;
    Ok(rc == 0)
}

fn report_tpm_rc(op: &str, rc: u32) -> Result<(), String> {
    let class = classify_tpm_rc(rc);
    println!("  {op} TPM_RC: 0x{rc:08X} ({})", describe_tpm_rc(rc));
    match class {
        RcClass::Success => {
            println!("  PASS  unprivileged {op} succeeded");
            Ok(())
        }
        RcClass::Auth => {
            println!("  FAIL  auth-class RC — owner hierarchy may require privilege");
            Err(format!("{op} auth failure 0x{rc:08X}"))
        }
        RcClass::Format => {
            println!("  FAIL  format-class RC — fix command marshalling (NOT a privilege result)");
            Err(format!("{op} marshalling error 0x{rc:08X}"))
        }
        RcClass::Other => {
            println!("  FAIL  unexpected TPM error");
            Err(format!("{op} failed 0x{rc:08X}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use node_tpm2::tbs::parse::attest_extra_data;

    #[test]
    fn extra_data_slice() {
        let mut msg = vec![0u8; 6];
        msg.extend_from_slice(&[0x00, 0x04, b'a', b'b', b'c', b'd']);
        msg.extend_from_slice(&[0x00, 0x03, b'x', b'y', b'z']);
        assert_eq!(attest_extra_data(&msg), Some(b"xyz".as_slice()));
    }
}

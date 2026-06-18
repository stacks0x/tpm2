//! Phase 0 direct-TBS probes (Option B). Zero tss-esapi dependency.

#[cfg(not(windows))]
fn main() {
    eprintln!("tbs-probe: Windows-only (non-elevated PowerShell on the Windows 11 VM)");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "all".to_string());

    let result = match cmd.as_str() {
        "get-random" => run_get_random(),
        "create-primary" => run_create_primary(),
        "all" => run_all(),
        other => {
            eprintln!("unknown command: {other}");
            eprintln!("usage: tbs-probe [get-random|create-primary|all]");
            std::process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("tbs-probe FAILED: {e}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run_all() -> Result<(), String> {
    run_get_random()?;
    run_create_primary()?;
    println!("\ntbs-probe: all checks passed");
    Ok(())
}

#[cfg(windows)]
fn run_get_random() -> Result<(), String> {
    use node_tpm2::tbs::commands::{get_random_8, tpm_rc_from_response};

    println!("== get-random ==");
    let resp = node_tpm2::tbs::submit_tpm_command(&get_random_8())?;
    let rc = tpm_rc_from_response(&resp).ok_or("short TPM response")?;
    report_tpm_rc("GetRandom", rc)
}

#[cfg(windows)]
fn run_create_primary() -> Result<(), String> {
    use node_tpm2::tbs::commands::{create_primary_candidates, tpm_rc_from_response, tpm_rc_name};
    use node_tpm2::tbs::rc::{classify_tpm_rc, describe_tpm_rc, RcClass};

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

#[cfg(windows)]
fn flush_created_transient(handle: u32) -> Result<(), String> {
    use node_tpm2::tbs::commands::{
        flush_context, get_capability_transient_handles, is_transient_object_handle,
        transient_handles_from_getcap, tpm_rc_from_response,
    };

    if !is_transient_object_handle(handle) {
        return Err(format!(
            "refusing to flush non-transient handle 0x{handle:08X}"
        ));
    }

    let mut flushed = try_flush_handle(handle)?;

    if !flushed {
        // Fallback: flush every transient handle the TPM reports (same TBS context).
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
             (TPM_RC_HANDLE — transient may leak; Windows TBS requires one context per process)"
        );
    }
    Ok(())
}

#[cfg(windows)]
fn try_flush_handle(handle: u32) -> Result<bool, String> {
    use node_tpm2::tbs::commands::{flush_context, tpm_rc_from_response};

    let resp = node_tpm2::tbs::submit_tpm_command(&flush_context(handle))?;
    let rc = tpm_rc_from_response(&resp).ok_or("short FlushContext response")?;
    Ok(rc == 0)
}

#[cfg(windows)]
fn report_tpm_rc(op: &str, rc: u32) -> Result<(), String> {
    use node_tpm2::tbs::rc::{classify_tpm_rc, describe_tpm_rc, RcClass};

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

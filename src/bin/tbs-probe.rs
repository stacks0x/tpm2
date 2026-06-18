//! Phase 0 direct-TBS probes (Option B). Zero tss-esapi dependency.
//!
//! ```text
//! cargo run --bin tbs-probe              # all checks
//! cargo run --bin tbs-probe -- get-random
//! cargo run --bin tbs-probe -- create-primary
//! ```

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
        "all" => {
            run_get_random()?;
            run_create_primary()?;
            println!("\ntbs-probe: all checks passed");
            Ok(())
        }
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
fn run_get_random() -> Result<(), String> {
    use node_tpm2::tbs::commands::{get_random_8, tpm_rc_from_response};

    println!("== get-random ==");
    let resp = node_tpm2::tbs::submit_tpm_command(&get_random_8())?;
    let rc = tpm_rc_from_response(&resp).ok_or("short TPM response")?;
    report_tpm_rc("GetRandom", rc)
}

#[cfg(windows)]
fn run_create_primary() -> Result<(), String> {
    use node_tpm2::tbs::commands::{create_primary_owner_ecc_storage, tpm_rc_from_response};

    println!("== create-primary (owner hierarchy, ECC storage, null auth) ==");
    let cmd = create_primary_owner_ecc_storage();
    if std::env::var("TBS_PROBE_DEBUG").is_ok() {
        println!("  command ({} bytes): {}", cmd.len(), hex_preview(&cmd));
    }
    let resp = node_tpm2::tbs::submit_tpm_command(&cmd)?;
    let rc = tpm_rc_from_response(&resp).ok_or("short TPM response")?;
    report_tpm_rc("CreatePrimary", rc)?;
    if rc == 0 && resp.len() >= 14 {
        let handle = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]);
        println!("  primary handle: 0x{handle:08X}");
    }
    Ok(())
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

#[cfg(windows)]
fn hex_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

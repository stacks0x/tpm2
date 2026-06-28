//! Direct-TBS validation probes (Option B). Linux and Windows, non-elevated by default.
//!
//! Windows PCP activation requires elevation; `all` skips activate and policy-secret when unprivileged.
//! Fleet cross-user spike: elevated `machine-provision`, then standard `quote-blob`.
//! Run `tbs-probe help` on Windows for step-by-step instructions.

use node_tpm2::tbs::ak_blob::{is_pcp_blob, pcp_key_scope};
use node_tpm2::tbs::commands::{create_primary_candidates, get_random_8, tpm_rc_from_response, tpm_rc_name};
use node_tpm2::tbs::credential::credential_roundtrip_self_test;
use node_tpm2::tbs::keys::{provision_ak, provision_ak_blob, provision_ak_with_options, AkBlob, ProvisionAkOptions};
use node_tpm2::tbs::parse::attest_extra_data;
use node_tpm2::tbs::pcr::{pcr_read, PcrBank};
use node_tpm2::tbs::quote::quote_with_ak_blob;
use node_tpm2::tbs::rc::{classify_tpm_rc, describe_tpm_rc, RcClass};

#[cfg(windows)]
use node_tpm2::tbs::ak_blob::PcpKeyScope;

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
        #[cfg(windows)]
        "pcp-capabilities" => run_pcp_capabilities(),
        #[cfg(windows)]
        "machine-provision" => run_machine_provision(),
        #[cfg(windows)]
        "quote-blob" => run_quote_blob(),
        #[cfg(windows)]
        "help" | "--help" | "-h" => {
            print_windows_help();
            Ok(())
        }
        "all" => run_all(),
        other => {
            eprintln!("unknown command: {other}");
            print_usage();
            std::process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("tbs-probe FAILED: {e}");
        std::process::exit(1);
    }
}

fn print_usage() {
    eprintln!("usage: tbs-probe <command>");
    eprintln!("  get-random | create-primary | pcr-read | quote | provision-ak");
    eprintln!("  activate-credential | policy-secret | all");
    #[cfg(windows)]
    {
        eprintln!("  pcp-capabilities | machine-provision | quote-blob | help");
        eprintln!();
        eprintln!("Windows: run `tbs-probe help` for testing instructions.");
    }
}

#[cfg(windows)]
fn print_windows_help() {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "target\\debug\\tbs-probe.exe".to_string());

    println!(
        r#"tbs-probe — Windows testing guide
================================

BUILD (once, any shell):
  cargo build --no-default-features --features probe-bin --bin tbs-probe

────────────────────────────────────────────────────────────────────
1. RUNTIME PATH (standard PowerShell — no admin)  [required]
────────────────────────────────────────────────────────────────────
  {exe} all

Proves quote/provision work unprivileged. Activate and policy-secret are SKIPped (enrollment / elevated diagnostics).

────────────────────────────────────────────────────────────────────
2. CROSS-USER QUOTE (standard user quotes machine AK)  [required]
────────────────────────────────────────────────────────────────────
STEP B always runs in standard PowerShell:

  {exe} quote-blob --in C:\ProgramData\node-tpm2-spike\ak.blob

STEP A — provision the machine key. Two contexts matter:

  (a) Admin spike — strong evidence, NOT production context
      Administrator PowerShell:
        {exe} machine-provision --key-name YOUR-KEY-NAME --out ak.blob
      pcp-capabilities must show: running as SYSTEM: false

  (b) SYSTEM spike — REQUIRED before calling the foundation complete
      Production enrollment (Intune/SCCM/GPO) runs as SYSTEM, not Admin.
      Re-run STEP A as SYSTEM, then STEP B again as standard user.

      Built-in Windows (Admin PowerShell, no PsExec install):

        # Rebuild MUST succeed before running the task (stale exe = wrong results).
        cargo build --no-default-features --features probe-bin --bin tbs-probe

        $exe = "{exe}"
        $dir = "C:\ProgramData\node-tpm2-spike"
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $log = "$dir\provision.log"
        $blob = "$dir\ak.blob"
        schtasks /Delete /TN "node-tpm2-system-spike" /F 2>$null
        schtasks /Create /TN "node-tpm2-system-spike" `
          /TR "cmd /c `"$exe`" machine-provision --key-name YOUR-KEY-NAME --out `"$blob`" > `"$log`" 2>&1" `
          /SC ONCE /ST 23:59 /SD 01/01/2030 /RU SYSTEM /RL HIGHEST /F
        schtasks /Run /TN "node-tpm2-system-spike"
        Start-Sleep -Seconds 8
        Get-Content $log
        # log must show "provision context: SYSTEM" and PASS

      Then standard PowerShell:
        {exe} quote-blob --in C:\ProgramData\node-tpm2-spike\ak.blob

      Alternative: PsExec -s -i (Sysinternals) if you already have it.

────────────────────────────────────────────────────────────────────
3. ACTIVATE ROUNDTRIP (elevated admin or SYSTEM)  [optional probe]
────────────────────────────────────────────────────────────────────
  {exe} activate-credential

────────────────────────────────────────────────────────────────────
Before production (outside this library)
────────────────────────────────────────────────────────────────────
- Validate SYSTEM provision on one real firmware TPM, domain-joined corp image
  (VM/swtpm is not a nurse's station)
- hardproof-enroll tooling is product-specific, not node-tpm2
"#
    );
}

#[cfg(not(windows))]
fn print_windows_help() {
    println!("help: Windows-only (machine PCP spike). On Linux, use: tbs-probe all");
}

fn run_all() -> Result<(), String> {
    run_get_random()?;
    run_create_primary()?;
    run_pcr_read()?;
    run_quote()?;
    run_provision_ak()?;
    run_activate_credential()?;
    run_policy_secret()?;
    println!("\ntbs-probe: all checks passed");
    #[cfg(windows)]
    if !node_tpm2::tbs::pcp::is_process_elevated() {
        println!("(Windows runtime path OK. Fleet machine-key spike: tbs-probe help)");
    }
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
    let pcrs = pcr_read(&[0, 1, 7], PcrBank::Sha256).map_err(|e| e.message())?;
    for idx in [0u32, 1, 7] {
        let digest = pcrs.get(&idx).ok_or_else(|| format!("missing PCR {idx}"))?;
        println!("  PCR {idx}: {digest}");
    }
    println!("  PASS  PCR_Read returned SHA-256 digests for [0, 1, 7]");
    Ok(())
}

fn run_quote() -> Result<(), String> {
    println!("== quote (wrapped AK blob, qualifyingData -> extraData) ==");

    let blob = provision_ak_blob().map_err(|e| e.message())?;
    print_blob_summary(&blob);
    quote_blob_roundtrip(&blob)
}

fn quote_blob_roundtrip(blob: &AkBlob) -> Result<(), String> {
    let qualifying = b"node-tpm2-tbs-probe-qualifying-data";
    let result = quote_with_ak_blob(blob, &[0, 1, 7], qualifying, PcrBank::Sha256)
        .map_err(|e| e.message())?;

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

    let result = provision_ak().map_err(|e| e.message())?;
    println!("  ak public DER: {} bytes", result.ak_public_der.len());
    print_blob_summary(&result.ak_blob);
    println!("  PASS  provisionAk returned exportable blob");
    Ok(())
}

fn run_activate_credential() -> Result<(), String> {
    println!("== activate-credential (MakeCredential + ActivateCredential) ==");

    #[cfg(windows)]
    if !node_tpm2::tbs::pcp::is_process_elevated() {
        println!(
            "  SKIP  PCP ActivateCredential requires elevation (Microsoft PCP / go-attestation #177); \
             runtime uses quote-only"
        );
        return Ok(());
    }

    let blob = provision_ak_blob().map_err(|e| e.message())?;
    match credential_roundtrip_self_test(&blob) {
        Ok(recovered) => {
            if recovered != b"node-tpm2-credential-self-test" {
                return Err("credential roundtrip secret mismatch".to_string());
            }
            println!("  PASS  credential roundtrip recovered expected secret");
            Ok(())
        }
        Err(e) => Err(e.message()),
    }
}

#[cfg(windows)]
fn run_pcp_capabilities() -> Result<(), String> {
    println!("== pcp-capabilities ==");
    let caps = node_tpm2::tbs::pcp::pcp_capabilities().map_err(|e| e.message())?;
    println!(
        "  Security Descr Support: {}",
        caps.security_descr_supported
    );
    println!(
        "  provision context: {}",
        node_tpm2::tbs::pcp::provision_context_label()
    );
    println!(
        "  process elevated: {}",
        node_tpm2::tbs::pcp::is_process_elevated()
    );
    println!(
        "  running as SYSTEM: {}",
        node_tpm2::tbs::pcp::is_running_as_system()
    );
    if !caps.security_descr_supported {
        println!("  WARN  machine-scoped AK (fleet enroll) requires Security Descr Support");
    }
    println!("  PASS  pcp-capabilities reported");
    Ok(())
}

#[cfg(windows)]
fn run_machine_provision() -> Result<(), String> {
    println!("== machine-provision (PCP2 machine-scoped AK) ==");
    println!(
        "  provision context: {}",
        node_tpm2::tbs::pcp::provision_context_label()
    );
    if node_tpm2::tbs::pcp::is_process_elevated() && !node_tpm2::tbs::pcp::is_running_as_system() {
        println!(
            "  NOTE  Admin context — production enrollment runs as SYSTEM; \
             see `tbs-probe help` section 2(b)"
        );
    }

    let key_name = flag_value("--key-name")
        .or_else(|| std::env::var("TPM2_KEY_NAME").ok())
        .unwrap_or_else(|| "node-tpm2-machine-ak".to_string());
    let out_path = flag_value("--out")
        .or_else(|| std::env::var("TPM2_AK_BLOB_PATH").ok())
        .unwrap_or_else(|| "ak.blob".to_string());

    if !node_tpm2::tbs::pcp::is_process_elevated() && !node_tpm2::tbs::pcp::is_running_as_system() {
        return Err(format!(
            "machine-provision must run elevated.\n\
             Open Start → Windows PowerShell → Run as administrator, then:\n\
             \n\
             cd {}\n\
             {} machine-provision --key-name {key_name} --out {out_path}\n\
             \n\
             (Run `tbs-probe help` for the full guide.)",
            std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| ".".to_string()),
            std::env::current_exe()
                .ok()
                .and_then(|p| p.to_str().map(String::from))
                .unwrap_or_else(|| "tbs-probe.exe".to_string()),
        ));
    }

    let opts = ProvisionAkOptions {
        key_name: Some(key_name.clone()),
        scope: PcpKeyScope::Machine,
        overwrite: true,
    };
    let result = provision_ak_with_options(&opts).map_err(|e| e.message())?;
    print_blob_summary(&result.ak_blob);
    write_ak_blob_file(&out_path, &result.ak_blob)?;
    println!("  key name: {key_name}");
    println!("  wrote blob: {out_path}");
    println!("  PASS  machine AK provisioned");
    println!();
    println!("  NEXT — switch to standard (non-admin) PowerShell and run:");
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "tbs-probe.exe".to_string());
    println!("    {exe} quote-blob --in {out_path}");
    Ok(())
}

#[cfg(windows)]
fn run_quote_blob() -> Result<(), String> {
    println!("== quote-blob (quote from persisted AK blob file) ==");

    let in_path = flag_value("--in")
        .or_else(|| std::env::var("TPM2_AK_BLOB_PATH").ok())
        .unwrap_or_else(|| "ak.blob".to_string());

    let blob = read_ak_blob_file(&in_path)?;
    print_blob_summary(&blob);
    if pcp_key_scope(&blob) != Some(PcpKeyScope::Machine) {
        println!("  WARN  blob is not PCP2 machine-scoped; cross-user spike expects machine key");
    }
    quote_blob_roundtrip(&blob)
}

fn print_blob_summary(blob: &AkBlob) {
    let scope = pcp_key_scope(blob)
        .map(|s| format!("{s:?}"))
        .unwrap_or_else(|| "linux".to_string());
    println!(
        "  ak blob: scope={scope}, public={} bytes, private={} bytes",
        blob.public.len(),
        blob.private.len()
    );
    if is_pcp_blob(blob) {
        if let Ok(meta) = node_tpm2::tbs::ak_blob::decode_pcp_blob(blob) {
            println!("  pcp key name: {}", meta.key_name);
        }
    }
}

fn flag_value(name: &str) -> Option<String> {
    let mut args = std::env::args().skip(2);
    while let Some(arg) = args.next() {
        if arg == name {
            return args.next();
        }
        if let Some(rest) = arg.strip_prefix(&format!("{name}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

const AKBL_MAGIC: &[u8; 4] = b"AKBL";

#[cfg(windows)]
fn write_ak_blob_file(path: &str, blob: &AkBlob) -> Result<(), String> {
    let mut out = Vec::new();
    out.extend_from_slice(AKBL_MAGIC);
    out.extend_from_slice(&(blob.public.len() as u32).to_le_bytes());
    out.extend_from_slice(&blob.public);
    out.extend_from_slice(&(blob.private.len() as u32).to_le_bytes());
    out.extend_from_slice(&blob.private);
    std::fs::write(path, out).map_err(|e| format!("write {path}: {e}"))
}

#[cfg(windows)]
fn read_ak_blob_file(path: &str) -> Result<AkBlob, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    if data.len() < 12 || &data[..4] != AKBL_MAGIC {
        return Err(format!("{path}: expected AKBL magic header"));
    }
    let mut off = 4;
    let pub_len = u32::from_le_bytes(data[off..off + 4].try_into().expect("4")) as usize;
    off += 4;
    if off + pub_len + 4 > data.len() {
        return Err(format!("{path}: truncated public field"));
    }
    let public = data[off..off + pub_len].to_vec();
    off += pub_len;
    let priv_len = u32::from_le_bytes(data[off..off + 4].try_into().expect("4")) as usize;
    off += 4;
    if off + priv_len > data.len() {
        return Err(format!("{path}: truncated private field"));
    }
    let private = data[off..off + priv_len].to_vec();
    Ok(AkBlob { public, private })
}

fn run_policy_secret() -> Result<(), String> {
    #[cfg(windows)]
    if !node_tpm2::tbs::pcp::is_process_elevated() {
        println!("== policy-secret (StartAuthSession + PolicySecret endorsement) ==");
        println!(
            "  SKIP  raw-TBS PolicySecret requires elevation on Windows; \
             run `tbs-probe policy-secret` elevated or use Linux for credential policy tests"
        );
        return Ok(());
    }

    use node_tpm2::tbs::session_hmac::random_nonce_32;

    const TPM_CC_POLICY_SECRET: u32 = 0x0000_0151;
    const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;

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
        .map_err(|e| e.message())?;
    println!("  session handle: 0x{handle:08X}");
    println!("  nonceTPM: {} bytes", nonce_tpm.len());

    let mut params = Vec::new();
    params.extend(node_tpm2::tbs::wire::tpm2b_empty());
    params.extend(node_tpm2::tbs::wire::tpm2b_empty());
    params.extend(node_tpm2::tbs::wire::tpm2b_empty());
    params.extend_from_slice(&0i32.to_be_bytes());
    let ps_cmd = node_tpm2::tbs::wire::command_with_handles_and_session(
        &[TPM_RH_ENDORSEMENT, handle],
        &node_tpm2::tbs::wire::password_session_null_auth(),
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
            if rc == node_tpm2::tbs::rc::WINDOWS_TPM_E_COMMAND_BLOCKED {
                println!(
                    "  FAIL  Windows TPM driver blocked this command ordinal (TPM_E_COMMAND_BLOCKED); \
                     raw TBS cannot invoke it on this OS build"
                );
            } else {
                println!("  FAIL  unexpected TPM error");
            }
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

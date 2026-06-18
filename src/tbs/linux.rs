//! Linux TPM access via `/dev/tpmrm0` (kernel resource manager).

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

const TPM_DEVICE: &str = "/dev/tpmrm0";

pub fn submit_tpm_command(cmd: &[u8]) -> Result<Vec<u8>, String> {
    if !Path::new(TPM_DEVICE).exists() {
        return Err(format!("{TPM_DEVICE} not found"));
    }

    let mut device = OpenOptions::new()
        .read(true)
        .write(true)
        .open(TPM_DEVICE)
        .map_err(|e| format!("open {TPM_DEVICE}: {e}"))?;

    device
        .write_all(cmd)
        .map_err(|e| format!("write {TPM_DEVICE}: {e}"))?;

    let mut resp = vec![0u8; 4096];
    let n = device
        .read(&mut resp)
        .map_err(|e| format!("read {TPM_DEVICE}: {e}"))?;
    resp.truncate(n);
    Ok(resp)
}

pub fn device_path() -> &'static str {
    TPM_DEVICE
}

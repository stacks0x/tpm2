//! Linux TPM access via `/dev/tpmrm0` (kernel resource manager).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Mutex;

const TPM_DEVICE: &str = "/dev/tpmrm0";

/// One open `/dev/tpmrm0` per process. Transient handles are scoped to the connection,
/// like Windows TBS contexts — a new fd per command breaks `GetCapability` / `FlushContext`.
static TPM_DEVICE_HANDLE: Mutex<Option<File>> = Mutex::new(None);

fn open_tpm_device() -> Result<File, String> {
    if !Path::new(TPM_DEVICE).exists() {
        return Err(format!("{TPM_DEVICE} not found"));
    }

    OpenOptions::new()
        .read(true)
        .write(true)
        .open(TPM_DEVICE)
        .map_err(|e| format!("open {TPM_DEVICE}: {e}"))
}

pub fn submit_tpm_command(cmd: &[u8]) -> Result<Vec<u8>, String> {
    let mut guard = TPM_DEVICE_HANDLE
        .lock()
        .map_err(|e| format!("TPM device lock poisoned: {e}"))?;
    if guard.is_none() {
        *guard = Some(open_tpm_device()?);
    }
    let device = guard.as_mut().unwrap();

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

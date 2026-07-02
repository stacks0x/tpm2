//! Windows TBS context + command submission.

use std::ffi::c_void;
use std::sync::Mutex;

use windows::Win32::System::TpmBaseServices::{
    Tbsi_Context_Create, Tbsip_Context_Close, Tbsip_Submit_Command, TBS_COMMAND_LOCALITY_ZERO,
    TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS, TBS_CONTEXT_PARAMS2,
};

use crate::tbs::response_buf::tpm_response_buffer_capacity;

pub struct TbsContext {
    handle: *mut c_void,
}

// SAFETY: TBS context handles are opaque OS resources. All use goes through the
// process-wide mutex below, so the handle is never accessed concurrently.
unsafe impl Send for TbsContext {}
unsafe impl Sync for TbsContext {}

impl TbsContext {
    pub fn open() -> Result<Self, String> {
        unsafe {
            let mut params = TBS_CONTEXT_PARAMS2::default();
            params.version = 2;
            params.Anonymous.asUINT32 = 0x0000_0004; // includeTpm20

            let mut handle: *mut c_void = std::ptr::null_mut();
            let rc = Tbsi_Context_Create(
                &params as *const TBS_CONTEXT_PARAMS2 as *const TBS_CONTEXT_PARAMS,
                &mut handle,
            );
            if rc != 0 {
                return Err(format!("Tbsi_Context_Create -> 0x{rc:08X}"));
            }
            Ok(Self { handle })
        }
    }

    pub fn submit(&self, cmd: &[u8]) -> Result<Vec<u8>, String> {
        submit_to_context(self.handle, cmd)
    }
}

/// Submit a TPM command through an existing TBS context (caller-owned; not closed here).
///
/// PCP `PCP_PLATFORMHANDLE` returns a context where persisted key handles are visible.
/// Windows TBS: `TBS_E_INSUFFICIENT_BUFFER` (0x80284005).
const TBS_E_INSUFFICIENT_BUFFER: u32 = 0x8028_4005;

pub fn submit_to_context(context: *mut c_void, cmd: &[u8]) -> Result<Vec<u8>, String> {
    if context.is_null() {
        return Err("TBS context is null".to_string());
    }
    let mut capacity = tpm_response_buffer_capacity();
    loop {
        let mut resp = vec![0u8; capacity];
        let mut resp_len: u32 = resp.len() as u32;
        let rc = unsafe {
            Tbsip_Submit_Command(
                context,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                cmd,
                resp.as_mut_ptr(),
                &mut resp_len,
            )
        };
        if rc == 0 {
            resp.truncate(resp_len as usize);
            return Ok(resp);
        }
        if rc == TBS_E_INSUFFICIENT_BUFFER && capacity < 65_536 {
            capacity = capacity.saturating_mul(2);
            continue;
        }
        return Err(format!("Tbsip_Submit_Command -> 0x{rc:08X}"));
    }
}

impl Drop for TbsContext {
    fn drop(&mut self) {
        unsafe {
            let _ = Tbsip_Context_Close(self.handle);
        }
    }
}

/// One TBS context per process. Transient handles created by `CreatePrimary` are only
/// visible to the context that loaded them; opening a new context per command breaks
/// `FlushContext` with `TPM_RC_HANDLE` (0x8B).
static TBS_CONTEXT: Mutex<Option<TbsContext>> = Mutex::new(None);

pub fn submit_tpm_command(cmd: &[u8]) -> Result<Vec<u8>, String> {
    let mut guard = TBS_CONTEXT
        .lock()
        .map_err(|e| format!("TBS context lock poisoned: {e}"))?;
    if guard.is_none() {
        *guard = Some(TbsContext::open()?);
    }
    guard.as_mut().unwrap().submit(cmd)
}

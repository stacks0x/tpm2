//! Windows TBS context + command submission.

use std::ffi::c_void;

use windows::Win32::System::TpmBaseServices::{
    Tbsi_Context_Create, Tbsip_Context_Close, Tbsip_Submit_Command, TBS_COMMAND_LOCALITY_ZERO,
    TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS, TBS_CONTEXT_PARAMS2,
};

pub struct TbsContext {
    handle: *mut c_void,
}

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
        unsafe {
            let mut resp = vec![0u8; 4096];
            let mut resp_len: u32 = resp.len() as u32;
            let rc = Tbsip_Submit_Command(
                self.handle,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                cmd,
                resp.as_mut_ptr(),
                &mut resp_len,
            );
            if rc != 0 {
                return Err(format!("Tbsip_Submit_Command -> 0x{rc:08X}"));
            }
            resp.truncate(resp_len as usize);
            Ok(resp)
        }
    }
}

impl Drop for TbsContext {
    fn drop(&mut self) {
        unsafe {
            let _ = Tbsip_Context_Close(self.handle);
        }
    }
}

pub fn submit_tpm_command(cmd: &[u8]) -> Result<Vec<u8>, String> {
    let ctx = TbsContext::open()?;
    ctx.submit(cmd)
}

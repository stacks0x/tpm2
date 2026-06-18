//! Platform transport seam: TBS on Windows, `/dev/tpmrm0` on Linux.
//! Option A (tss-esapi) only — behind the `esapi` feature.

#![cfg(feature = "esapi")]

#[cfg(not(target_os = "macos"))]
pub fn default_tcti() -> Result<tss_esapi::TctiNameConf, String> {
    use std::str::FromStr;

    #[cfg(target_os = "linux")]
    {
        use tss_esapi::tcti_ldr::DeviceConfig;
        Ok(tss_esapi::TctiNameConf::Device(
            DeviceConfig::from_str("/dev/tpmrm0")
                .map_err(|e| format!("invalid device path: {e}"))?,
        ))
    }

    #[cfg(target_os = "windows")]
    {
        tss_esapi::TctiNameConf::from_str("tbs:")
            .map_err(|e| format!("invalid TBS TCTI config: {e}"))
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = FromStr::from_str;
        Err("unsupported platform".to_string())
    }
}

#[cfg(not(target_os = "macos"))]
pub fn open_context() -> Result<tss_esapi::Context, String> {
    let tcti = default_tcti()?;
    tss_esapi::Context::new(tcti).map_err(|e| format!("Context::new failed: {e}"))
}

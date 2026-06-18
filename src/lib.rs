#[cfg(feature = "esapi")]
pub mod tpm;
#[cfg(feature = "esapi")]
pub mod transport;

pub mod tbs;

use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi(object)]
pub struct FixedPropertiesJs {
    pub manufacturer: String,
    pub firmware_version: String,
    pub is_virtual: bool,
    pub spec: String,
}

#[napi]
pub async fn is_available() -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        return Ok(false);
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        return Ok(tbs::is_available());
    }
    #[allow(unreachable_code)]
    Ok(false)
}

#[napi]
pub async fn get_fixed_properties() -> Result<FixedPropertiesJs> {
    #[cfg(target_os = "macos")]
    {
        return Err(Error::from_reason("TPM is not available on macOS"));
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let props = tbs::properties::read_fixed_properties()
            .map_err(|e| Error::from_reason(e))?;
        return Ok(FixedPropertiesJs {
            manufacturer: props.manufacturer,
            firmware_version: props.firmware_version,
            is_virtual: props.is_virtual,
            spec: props.spec,
        });
    }
    #[allow(unreachable_code)]
    Err(Error::from_reason("TPM backend not available on this platform"))
}

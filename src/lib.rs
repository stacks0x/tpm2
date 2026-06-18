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
}

#[napi]
pub async fn is_available() -> Result<bool> {
    #[cfg(all(feature = "esapi", not(target_os = "macos")))]
    {
        return Ok(tpm::is_available());
    }
    #[allow(unreachable_code)]
    Ok(false)
}

#[napi]
pub async fn get_fixed_properties() -> Result<FixedPropertiesJs> {
    #[cfg(all(feature = "esapi", not(target_os = "macos")))]
    {
        let props = tpm::probe().map_err(|e| Error::from_reason(e))?;
        return Ok(FixedPropertiesJs {
            manufacturer: props.manufacturer,
            firmware_version: props.firmware_version,
            is_virtual: props.is_virtual,
        });
    }
    Err(Error::from_reason(
        "TPM backend not available (macOS, or build without esapi feature)",
    ))
}

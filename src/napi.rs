use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::collections::HashMap;

use crate::tbs::error::TpmOpError;
use crate::tbs::pcr::PcrBank;
use crate::tbs::quote::quote_with_ak_blob;
use crate::tbs::read_public::{parse_handle, read_public as read_public_cmd};

#[napi(object)]
pub struct FixedPropertiesJs {
    pub manufacturer: String,
    pub firmware_version: String,
    pub is_virtual: bool,
    pub spec: String,
}

#[napi(object)]
pub struct ReadPublicJs {
    pub public_key_der: Buffer,
    pub name: Buffer,
}

#[napi(object)]
pub struct AkBlobJs {
    pub public: Buffer,
    pub private: Buffer,
}

#[napi(object)]
pub struct ProvisionAkOptionsJs {
    pub key_name: Option<String>,
    /// Windows only: `"user"` (default) or `"machine"`.
    pub scope: Option<String>,
    /// Windows only: replace existing persisted key of the same name.
    pub overwrite: Option<bool>,
}

#[napi(object)]
pub struct ProvisionAkJs {
    pub ak_public_der: Buffer,
    pub ak_blob: AkBlobJs,
}

#[napi(object)]
pub struct ActivateCredentialOptionsJs {
    pub ak_blob: AkBlobJs,
    pub credential_blob: Buffer,
    pub secret: Buffer,
}

#[napi(object)]
pub struct QuoteJs {
    pub message: Buffer,
    pub signature: Buffer,
}

#[napi(object)]
pub struct QuoteOptionsJs {
    pub ak_blob: AkBlobJs,
    pub pcr_selection: Vec<u32>,
    pub qualifying_data: Buffer,
    pub bank: Option<String>,
}

#[napi]
pub async fn random_bytes(count: u32) -> Result<Buffer> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let bytes = crate::tbs::random::random_bytes(count)?;
        Ok(Buffer::from(bytes))
    }
}

#[napi]
pub async fn is_available() -> Result<bool> {
    #[cfg(target_os = "macos")]
    {
        return Ok(false);
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        return Ok(crate::tbs::is_available());
    }
    #[allow(unreachable_code)]
    Ok(false)
}

#[napi]
pub async fn get_fixed_properties() -> Result<FixedPropertiesJs> {
    #[cfg(target_os = "macos")]
    {
        return Err(TpmOpError::unavailable("TPM is not available on macOS").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let props = crate::tbs::properties::read_fixed_properties().map_err(TpmOpError::transport)?;
        return Ok(FixedPropertiesJs {
            manufacturer: props.manufacturer,
            firmware_version: props.firmware_version,
            is_virtual: props.is_virtual,
            spec: props.spec,
        });
    }
    #[allow(unreachable_code)]
    Err(TpmOpError::unavailable("TPM backend not available on this platform").into())
}

#[napi]
pub async fn pcr_read(selection: Vec<u32>, bank: Option<String>) -> Result<HashMap<String, String>> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let bank = PcrBank::parse(bank.as_deref())?;
        let raw = crate::tbs::pcr::pcr_read(&selection, bank)?;
        Ok(raw
            .into_iter()
            .map(|(idx, digest)| (idx.to_string(), digest))
            .collect())
    }
}

#[napi]
pub async fn read_public(handle: String) -> Result<ReadPublicJs> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let handle = parse_handle(&handle)?;
        let result = read_public_cmd(handle)?;
        Ok(ReadPublicJs {
            public_key_der: Buffer::from(result.public_key_der),
            name: Buffer::from(result.name),
        })
    }
}

#[napi]
pub async fn read_ek_certificate() -> Result<Option<Buffer>> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        Ok(crate::tbs::nv::read_ek_certificate()?.map(Buffer::from))
    }
}

#[napi]
pub async fn quote(opts: QuoteOptionsJs) -> Result<QuoteJs> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let bank = PcrBank::parse(opts.bank.as_deref())?;
        let blob = crate::tbs::keys::AkBlob {
            public: opts.ak_blob.public.to_vec(),
            private: opts.ak_blob.private.to_vec(),
        };
        let result = quote_with_ak_blob(
            &blob,
            &opts.pcr_selection,
            &opts.qualifying_data,
            bank,
        )?;
        Ok(QuoteJs {
            message: Buffer::from(result.message),
            signature: Buffer::from(result.signature),
        })
    }
}

#[napi]
pub async fn provision_ak(opts: Option<ProvisionAkOptionsJs>) -> Result<ProvisionAkJs> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let options = provision_options_from_js(opts);
        let result = crate::tbs::keys::provision_ak_with_options(&options)?;
        Ok(ProvisionAkJs {
            ak_public_der: Buffer::from(result.ak_public_der),
            ak_blob: AkBlobJs {
                public: Buffer::from(result.ak_blob.public),
                private: Buffer::from(result.ak_blob.private),
            },
        })
    }
}

fn provision_options_from_js(opts: Option<ProvisionAkOptionsJs>) -> crate::tbs::keys::ProvisionAkOptions {
    let mut options = crate::tbs::keys::ProvisionAkOptions::default();
    if let Some(opts) = opts {
        options.key_name = opts.key_name;
        #[cfg(windows)]
        {
            use crate::tbs::ak_blob::PcpKeyScope;
            options.scope = match opts.scope.as_deref() {
                Some("machine") => PcpKeyScope::Machine,
                _ => PcpKeyScope::User,
            };
            options.overwrite = opts.overwrite.unwrap_or(false);
        }
    }
    options
}

#[napi]
pub async fn activate_credential(opts: ActivateCredentialOptionsJs) -> Result<Buffer> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let blob = crate::tbs::keys::AkBlob {
            public: opts.ak_blob.public.to_vec(),
            private: opts.ak_blob.private.to_vec(),
        };
        let recovered = crate::tbs::credential::activate_credential_with_ak_blob(
            &blob,
            &opts.credential_blob,
            &opts.secret,
        )?;
        Ok(Buffer::from(recovered))
    }
}

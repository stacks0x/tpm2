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

#[napi(object)]
pub struct KeyCreateOptionsJs {
    pub key_type: Option<String>,
    pub sign: Option<bool>,
    pub decrypt: Option<bool>,
}

#[napi(object)]
pub struct KeyCreateResultJs {
    pub public_key_der: Buffer,
    pub key_blob: AkBlobJs,
}

#[napi(object)]
pub struct SignKeyBlobOptionsJs {
    pub key_blob: AkBlobJs,
    pub digest: Buffer,
}

#[napi(object)]
pub struct DecryptKeyBlobOptionsJs {
    pub key_blob: AkBlobJs,
    pub cipher: Buffer,
}

#[napi(object)]
pub struct SealOptionsJs {
    pub data: Buffer,
    pub pcr_selection: Option<Vec<u32>>,
}

#[napi(object)]
pub struct NvWriteOptionsJs {
    pub handle: String,
    pub data: Buffer,
    pub offset: Option<u32>,
    pub auth: Option<Buffer>,
}

#[napi(object)]
pub struct NvDefineOptionsJs {
    pub handle: String,
    pub size: u32,
    pub auth: Option<Buffer>,
    pub owner_auth: Option<Buffer>,
}

#[napi(object)]
pub struct NvUndefineOptionsJs {
    pub handle: String,
    pub owner_auth: Option<Buffer>,
}

#[napi(object)]
pub struct NvReadPublicJs {
    pub data_size: u32,
    pub attributes: u32,
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
pub async fn pcr_extend(index: u32, digest: Buffer) -> Result<()> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        crate::tbs::pcr::pcr_extend(index, &digest)?;
        Ok(())
    }
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

#[napi]
pub async fn create_key(opts: Option<KeyCreateOptionsJs>) -> Result<KeyCreateResultJs> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let js = opts.unwrap_or(KeyCreateOptionsJs {
            key_type: None,
            sign: None,
            decrypt: None,
        });
        let options = crate::tbs::device_keys::parse_key_create_options(
            js.key_type.as_deref(),
            js.sign,
            js.decrypt,
        )?;
        let result = crate::tbs::device_keys::create_key(&options)?;
        Ok(KeyCreateResultJs {
            public_key_der: Buffer::from(result.public_key_der),
            key_blob: AkBlobJs {
                public: Buffer::from(result.key_blob.public),
                private: Buffer::from(result.key_blob.private),
            },
        })
    }
}

#[napi]
pub async fn key_blob_public_der(key_blob: AkBlobJs) -> Result<Buffer> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let blob = crate::tbs::keys::AkBlob {
            public: key_blob.public.to_vec(),
            private: key_blob.private.to_vec(),
        };
        Ok(Buffer::from(crate::tbs::device_keys::key_blob_spki(&blob)?))
    }
}

#[napi]
pub async fn sign_key_blob(opts: SignKeyBlobOptionsJs) -> Result<Buffer> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let blob = crate::tbs::keys::AkBlob {
            public: opts.key_blob.public.to_vec(),
            private: opts.key_blob.private.to_vec(),
        };
        let sig = crate::tbs::device_keys::sign_with_key_blob(&blob, &opts.digest)?;
        Ok(Buffer::from(sig))
    }
}

#[napi]
pub async fn decrypt_key_blob(opts: DecryptKeyBlobOptionsJs) -> Result<Buffer> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let blob = crate::tbs::keys::AkBlob {
            public: opts.key_blob.public.to_vec(),
            private: opts.key_blob.private.to_vec(),
        };
        let plain = crate::tbs::device_keys::decrypt_with_key_blob(&blob, &opts.cipher)?;
        Ok(Buffer::from(plain))
    }
}

#[napi]
pub async fn nv_read(
    handle: String,
    offset: Option<u32>,
    size: Option<u32>,
    auth: Option<Buffer>,
) -> Result<Buffer> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let index = crate::tbs::nv::parse_nv_handle(&handle)?;
        let info = crate::tbs::nv::nv_read_public(index)?;
        let offset = offset.unwrap_or(0);
        if offset > u16::MAX as u32 {
            return Err(TpmOpError::invalid_argument("NV offset exceeds u16 max").into());
        }
        let read_size = match size {
            Some(s) => {
                if s == 0 || s > u16::MAX as u32 {
                    return Err(TpmOpError::invalid_argument("NV read size must be 1..=65535").into());
                }
                s as u16
            }
            None => {
                let end = info.data_size as u32;
                if offset >= end {
                    return Err(TpmOpError::invalid_argument("NV offset beyond index size").into());
                }
                (end - offset) as u16
            }
        };
        let data = crate::tbs::nv::nv_read(
            index,
            offset as u16,
            read_size,
            auth.as_ref().map(|b| b.as_ref()),
        )?;
        Ok(Buffer::from(data))
    }
}

#[napi]
pub async fn nv_write(opts: NvWriteOptionsJs) -> Result<()> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let index = crate::tbs::nv::parse_nv_handle(&opts.handle)?;
        let offset = opts.offset.unwrap_or(0);
        if offset > u16::MAX as u32 {
            return Err(TpmOpError::invalid_argument("NV offset exceeds u16 max").into());
        }
        crate::tbs::nv::nv_write(
            index,
            offset as u16,
            &opts.data,
            opts.auth.as_ref().map(|b| b.as_ref()),
        )?;
        Ok(())
    }
}

#[napi]
pub async fn nv_read_public(handle: String) -> Result<NvReadPublicJs> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let index = crate::tbs::nv::parse_nv_handle(&handle)?;
        let info = crate::tbs::nv::nv_read_public(index)?;
        Ok(NvReadPublicJs {
            data_size: info.data_size as u32,
            attributes: info.attributes,
        })
    }
}

#[napi]
pub async fn nv_define(opts: NvDefineOptionsJs) -> Result<()> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        if opts.size == 0 || opts.size > u16::MAX as u32 {
            return Err(TpmOpError::invalid_argument("NV define size must be 1..=65535").into());
        }
        crate::tbs::nv::nv_define(&crate::tbs::nv::NvDefineOptions {
            index: crate::tbs::nv::parse_nv_handle(&opts.handle)?,
            size: opts.size as u16,
            attributes: None,
            index_auth: opts.auth.map(|b| b.to_vec()),
            owner_auth: opts.owner_auth.map(|b| b.to_vec()),
        })?;
        Ok(())
    }
}

#[napi]
pub async fn nv_undefine(opts: NvUndefineOptionsJs) -> Result<()> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let index = crate::tbs::nv::parse_nv_handle(&opts.handle)?;
        crate::tbs::nv::nv_undefine(
            index,
            opts.owner_auth.as_ref().map(|b| b.as_ref()),
        )?;
        Ok(())
    }
}

#[napi]
pub async fn seal(opts: SealOptionsJs) -> Result<Buffer> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let pcr = opts.pcr_selection.as_deref();
        let blob = crate::tbs::seal::seal(&opts.data, pcr)?;
        Ok(Buffer::from(blob))
    }
}

#[napi]
pub async fn unseal(blob: Buffer) -> Result<Buffer> {
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        return Err(TpmOpError::unavailable("TPM is not available on this platform").into());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let plain = crate::tbs::seal::unseal(&blob)?;
        Ok(Buffer::from(plain))
    }
}

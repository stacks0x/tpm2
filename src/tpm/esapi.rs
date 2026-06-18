//! tss-esapi command helpers for spike and native bindings.
#![cfg(feature = "esapi")]

use std::collections::HashMap;

use tss_esapi::{
    constants::PropertyTag,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        CreatePrimaryKeyResult, EccScheme, HashScheme, MaxBuffer, PcrSelectionListBuilder,
        PublicBuilder, PublicEccParametersBuilder, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
        SignatureScheme, SymmetricDefinitionObject,
    },
    Context,
};

use crate::transport;

#[derive(Debug, Clone)]
pub struct FixedProperties {
    pub manufacturer: String,
    pub firmware_version: String,
    pub is_virtual: bool,
}

pub fn is_available() -> bool {
    probe().is_ok()
}

pub fn probe() -> Result<FixedProperties, String> {
    let mut ctx = transport::open_context()?;
    read_fixed_properties(&mut ctx)
}

pub fn read_fixed_properties(ctx: &mut Context) -> Result<FixedProperties, String> {
    let props = ctx
        .get_capability_tpm_properties(tss_esapi::constants::CapabilityType::TpmProperties, 1, 64)
        .map_err(|e| format!("get_capability_tpm_properties failed: {e}"))?;

    let mut manufacturer = String::from("unknown");
    let mut firmware_version = String::from("unknown");
    let mut firmware_v1 = None;
    let mut firmware_v2 = None;

    for (tag, value) in props {
        match tag {
            PropertyTag::Manufacturer => manufacturer = four_cc(*value),
            PropertyTag::FirmwareVersion1 => firmware_v1 = Some(*value),
            PropertyTag::FirmwareVersion2 => firmware_v2 = Some(*value),
            _ => {}
        }
    }

    if let Some(v1) = firmware_v1 {
        firmware_version = format_firmware(v1, firmware_v2);
    }

    let vendor = vendor_string_from_properties(ctx);
    let is_virtual = vendor.to_ascii_lowercase().contains("swtpm")
        || vendor.to_ascii_lowercase().contains("virtual");

    Ok(FixedProperties {
        manufacturer,
        firmware_version,
        is_virtual,
    })
}

pub fn pcr_read(ctx: &mut Context, selection: &[u32]) -> Result<HashMap<u32, String>, String> {
    let pcr_slots: Vec<_> = selection
        .iter()
        .map(|&n| {
            tss_esapi::structures::PcrSlot::try_from(n)
                .map_err(|e| format!("invalid PCR index {n}: {e}"))
        })
        .collect::<Result<_, _>>()?;

    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &pcr_slots)
        .build()
        .map_err(|e| format!("PCR selection build failed: {e}"))?;

    let (_update_counter, pcr_digest, _pcr_selection_out) = ctx
        .execute_without_session(|ctx| ctx.pcr_read(pcr_selection))
        .map_err(|e| format!("pcr_read failed: {e}"))?;

    let mut out = HashMap::new();
    for (i, slot) in pcr_slots.iter().enumerate() {
        let digest = pcr_digest
            .value()
            .get(i)
            .ok_or_else(|| format!("missing digest for PCR {}", u8::from(*slot)))?;
        out.insert(u8::from(*slot) as u32, hex_encode(digest.value()));
    }
    Ok(out)
}

pub fn create_storage_primary(ctx: &mut Context) -> Result<CreatePrimaryKeyResult, String> {
    let object_attributes = tss_esapi::interface_types::resource_handles::ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(|e| format!("object attributes: {e}"))?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new_empty()
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .with_is_signing_key(false)
                .with_is_decryption_key(true)
                .with_restricted(true)
                .build()
                .map_err(|e| format!("rsa parameters: {e}"))?,
        )
        .build()
        .map_err(|e| format!("primary public build failed: {e}"))?;

    let sensitive = tss_esapi::structures::SensitiveCreateBuilder::new()
        .with_user_auth(
            tss_esapi::structures::Auth::try_from([0u8; 20])
                .map_err(|e| format!("auth: {e}"))?,
        )
        .build()
        .map_err(|e| format!("sensitive build failed: {e}"))?;

    ctx.execute_with_nullauth_session(|ctx| {
        ctx.create_primary(Hierarchy::Owner, sensitive, public, None, None, None)
    })
    .map_err(|e| format!("create_primary failed: {e}"))
}

#[derive(Debug, Clone)]
pub struct AkBlob {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

pub fn provision_ak_blob(ctx: &mut Context) -> Result<AkBlob, String> {
    let primary = create_storage_primary(ctx)?;
    provision_ak_blob_under_parent(ctx, primary.key_handle)
}

pub fn provision_ak_blob_under_parent(
    ctx: &mut Context,
    parent: tss_esapi::handles::KeyHandle,
) -> Result<AkBlob, String> {
    let object_attributes = tss_esapi::interface_types::resource_handles::ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()
        .map_err(|e| format!("ak object attributes: {e}"))?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new()
                .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                .with_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_curve(tss_esapi::interface_types::ecc::EccCurve::NistP256)
                .build()
                .map_err(|e| format!("ak ecc parameters: {e}"))?,
        )
        .build()
        .map_err(|e| format!("ak public build failed: {e}"))?;

    let sensitive = tss_esapi::structures::SensitiveCreateBuilder::new()
        .with_user_auth(
            tss_esapi::structures::Auth::try_from([0u8; 20])
                .map_err(|e| format!("auth: {e}"))?,
        )
        .build()
        .map_err(|e| format!("ak sensitive build failed: {e}"))?;

    let created = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create(parent, sensitive, public, None, None, None)
        })
        .map_err(|e| format!("create AK failed: {e}"))?;

    Ok(AkBlob {
        public: created
            .out_public
            .marshall()
            .map_err(|e| format!("marshall public: {e}"))?,
        private: created
            .out_private
            .marshall()
            .map_err(|e| format!("marshall private: {e}"))?,
    })
}

pub fn load_ak_blob(
    ctx: &mut Context,
    primary: tss_esapi::handles::KeyHandle,
    blob: &AkBlob,
) -> Result<tss_esapi::handles::KeyHandle, String> {
    let out_public = tss_esapi::structures::Public::unmarshall(&blob.public)
        .map_err(|e| format!("unmarshall public: {e}"))?;
    let out_private = tss_esapi::structures::Private::unmarshall(&blob.private)
        .map_err(|e| format!("unmarshall private: {e}"))?;

    ctx.execute_with_nullauth_session(|ctx| ctx.load(primary, out_private, out_public))
        .map_err(|e| format!("load AK blob failed: {e}"))
}

pub fn quote_with_ak(
    ctx: &mut Context,
    ak: tss_esapi::handles::KeyHandle,
    pcr_selection: &[u32],
    qualifying_data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let pcr_slots: Vec<_> = pcr_selection
        .iter()
        .map(|&n| {
            tss_esapi::structures::PcrSlot::try_from(n)
                .map_err(|e| format!("invalid PCR index {n}: {e}"))
        })
        .collect::<Result<_, _>>()?;

    let selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &pcr_slots)
        .build()
        .map_err(|e| format!("quote pcr selection: {e}"))?;

    let qualifying = MaxBuffer::try_from(qualifying_data.to_vec())
        .map_err(|e| format!("qualifying data: {e}"))?;

    let (attest, signature) = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.quote(
                ak,
                qualifying,
                SignatureScheme::EcDsa {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                selection,
            )
        })
        .map_err(|e| format!("quote failed: {e}"))?;

    let message = attest
        .marshall()
        .map_err(|e| format!("marshall attest: {e}"))?;
    let sig = signature
        .marshall()
        .map_err(|e| format!("marshall signature: {e}"))?;

    Ok((message, sig))
}

fn four_cc(value: u32) -> String {
    let bytes = value.to_be_bytes();
    String::from_utf8_lossy(&bytes)
        .trim_end_matches('\0')
        .to_string()
}

fn format_firmware(v1: u32, v2: Option<u32>) -> String {
    let major = (v1 >> 16) & 0xffff;
    let minor = v1 & 0xffff;
    match v2 {
        Some(v2) => format!("{major}.{minor}.{v2}"),
        None => format!("{major}.{minor}"),
    }
}

fn vendor_string_from_properties(ctx: &mut Context) -> String {
    let Ok(props) = ctx.get_capability_tpm_properties(
        tss_esapi::constants::CapabilityType::TpmProperties,
        1,
        64,
    ) else {
        return String::new();
    };

    let mut chunks = [0u32; 4];
    for (tag, value) in props {
        match tag {
            PropertyTag::VendorString1 => chunks[0] = *value,
            PropertyTag::VendorString2 => chunks[1] = *value,
            PropertyTag::VendorString3 => chunks[2] = *value,
            PropertyTag::VendorString4 => chunks[3] = *value,
            _ => {}
        }
    }

    chunks
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .take_while(|&b| b != 0)
        .map(|b| b as char)
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

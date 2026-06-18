//! TPM fixed properties via GetCapability.

use crate::tbs::commands::tpm_rc_from_response;
use crate::tbs::wire::{command, u32};
use crate::tbs::submit_tpm_command;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017A;
const TPM_CAP_TPM_PROPERTIES: u32 = 0x0000_0006;

const TPM_PT_MANUFACTURER: u32 = 0x0000_0105;
const TPM_PT_FIRMWARE_VERSION_1: u32 = 0x0000_010B;
const TPM_PT_FIRMWARE_VERSION_2: u32 = 0x0000_010C;
const TPM_PT_VENDOR_STRING_1: u32 = 0x0000_0106;
const TPM_PT_VENDOR_STRING_2: u32 = 0x0000_0107;
const TPM_PT_VENDOR_STRING_3: u32 = 0x0000_0108;
const TPM_PT_VENDOR_STRING_4: u32 = 0x0000_0109;

#[derive(Debug, Clone)]
pub struct FixedProperties {
    pub manufacturer: String,
    pub firmware_version: String,
    pub is_virtual: bool,
}

pub fn read_fixed_properties() -> Result<FixedProperties, String> {
    let mut body = Vec::new();
    body.extend_from_slice(&u32(TPM_CAP_TPM_PROPERTIES));
    body.extend_from_slice(&u32(1)); // first property tag
    body.extend_from_slice(&u32(64)); // property count
    let cmd = command(TPM_ST_NO_SESSIONS, TPM_CC_GET_CAPABILITY, &body);

    let resp = submit_tpm_command(&cmd)?;
    let rc = tpm_rc_from_response(&resp).ok_or("short GetCapability response")?;
    if rc != 0 {
        return Err(format!("GetCapability failed 0x{rc:08X}"));
    }

    let props = parse_tpm_properties(&resp)?;
    Ok(FixedProperties {
        manufacturer: four_cc(props.get(&TPM_PT_MANUFACTURER).copied().unwrap_or(0)),
        firmware_version: format_firmware(
            props.get(&TPM_PT_FIRMWARE_VERSION_1).copied(),
            props.get(&TPM_PT_FIRMWARE_VERSION_2).copied(),
        ),
        is_virtual: vendor_string(&props).to_ascii_lowercase().contains("swtpm")
            || vendor_string(&props).to_ascii_lowercase().contains("virtual"),
    })
}

fn parse_tpm_properties(resp: &[u8]) -> Result<std::collections::HashMap<u32, u32>, String> {
    if resp.len() < 19 {
        return Err("GetCapability response too short".to_string());
    }

    let capability = u32::from_be_bytes([resp[11], resp[12], resp[13], resp[14]]);
    if capability != TPM_CAP_TPM_PROPERTIES {
        return Err(format!("unexpected capability 0x{capability:08X}"));
    }

    let count = u32::from_be_bytes([resp[15], resp[16], resp[17], resp[18]]) as usize;
    let mut out = std::collections::HashMap::new();
    let mut offset = 19;
    for _ in 0..count {
        if offset + 8 > resp.len() {
            break;
        }
        let property = u32::from_be_bytes([
            resp[offset],
            resp[offset + 1],
            resp[offset + 2],
            resp[offset + 3],
        ]);
        let value = u32::from_be_bytes([
            resp[offset + 4],
            resp[offset + 5],
            resp[offset + 6],
            resp[offset + 7],
        ]);
        out.insert(property, value);
        offset += 8;
    }
    Ok(out)
}

fn four_cc(value: u32) -> String {
    let bytes = value.to_be_bytes();
    String::from_utf8_lossy(&bytes)
        .trim_end_matches('\0')
        .to_string()
}

fn format_firmware(v1: Option<u32>, v2: Option<u32>) -> String {
    match v1 {
        Some(v1) => {
            let major = (v1 >> 16) & 0xffff;
            let minor = v1 & 0xffff;
            match v2 {
                Some(v2) => format!("{major}.{minor}.{v2}"),
                None => format!("{major}.{minor}"),
            }
        }
        None => String::from("unknown"),
    }
}

fn vendor_string(props: &std::collections::HashMap<u32, u32>) -> String {
    let chunks = [
        props.get(&TPM_PT_VENDOR_STRING_1).copied().unwrap_or(0),
        props.get(&TPM_PT_VENDOR_STRING_2).copied().unwrap_or(0),
        props.get(&TPM_PT_VENDOR_STRING_3).copied().unwrap_or(0),
        props.get(&TPM_PT_VENDOR_STRING_4).copied().unwrap_or(0),
    ];
    chunks
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .take_while(|&b| b != 0)
        .map(|b| b as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_capability_response_layout() {
        // minimal synthetic response: rc=0, cap=6, count=1, prop 0x105 = IBM
        let mut resp = vec![0u8; 27];
        resp[6..10].copy_from_slice(&0u32.to_be_bytes());
        resp[10] = 0; // moreData
        resp[11..15].copy_from_slice(&TPM_CAP_TPM_PROPERTIES.to_be_bytes());
        resp[15..19].copy_from_slice(&1u32.to_be_bytes());
        resp[19..23].copy_from_slice(&TPM_PT_MANUFACTURER.to_be_bytes());
        resp[23..27].copy_from_slice(&0x4942_4D00u32.to_be_bytes()); // "IBM\0"

        let props = parse_tpm_properties(&resp).unwrap();
        assert_eq!(props.get(&TPM_PT_MANUFACTURER), Some(&0x4942_4D00));
        assert_eq!(four_cc(0x4942_4D00), "IBM");
    }
}

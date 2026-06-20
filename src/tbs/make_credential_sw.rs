//! Software TPM2_MakeCredential (matches tpm2-tools off-TPM path for RSA EK).

use crate::tbs::error::{TpmOpError, TpmResult};
use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use cfb_mode::Encryptor;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rsa::oaep::Oaep;
use rsa::{BigUint, RsaPublicKey};
use sha2::Sha256;

type Aes128CfbEnc = Encryptor<aes::Aes128>;

const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_CFB: u16 = 0x0043;
const TPM_ALG_SHA256: u16 = 0x000B;

struct EkRsaPublic {
    name_alg: u16,
    sym_key_bits: u16,
    modulus: Vec<u8>,
    exponent: u32,
}

pub struct MakeCredentialResult {
    pub credential_blob: Vec<u8>,
    pub secret: Vec<u8>,
}

pub fn make_credential(
    ek_public_wire: &[u8],
    credential: &[u8],
    object_name: &[u8],
) -> TpmResult<MakeCredentialResult> {
    let ek = parse_rsa_ek_public(ek_public_wire)?;
    let hash_len = hash_size(ek.name_alg)?;
    if credential.len() > hash_len {
        return Err(TpmOpError::other(format!(
            "credential length {} exceeds EK nameAlg digest size {hash_len}",
            credential.len()
        )));
    }

    let mut seed = vec![0u8; hash_len];
    rand::thread_rng().fill_bytes(&mut seed);

    let secret = encrypt_seed_identity(&ek, &seed)?;
    let hmac_key = kdfa(
        ek.name_alg,
        &seed,
        b"INTEGRITY",
        &[],
        &[],
        (hash_len * 8) as u32,
    )?;
    let enc_key = kdfa(
        ek.name_alg,
        &seed,
        b"STORAGE",
        object_name,
        &[],
        ek.sym_key_bits as u32,
    )?;

    let mut marshalled = Vec::with_capacity(2 + credential.len());
    marshalled.extend_from_slice(&(credential.len() as u16).to_be_bytes());
    marshalled.extend_from_slice(credential);

    let encrypted_sensitive = aes_cfb_encrypt(&enc_key, &marshalled)?;
    let outer_hmac = hmac_outer(ek.name_alg, &hmac_key, &encrypted_sensitive, object_name)?;

    let mut credential_blob = Vec::with_capacity(2 + outer_hmac.len() + encrypted_sensitive.len());
    credential_blob.extend_from_slice(&(outer_hmac.len() as u16).to_be_bytes());
    credential_blob.extend_from_slice(&outer_hmac);
    credential_blob.extend_from_slice(&encrypted_sensitive);

    Ok(MakeCredentialResult {
        credential_blob,
        secret,
    })
}

fn parse_rsa_ek_public(wire: &[u8]) -> TpmResult<EkRsaPublic> {
    if wire.len() < 4 {
        return Err(TpmOpError::other("EK public wire too short"));
    }
    let inner_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
    if wire.len() < 2 + inner_len {
        return Err(TpmOpError::other("truncated EK public wire"));
    }
    let public = &wire[2..2 + inner_len];
    let mut off = 0usize;
    let end = public.len();
    let alg = read_u16(public, &mut off, end)?;
    if alg != TPM_ALG_RSA {
        return Err(TpmOpError::other(format!(
            "software MakeCredential supports RSA EK only (got 0x{alg:04X})"
        )));
    }
    let name_alg = read_u16(public, &mut off, end)?;
    let _attrs = read_u32(public, &mut off, end)?;
    off = skip_tpm2b(public, off, end)?;
    let sym_alg = read_u16(public, &mut off, end)?;
    if sym_alg != TPM_ALG_AES {
        return Err(TpmOpError::other("EK symmetric algorithm must be AES"));
    }
    let sym_key_bits = read_u16(public, &mut off, end)?;
    let sym_mode = read_u16(public, &mut off, end)?;
    if sym_mode != TPM_ALG_CFB {
        return Err(TpmOpError::other("EK symmetric mode must be CFB"));
    }
    off = skip_rsa_scheme(public, off, end)?;
    let key_bits = read_u16(public, &mut off, end)?;
    let exponent = read_u32(public, &mut off, end)?;
    let modulus = read_tpm2b(public, &mut off, end)?;
    if modulus.len() * 8 != key_bits as usize {
        // swtpm may pad; modulus TPM2B is authoritative.
    }
    Ok(EkRsaPublic {
        name_alg,
        sym_key_bits,
        modulus,
        exponent,
    })
}

fn encrypt_seed_identity(ek: &EkRsaPublic, seed: &[u8]) -> TpmResult<Vec<u8>> {
    let exp = if ek.exponent == 0 {
        BigUint::from(65537u32)
    } else {
        BigUint::from(ek.exponent)
    };
    let n = BigUint::from_bytes_be(&ek.modulus);
    let pubkey = RsaPublicKey::new(n, exp)
        .map_err(|e| TpmOpError::other(format!("invalid RSA EK public key: {e}")))?;
    let padding = Oaep::new_with_label::<Sha256, _>("IDENTITY");
    let mut rng = rand::thread_rng();
    let encrypted = pubkey
        .encrypt(&mut rng, padding, seed)
        .map_err(|e| TpmOpError::other(format!("RSA-OAEP encrypt failed: {e}")))?;
    Ok(encrypted)
}

fn kdfa(
    hash_alg: u16,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> TpmResult<Vec<u8>> {
    let out_len = (bits as usize).div_ceil(8);
    let mut out = Vec::with_capacity(out_len);
    let mut counter = 0u32;
    while out.len() < out_len {
        counter += 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(&counter.to_be_bytes());
        buf.extend_from_slice(label);
        buf.push(0);
        buf.extend_from_slice(context_u);
        buf.extend_from_slice(context_v);
        buf.extend_from_slice(&bits.to_be_bytes());
        let block = hmac_block(hash_alg, key, &buf)?;
        out.extend_from_slice(&block);
    }
    out.truncate(out_len);
    Ok(out)
}

fn hmac_outer(
    hash_alg: u16,
    key: &[u8],
    encrypted: &[u8],
    object_name: &[u8],
) -> TpmResult<Vec<u8>> {
    let mut data = Vec::with_capacity(encrypted.len() + object_name.len());
    data.extend_from_slice(encrypted);
    data.extend_from_slice(object_name);
    hmac_block(hash_alg, key, &data)
}

fn hmac_block(hash_alg: u16, key: &[u8], data: &[u8]) -> TpmResult<Vec<u8>> {
    match hash_alg {
        TPM_ALG_SHA256 => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(key).map_err(|e| TpmOpError::other(e.to_string()))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        other => Err(TpmOpError::other(format!(
            "unsupported hash algorithm 0x{other:04X}"
        ))),
    }
}

fn aes_cfb_encrypt(key: &[u8], plaintext: &[u8]) -> TpmResult<Vec<u8>> {
    if key.len() < 16 {
        return Err(TpmOpError::other("AES-128 key too short"));
    }
    let iv = [0u8; 16];
    let cipher = Aes128CfbEnc::new_from_slices(&key[..16], &iv)
        .map_err(|e| TpmOpError::other(format!("AES-CFB init failed: {e}")))?;
    let mut out = plaintext.to_vec();
    cipher.encrypt(&mut out);
    Ok(out)
}

fn hash_size(alg: u16) -> TpmResult<usize> {
    match alg {
        TPM_ALG_SHA256 => Ok(32),
        other => Err(TpmOpError::other(format!(
            "unsupported nameAlg 0x{other:04X}"
        ))),
    }
}

fn tpm2b(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + data.len());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn read_u16(data: &[u8], off: &mut usize, end: usize) -> TpmResult<u16> {
    if *off + 2 > end {
        return Err(TpmOpError::other("truncated TPM public"));
    }
    let v = u16::from_be_bytes([data[*off], data[*off + 1]]);
    *off += 2;
    Ok(v)
}

fn read_u32(data: &[u8], off: &mut usize, end: usize) -> TpmResult<u32> {
    if *off + 4 > end {
        return Err(TpmOpError::other("truncated TPM public"));
    }
    let v = u32::from_be_bytes([data[*off], data[*off + 1], data[*off + 2], data[*off + 3]]);
    *off += 4;
    Ok(v)
}

fn read_tpm2b(data: &[u8], off: &mut usize, end: usize) -> TpmResult<Vec<u8>> {
    if *off + 2 > end {
        return Err(TpmOpError::other("truncated TPM2B"));
    }
    let size = u16::from_be_bytes([data[*off], data[*off + 1]]) as usize;
    *off += 2;
    if *off + size > end {
        return Err(TpmOpError::other("truncated TPM2B payload"));
    }
    let v = data[*off..*off + size].to_vec();
    *off += size;
    Ok(v)
}

fn skip_tpm2b(data: &[u8], off: usize, end: usize) -> TpmResult<usize> {
    if off + 2 > end {
        return Err(TpmOpError::other("truncated TPM2B"));
    }
    let size = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
    if off + 2 + size > end {
        return Err(TpmOpError::other("truncated TPM2B payload"));
    }
    Ok(off + 2 + size)
}

fn skip_rsa_scheme(data: &[u8], off: usize, end: usize) -> TpmResult<usize> {
    if off + 2 > end {
        return Err(TpmOpError::other("truncated RSA scheme"));
    }
    let scheme = u16::from_be_bytes([data[off], data[off + 1]]);
    let mut o = off + 2;
    if scheme != 0x0010 {
        if o + 2 > end {
            return Err(TpmOpError::other("truncated RSA scheme hash"));
        }
        o += 2;
    }
    Ok(o)
}

use sha1::{Digest, Sha1};
use hmac::Hmac;
use crypto_mac::{Mac, MacResult};
use yubicoerror::YubicoError;
use base64::{decode};
use hmacmode::HmacKey;

const PRESET_VALUE: u16 = 0xFFFF;
const POLYNOMIAL: u16 = 0x8408;
const SHA1_DIGEST_SIZE: usize = 20;
pub const CRC_RESIDUAL_OK: u16 = 0xf0b8;

type HmacSha1 = Hmac<Sha1>;

//  1. Apply the HMAC-SHA-1 algorithm on the line as an octet string using the API key as key
pub fn build_signature(key: Vec<u8>, query: String) -> Result<MacResult<<sha1::Sha1 as Digest>::OutputSize>, YubicoError>
{
    let decoded_key = decode(&key)?;

    let mut hmac = match HmacSha1::new_varkey(&decoded_key) {
        Ok(h) => h,
        Err(_) => return Err(YubicoError::InvalidKeyLength)
    };
    hmac.input(query.as_bytes());
    Ok(hmac.result())
}

pub fn hmac_sha1(key: &HmacKey, data: &[u8]) -> [u8; SHA1_DIGEST_SIZE] {
    let mut hmac = HmacSha1::new_varkey(&key.0).unwrap();
    hmac.input(data);

    let mut code = [0; SHA1_DIGEST_SIZE];
    code.copy_from_slice(hmac.result().code().as_slice());

    code
}

pub fn crc16(data: &[u8]) -> u16 {
    let mut crc_value = PRESET_VALUE;
    for &b in data {
        crc_value ^= b as u16;
        for _ in 0..8 {
            let j = crc_value & 1;
            crc_value >>= 1;
            if j != 0 {
                crc_value ^= POLYNOMIAL
            }
        }
    }
    crc_value
}
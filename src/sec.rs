use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use yubicoerror::YubicoError;
use base64::{decode};
use hmacmode::HmacKey;

const PRESET_VALUE: u16 = 0xFFFF;
const POLYNOMIAL: u16 = 0x8408;
const SHA1_DIGEST_SIZE: usize = 20;
pub const CRC_RESIDUAL_OK: u16 = 0xf0b8;

//  1. Apply the HMAC-SHA-1 algorithm on the line as an octet string using the API key as key
pub fn build_signature(key: Vec<u8>, query: String) -> Result<MacResult, YubicoError> {
    let decoded_key = decode(&key)?;

    let mut hmac = Hmac::new(Sha1::new(), &decoded_key);
    hmac.input(query.as_bytes());
    Ok(hmac.result())
}

pub fn hmac_sha1(key: &HmacKey, data: &[u8]) -> [u8; SHA1_DIGEST_SIZE] {
    let digest = Sha1::new();
    let mut hmac = Hmac::new(digest, &key.0);
    hmac.input(data);

    let mut code = [0; SHA1_DIGEST_SIZE];
    hmac.raw_result(&mut code);

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
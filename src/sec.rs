use crate::yubicoerror::YubicoError;
use base64::decode;
use crypto_mac::{Mac, NewMac, Output};
use hmac::Hmac;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

//  1. Apply the HMAC-SHA-1 algorithm on the line as an octet string using the API key as key
pub fn build_signature(
    key: &[u8],
    input: &[u8],
) -> Result<Output<HmacSha1>, YubicoError> {
    let decoded_key = decode(key)?;

    let mut hmac = match HmacSha1::new_varkey(&decoded_key) {
        Ok(h) => h,
        Err(_) => return Err(YubicoError::InvalidKeyLength),
    };
    hmac.update(input);
    Ok(hmac.finalize())
}

pub fn verify_signature(
    key: &[u8],
    input: &[u8],
    expected: &[u8],
) -> Result<(), YubicoError> {
    let decoded_key = decode(key)?;

    let mut hmac = match HmacSha1::new_varkey(&decoded_key) {
        Ok(h) => h,
        Err(_) => return Err(YubicoError::InvalidKeyLength),
    };
    hmac.update(input);
    hmac.verify(expected).map_err(|_| YubicoError::SignatureMismatch)
}

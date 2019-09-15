use sha1::{Digest, Sha1};
use hmac::Hmac;
use crypto_mac::{Mac, MacResult};
use yubicoerror::YubicoError;
use base64::{decode};

type HmacSha1 = Hmac<Sha1>;

//  1. Apply the HMAC-SHA-1 algorithm on the line as an octet string using the API key as key
pub fn build_signature(key: &[u8], input: &[u8]) -> Result<MacResult<<sha1::Sha1 as Digest>::OutputSize>, YubicoError>
{
    let decoded_key = decode(key)?;

    let mut hmac = match HmacSha1::new_varkey(&decoded_key) {
        Ok(h) => h,
        Err(_) => return Err(YubicoError::InvalidKeyLength)
    };
    hmac.input(input);
    Ok(hmac.result())
}
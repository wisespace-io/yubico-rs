use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use yubicoerror::YubicoError;
use base64::{decode};

const SHA1_DIGEST_SIZE: usize = 20;

/// A secret key for HMAC.
#[derive(Debug)]
pub struct HmacKey([u8; 20]);
impl Drop for HmacKey {
    fn drop(&mut self) {
        for i in self.0.iter_mut() {
            *i = 0;
        }
    }
}

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
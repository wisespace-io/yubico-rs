use std;
use rand::Rng;
use sec::hmac_sha1;

#[derive(Debug)]
pub struct Hmac(pub [u8; 20]);
impl Drop for Hmac {
    fn drop(&mut self) {
        for i in self.0.iter_mut() {
            *i = 0;
        }
    }
}

impl std::ops::Deref for Hmac {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Hmac {
    pub fn check(&self, key: &HmacKey, challenge: &[u8]) -> bool {
        &self.0[..] == hmac_sha1(key, challenge)
    }
}

/// A secret key for HMAC.
#[derive(Debug)]
pub struct HmacKey(pub [u8; 20]);
impl Drop for HmacKey {
    fn drop(&mut self) {
        for i in self.0.iter_mut() {
            *i = 0;
        }
    }
}

impl HmacKey {
    pub fn from_slice(s: &[u8]) -> Self {
        let mut key = HmacKey([0; 20]);
        (&mut key.0).clone_from_slice(s);
        key
    }

    pub fn generate<R:Rng>(mut rng: R) -> Self {
        let mut key = HmacKey([0; 20]);
        for i in key.0.iter_mut() {
            *i = rng.gen()
        }
        key
    }
}
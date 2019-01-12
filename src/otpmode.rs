use std;
use rand::Rng;
use aes;
use aes::block_cipher_trait::BlockCipher;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::generic_array::typenum::U16;
use sec::{ CRC_RESIDUAL_OK, crc16 };
use yubicoerror::YubicoError;

#[repr(C)]
#[repr(packed)]
#[derive(Default)]
pub struct Otp {
    /// The private ID, XORed with the challenge.
    pub uid: [u8; 6],
    /// A counter incremented each time the YubiKey is powered up.
    pub use_counter: u16,
    /// A timestamp, encoded little-endian, starting from the time the YubiKey is powered up.
    pub timestamp: [u8; 3],
    /// A counter incremented with each response.
    pub session_counter: u8,
    /// A random number (not cryptographically strong).
    pub random_number: u16,
    /// CRC of the other fields.
    pub crc: u16,
}

/// A secret key for AES128 / OTP challenge-response.
#[derive(Debug)]
pub struct Aes128Key(pub [u8; 16]);
impl Drop for Aes128Key {
    fn drop(&mut self) {
        for i in self.0.iter_mut() {
            *i = 0;
        }
    }
}

impl Aes128Key {
    pub fn from_slice(s: &[u8]) -> Self {
        let mut key = Aes128Key([0; 16]);
        (&mut key.0).clone_from_slice(s);
        key
    }

    pub fn generate<R:Rng>(mut rng: R) -> Self {
        let mut key = Aes128Key([0; 16]);
        for i in key.0.iter_mut() {
            *i = rng.gen()
        }
        key
    }
}

#[derive(Debug)]
pub struct Aes128Block {
    pub block: GenericArray<u8, U16>,
}

impl Drop for Aes128Block {
    fn drop(&mut self) {
        for i in self.block.iter_mut() {
            *i = 0;
        }
    }
}

impl std::ops::Deref for Aes128Block {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.block
    }
}

impl Aes128Block {
    /// Decrypts an AES block as returned by the YubiKey. The caller
    /// must check that the `uid` field is equal to the known private
    /// id, and that the `(use_counter, session_counter)` is strictly
    /// larger than the last value seen.
    pub fn check(&self, key: &Aes128Key, challenge: &[u8]) -> Result<Otp, YubicoError> {

        let aes_dec = aes::Aes128::new(GenericArray::from_slice(&key.0));
        let mut tmp = Otp::default();
        {
            let tmp =
                unsafe { std::slice::from_raw_parts_mut(&mut tmp as *mut Otp as *mut u8, 16) };
            let mut block_copy = &mut self.block.clone();
            aes_dec.decrypt_block(&mut block_copy);
            tmp.copy_from_slice(block_copy);

            if crc16(&tmp) != CRC_RESIDUAL_OK {
                return Err(YubicoError::WrongCRC);
            }
        }

        for i in 0..6 {
            tmp.uid[i] ^= challenge[i]
        }

        Ok(tmp)
    }
}

#[cfg(any(feature = "online", feature = "online-tokio"))]
extern crate reqwest;
#[cfg(feature = "usb")]
extern crate libusb;

#[macro_use] extern crate structure;
#[macro_use] extern crate url;

extern crate aes_soft as aes;
extern crate base64;
extern crate block_modes;
extern crate crypto_mac;
extern crate hmac;
extern crate rand;
extern crate sha1;
extern crate threadpool;
#[macro_use] extern crate bitflags;
extern crate subtle;
extern crate futures;

#[cfg(feature = "usb")]
mod manager;
pub mod otpmode;
pub mod hmacmode;
pub mod sec;
pub mod config;
#[cfg(feature = "usb")]
pub mod configure;
pub mod yubicoerror;
#[cfg(any(feature = "online", feature = "online-tokio"))]
mod online;

use aes::block_cipher_trait::generic_array::GenericArray;

use config::Command;
#[cfg(feature = "usb")]
use configure::{ DeviceModeConfig };
use hmacmode::{ Hmac };
use otpmode::{ Aes128Block };
use sec::{ CRC_RESIDUAL_OK, crc16 };
#[cfg(feature = "usb")]
use manager::{ Frame, Flags };
use config::{Config, Slot};
use yubicoerror::YubicoError;
#[cfg(feature = "usb")]
use libusb::{Context};

#[cfg(feature = "online")]
pub use online::verify;
#[cfg(feature = "online-tokio")]
pub use online::verify_async;

const VENDOR_ID: u16 = 0x1050;

/// The `Result` type used in this crate.
type Result<T> = ::std::result::Result<T, YubicoError>;

#[derive(Clone)]
pub struct Device {
    pub product_id: u16,
    pub vendor_id: u16
}

pub struct Yubico {
    #[cfg(feature = "usb")]
    context: Context,
}

impl Yubico {
    /// Creates a new Yubico instance.
    pub fn new() -> Self { 
        Yubico {
            #[cfg(feature = "usb")]
            context: Context::new().unwrap(),         
        }
    }

    #[cfg(feature = "usb")]
    pub fn find_yubikey(&mut self) -> Result<Device> {
        for mut device in self.context.devices().unwrap().iter() {
            let descr = device.device_descriptor().unwrap();
            if descr.vendor_id() == VENDOR_ID {
                let device = Device {
                    product_id: descr.product_id(),
                    vendor_id: descr.vendor_id()
                };
                return Ok(device);
            }
        }

        Err(YubicoError::DeviceNotFound)
    }

    #[cfg(feature = "usb")]
    pub fn write_config(&mut self, conf: Config, device_config: &mut DeviceModeConfig) -> Result<()> {
        let d = device_config.to_frame(conf.command);
        let mut buf = [0; 8];

        match manager::open_device(&mut self.context, conf.vendor_id, conf.product_id) {
            Ok(mut handle) => {
                manager::wait(&mut handle, |f| !f.contains(Flags::SLOT_WRITE_FLAG), &mut buf)?;

                // TODO: Should check version number.

                manager::write_frame(&mut handle, &d)?;
                manager::wait(&mut handle, |f| !f.contains(Flags::SLOT_WRITE_FLAG), &mut buf)?;

                Ok(())
            },
            Err(error) => Err(error)
        }
    }

    #[cfg(feature = "usb")]
    pub fn read_serial_number(&mut self, conf: Config) -> Result<u32> {

        match manager::open_device(&mut self.context, conf.vendor_id, conf.product_id) {
            Ok(mut handle) => {
                let mut challenge = [0; 64];
                let mut command = Command::DeviceSerial;

                let d = Frame::new(challenge, command); // FixMe: do not need a challange
                let mut buf = [0; 8];
                manager::wait(&mut handle, |f| !f.contains(manager::Flags::SLOT_WRITE_FLAG), &mut buf)?;
 
                manager::write_frame(&mut handle, &d)?;

                // Read the response.
                let mut response = [0; 36];
                manager::read_response(&mut handle, &mut response)?;

                // Check response.
                if crc16(&response[..6]) != CRC_RESIDUAL_OK {
                    return Err(YubicoError::WrongCRC);
                }

                let serial = structure!("2I").unpack(response[..8].to_vec())?;

                Ok(serial.0)
            },
            Err(error) => Err(error)
        }
    }

    #[cfg(feature = "usb")]
    pub fn challenge_response_hmac(&mut self, chall: &[u8], conf: Config) -> Result<Hmac> {
        let mut hmac = Hmac([0; 20]);

        match manager::open_device(&mut self.context, conf.vendor_id, conf.product_id) {
            Ok(mut handle) => {
                let mut challenge = [0; 64];
                
                if conf.variable && chall.last() == Some(&0) {
                    challenge = [0xff; 64];
                }

                let mut command = Command::ChallengeHmac1;
                if let Slot::Slot2 = conf.slot {
                    command = Command::ChallengeHmac2;
                }

                (&mut challenge[..chall.len()]).copy_from_slice(chall);
                let d = Frame::new(challenge, command);
                let mut buf = [0; 8];
                manager::wait(&mut handle, |f| !f.contains(manager::Flags::SLOT_WRITE_FLAG), &mut buf)?;
 
                manager::write_frame(&mut handle, &d)?;

                // Read the response.
                let mut response = [0; 36];
                manager::read_response(&mut handle, &mut response)?;

                // Check response.
                if crc16(&response[..22]) != CRC_RESIDUAL_OK {
                    return Err(YubicoError::WrongCRC);
                }

                hmac.0.clone_from_slice(&response[..20]);

                Ok(hmac)
            },
            Err(error) => Err(error)
        }
    }
    
    #[cfg(feature = "usb")]   
    pub fn challenge_response_otp(&mut self, chall: &[u8], conf: Config) -> Result<Aes128Block> {
        let mut block = Aes128Block { block: GenericArray::clone_from_slice(&[0; 16]) };

        match manager::open_device(&mut self.context, conf.vendor_id, conf.product_id) {
            Ok(mut handle) => {
                let mut challenge = [0; 64];
                //(&mut challenge[..6]).copy_from_slice(chall);

                let mut command = Command::ChallengeOtp1;
                if let Slot::Slot2 = conf.slot {
                    command = Command::ChallengeOtp2;
                }

                (&mut challenge[..chall.len()]).copy_from_slice(chall);
                let d = Frame::new(challenge, command);
                let mut buf = [0; 8];
               
                let mut response = [0; 36];
                manager::wait(&mut handle, |f| !f.contains(manager::Flags::SLOT_WRITE_FLAG), &mut buf)?;
                manager::write_frame(&mut handle, &d)?;
                manager::read_response(&mut handle, &mut response)?;

                // Check response.
                if crc16(&response[..18]) != CRC_RESIDUAL_OK {
                    return Err(YubicoError::WrongCRC);
                }

                block.block.copy_from_slice(&response[..16]);

                Ok(block)
            },
            Err(error) => Err(error)
        }
    }
}
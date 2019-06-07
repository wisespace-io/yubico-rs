#[cfg(feature = "online")]
extern crate reqwest;
#[cfg(feature = "usb")]
extern crate libusb;

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

#[cfg(feature = "usb")]
mod manager;
pub mod otpmode;
pub mod hmacmode;
pub mod sec;
pub mod config;
#[cfg(feature = "usb")]
pub mod configure;
pub mod yubicoerror;

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
use reqwest::header::USER_AGENT;

use std::io::prelude::*;
use base64::{encode, decode};
use rand::Rng;
use rand::rngs::OsRng;
use rand::distributions::Alphanumeric;
use threadpool::ThreadPool;
use std::collections::BTreeMap;
use std::sync::mpsc::{ channel, Sender };
use url::percent_encoding::{utf8_percent_encode, SIMPLE_ENCODE_SET};

const VENDOR_ID: u16 = 0x1050;

define_encode_set! {
    /// This encode set is used in the URL parser for query strings.
    pub QUERY_ENCODE_SET = [SIMPLE_ENCODE_SET] | {'+', '='}
}

/// The `Result` type used in this crate.
type Result<T> = ::std::result::Result<T, YubicoError>;

enum Response {
    Signal(Result<String>),
}

#[derive(Clone)]
pub struct Request {
    otp: String,
    nonce: String,
    signature: String,
    query: String,
}

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
            Some(mut handle) => {
                manager::wait(&mut handle, |f| !f.contains(Flags::SLOT_WRITE_FLAG), &mut buf)?;

                // TODO: Should check version number.

                manager::write_frame(&mut handle, &d)?;
                manager::wait(&mut handle, |f| !f.contains(Flags::SLOT_WRITE_FLAG), &mut buf)?;

                Ok(())
            },
            None => Err(YubicoError::OpenDeviceError)
        }
    }

    #[cfg(feature = "usb")]
    pub fn challenge_response_hmac(&mut self, chall: &[u8], conf: Config) -> Result<Hmac> {
        let mut hmac = Hmac([0; 20]);

        match manager::open_device(&mut self.context, conf.vendor_id, conf.product_id) {
            Some(mut handle) => {
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
            None => Err(YubicoError::OpenDeviceError)
        }
    }
    
    #[cfg(feature = "usb")]   
    pub fn challenge_response_otp(&mut self, chall: &[u8], conf: Config) -> Result<Aes128Block> {
        let mut block = Aes128Block { block: GenericArray::clone_from_slice(&[0; 16]) };

        match manager::open_device(&mut self.context, conf.vendor_id, conf.product_id) {
            Some(mut handle) => {
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
            None => Err(YubicoError::OpenDeviceError)
        }
    }
    
    // Verify a provided OTP
    #[cfg(feature = "online")]
    pub fn verify<S>(&self, otp: S, config: Config) -> Result<String>
        where S: Into<String>
    {
        let request = self.build_request(otp, &config)?;

        let number_of_hosts = config.api_hosts.len();
        let pool = ThreadPool::new(number_of_hosts);
        let (tx, rx) = channel();

        for api_host in config.api_hosts {
            let tx = tx.clone();
            let request = request.clone();
            let cloned_key = config.key.clone();
            pool.execute(move|| {
                let handler = RequestHandler::new(cloned_key.to_vec());
                handler.process(tx, api_host.as_str(), request);
            });
        }

        let mut success = false;
        let mut results: Vec<Result<String>> = Vec::new();
        for _ in 0..number_of_hosts {
            match rx.recv() {
                Ok(Response::Signal(result)) =>  {
                    match result {
                        Ok(_) => {
                            results.truncate(0);
                            success = true;
                        },
                        Err(_) => {
                            results.push(result);
                        },
                    }
                },
                Err(e) => {
                    results.push(Err(YubicoError::ChannelError(e)));
                    break
                },
            }
        }

        if success {
            Ok("The OTP is valid.".into())
        } else {
            let result = results.pop().unwrap();
            result
        }
    }

    #[cfg(feature = "online")]
    fn build_request<S>(&self, otp: S, config: &Config) -> Result<Request>
        where S: Into<String> {
        let str_otp = otp.into();
        match self.printable_characters(str_otp.clone()) {
            false => Err(YubicoError::BadOTP),
            _ => {
                let nonce: String = self.generate_nonce();
                let mut query = format!("id={}&nonce={}&otp={}&sl=secure", config.client_id, nonce, str_otp);

                match sec::build_signature(config.key.clone(), query.clone()) {
                    Ok(signature) => {
                        // Base 64 encode the resulting value according to RFC 4648
                        let encoded_signature = encode(&signature.code());

                        // Append the value under key h to the message.
                        let signature_param = format!("&h={}", encoded_signature);
                        let encoded = utf8_percent_encode(signature_param.as_ref(), QUERY_ENCODE_SET).collect::<String>();
                        query.push_str(encoded.as_ref());

                        Ok(Request {
                            otp: str_otp,
                            nonce,
                            signature: encoded_signature,
                            query,
                        })
                    },
                    Err(error) => {
                        return Err(error)
                    }
                }
            },
        }
    }

    // Recommendation is that clients only check that the input consists of 32-48 printable characters
    fn printable_characters(&self, otp: String) -> bool {
        for c in otp.chars() {
            if !c.is_ascii() {
                return false;
            }
        }
        otp.len() > 32 && otp.len() < 48
    }

    fn generate_nonce(&self) -> String {
        OsRng::new().unwrap()
                    .sample_iter(&Alphanumeric)
                    .take(40)
                    .collect()
    }
}

#[cfg(feature = "online")]
pub struct RequestHandler {
    key: Vec<u8>,
}

#[cfg(feature = "online")]
impl RequestHandler {
    pub fn new(key: Vec<u8>) -> Self {
        RequestHandler {
            key: key
        }
    }

    fn process(&self, sender: Sender<Response>, api_host: &str, request: Request) {
        let url = format!("{}?{}", api_host, request.query);
        match self.get(url) {
            Ok(raw_response) => {
                let result = self.verify_response(request, raw_response)
                    .map(|()| "The OTP is valid.".to_owned());
                sender.send(Response::Signal(result)).unwrap();
            },
            Err(e) => {
                sender.send(Response::Signal(Err(e))).unwrap();
            }
        }
    }

    fn verify_response(&self, request: Request, raw_response: String)
        -> Result<()>
    {
        let response_map: BTreeMap<String, String> = self.build_response_map(raw_response);

        let status: &str = &*response_map.get("status").unwrap();

        if let "OK" = status {
            // Signature located in the response must match the signature we will build
            let signature_response : &str = &*response_map.get("h").unwrap();
            if !self.is_same_signature(signature_response, response_map.clone()) {
                return Err(YubicoError::SignatureMismatch);
            }

            // Check if "otp" in the response is the same as the "otp" supplied in the request.
            let otp_response : &str = &*response_map.get("otp").unwrap();
            if !request.otp.contains(otp_response) {
                return Err(YubicoError::OTPMismatch);
            }

            // Check if "nonce" in the response is the same as the "nonce" supplied in the request.
            let nonce_response : &str = &*response_map.get("nonce").unwrap();
            if !request.nonce.contains(nonce_response) {
                return Err(YubicoError::NonceMismatch);
            }

            Ok(())
        } else {
            // Check the status of the operation
            match status {
                "BAD_OTP" => Err(YubicoError::BadOTP),
                "REPLAYED_OTP" => Err(YubicoError::ReplayedOTP),
                "BAD_SIGNATURE" => Err(YubicoError::BadSignature),
                "MISSING_PARAMETER" => Err(YubicoError::MissingParameter),
                "NO_SUCH_CLIENT" => Err(YubicoError::NoSuchClient),
                "OPERATION_NOT_ALLOWED" => Err(YubicoError::OperationNotAllowed),
                "BACKEND_ERROR" => Err(YubicoError::BackendError),
                "NOT_ENOUGH_ANSWERS" => Err(YubicoError::NotEnoughAnswers),
                "REPLAYED_REQUEST" => Err(YubicoError::ReplayedRequest),
                _ => Err(YubicoError::UnknownStatus)
            }
        }
    }

    // Remove the signature itself from the values over for verification.
    // Sort the key/value pairs.
    fn is_same_signature(&self, signature_response: &str, mut response_map: BTreeMap<String, String>) -> bool {
        response_map.remove("h");

        let mut query = String::new();
        for (key, value) in response_map {
            let param = format!("{}={}&", key, value);
            query.push_str(param.as_ref());
        }
        query.pop(); // remove last &

        if let Ok(signature) = sec::build_signature(self.key.clone(), query.clone()) {
            let decoded_signature = &decode(signature_response).unwrap()[..];

            use subtle::ConstantTimeEq;

            signature.code().ct_eq(decoded_signature).into()
        } else {
            return false;
        }
    }

    fn build_response_map(&self, result: String) -> BTreeMap<String, String> {
        let mut parameters = BTreeMap::new();
        for line in result.lines() {
            let param: Vec<&str> = line.splitn(2, '=').collect();
            if param.len() > 1 {
                parameters.insert(param[0].to_string(), param[1].to_string());
            }
        }
        parameters
    }

    pub fn get(&self, url: String) -> Result<String> {
        let client = reqwest::Client::new();
        let mut response = client
            .get(url.as_str())
            .header(USER_AGENT, "github.com/wisespace-io/yubico-rs")
            .send()?;

        let mut data = String::new();
        response.read_to_string(&mut data)?;

        Ok(data)
    }
}

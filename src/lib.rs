#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

#[macro_use] extern crate url;
extern crate reqwest;
extern crate base64;
extern crate crypto;
extern crate rand;
extern crate libusb;
extern crate threadpool;
#[macro_use] extern crate bitflags;

mod otpmode;
mod manager;
mod hmacmode;

pub mod sec;
pub mod config;
pub mod configure;
pub mod yubicoerror;

use configure::{ DeviceConfig };
use hmacmode::{ Hmac };
use otpmode::{ Aes128Block };
use sec::{ CRC_RESIDUAL_OK, crc16 };
use manager::{ Frame, Flags };
use config::{Config, Slot, Mode};
use yubicoerror::YubicoError;
use libusb::{Context};
use reqwest::header::{Headers, UserAgent};
use std::io::prelude::*;
use base64::{encode, decode};
use rand::{OsRng, Rng};
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
    context: Context,
}

impl Yubico {
    /// Creates a new Yubico instance.
    pub fn new() -> Self { 
        Yubico {
            context: Context::new().unwrap(),         
        }
    }

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

    // NOTE: Don't use it yet, it needs to be tested
    pub fn write_config(&mut self, conf: Config, config: &mut DeviceConfig) -> Result<()> {
        let mut command = manager::Command::ChallengeHmac1;
        if let Slot::Slot2 = conf.slot {
            command = manager::Command::ChallengeHmac2;
        }

        let d = config.to_frame(command);
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

    pub fn challenge_response(&mut self, chall: &[u8], conf: Config) -> Result<(Hmac, Aes128Block)> {     
        if let Mode::Sha1 = conf.mode {
            self.challenge_response_sha1(chall, conf)     
        } else {
            self.challenge_response_otp(chall, conf)
        }
    }

    fn challenge_response_sha1(&mut self, chall: &[u8], conf: Config) -> Result<(Hmac, Aes128Block)> {
        let mut hmac = Hmac([0; 20]);
        let block = Aes128Block { block: [0; 16] };

        match manager::open_device(&mut self.context, conf.vendor_id, conf.product_id) {
            Some(mut handle) => {
                let mut challenge = [0; 64];
                
                if conf.variable && chall.last() == Some(&0) {
                    challenge = [0xff; 64];
                }

                let mut command = manager::Command::ChallengeHmac1;
                if let Slot::Slot2 = conf.slot {
                    command = manager::Command::ChallengeHmac2;
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

                Ok((hmac, block))
            },
            None => Err(YubicoError::OpenDeviceError)
        }
    }
    
    fn challenge_response_otp(&mut self, chall: &[u8], conf: Config) -> Result<(Hmac, Aes128Block)> {
        let hmac = Hmac([0; 20]);
        let mut block = Aes128Block { block: [0; 16] };

        match manager::open_device(&mut self.context, conf.vendor_id, conf.product_id) {
            Some(mut handle) => {
                let mut challenge = [0; 64];
                (&mut challenge[..6]).copy_from_slice(chall);

                let mut command = manager::Command::ChallengeOtp1;
                if let Slot::Slot2 = conf.slot {
                    command = manager::Command::ChallengeOtp2;
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

                Ok((hmac, block))
            },
            None => Err(YubicoError::OpenDeviceError)
        }
    }
    
    // Verify a provided OTP
    pub fn verify<S>(&self, otp: S, config: Config) -> Result<String>
        where S: Into<String>
    {
        let str_otp = otp.into();
        match self.printable_characters(str_otp.clone()) {
            false => Err(YubicoError::BadOTP),
            _ => {                
                let nonce: String = self.generate_nonce();
                let mut query = format!("id={}&nonce={}&otp={}&sl=secure", config.client_id, nonce, str_otp);
       
                match sec::build_signature(config.key.clone(), query.clone()) {
                    Ok(signature) => {
                        // Base 64 encode the resulting value according to RFC 4648
                        let encoded_signature = encode(signature.code());

                        // Append the value under key h to the message.
                        let signature_param = format!("&h={}", encoded_signature);
                        let encoded = utf8_percent_encode(signature_param.as_ref(), QUERY_ENCODE_SET).collect::<String>();
                        query.push_str(encoded.as_ref());

                        let request = Request {otp: str_otp, nonce: nonce, signature: encoded_signature, query: query};

                        let number_of_hosts = config.api_hosts.len();
                        let pool = ThreadPool::new(number_of_hosts);
                        let (tx, rx) = channel();

                        for api_host in config.api_hosts {
                            let tx = tx.clone();
                            let request = request.clone();
                            let cloned_key = config.key.clone();
                            pool.execute(move|| { 
                                let handler = RequestHandler::new(cloned_key.to_vec());
                                handler.process(tx, api_host.as_str(), request) 
                            });
                        }

                        let mut results: Vec<Result<String>> = Vec::new();
                        for _ in 0..number_of_hosts {
                            match rx.recv() {
                                Ok(Response::Signal(result)) =>  {
                                    match result {
                                        Ok(_) => {
                                            results.truncate(0);
                                            break
                                        },
                                        Err(_) => results.push(result),
                                    }
                                },
                                Err(e) => {
                                    results.push(Err(YubicoError::ChannelError(e)));
                                    break
                                },
                            }
                        }

                        if results.len() == 0 {
                            Ok("The OTP is valid.".into())
                        } else {
                            let result = results.pop().unwrap();
                            result
                        }
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
                    .gen_ascii_chars()
                    .take(40)
                    .collect()
    }    
}

pub struct RequestHandler {
    key: Vec<u8>,   
}

impl RequestHandler {
    pub fn new(key: Vec<u8>) -> Self {
        RequestHandler {
            key: key
        }
    }

    fn process(&self, sender: Sender<Response>, api_host: &str, request: Request) {
        let url = format!("{}?{}", api_host, request.query);
        match self.get(url) {
            Ok(result) => {
                let response_map: BTreeMap<String, String> = self.build_response_map(result);

                // Signature located in the response must match the signature we will build
                let signature_response : &str = &*response_map.get("h").unwrap();
                if !self.is_same_signature(signature_response, response_map.clone()) {
                    sender.send(Response::Signal(Err(YubicoError::SignatureMismatch))).unwrap();
                    return;
                }

                // Check if "otp" in the response is the same as the "otp" supplied in the request.
                let otp_response : &str = &*response_map.get("otp").unwrap();
                if !request.otp.contains(otp_response) {
                    sender.send(Response::Signal(Err(YubicoError::OTPMismatch))).unwrap();
                    return;
                }

                // Check if "nonce" in the response is the same as the "nonce" supplied in the request.
                let nonce_response : &str = &*response_map.get("nonce").unwrap();
                if !request.nonce.contains(nonce_response) {
                    sender.send(Response::Signal(Err(YubicoError::NonceMismatch))).unwrap();
                    return;
                }

                // Check the status of the operation
                let status: &str = &*response_map.get("status").unwrap();
                match status {
                    "OK" => sender.send(Response::Signal(Ok("The OTP is valid.".to_owned()))).unwrap(),
                    "BAD_OTP" => sender.send(Response::Signal(Err(YubicoError::BadOTP))).unwrap(),
                    "REPLAYED_OTP" => sender.send(Response::Signal(Err(YubicoError::ReplayedOTP))).unwrap(),
                    "BAD_SIGNATURE" => sender.send(Response::Signal(Err(YubicoError::BadSignature))).unwrap(),
                    "MISSING_PARAMETER" => sender.send(Response::Signal(Err(YubicoError::MissingParameter))).unwrap(),
                    "NO_SUCH_CLIENT" => sender.send(Response::Signal(Err(YubicoError::NoSuchClient))).unwrap(),
                    "OPERATION_NOT_ALLOWED" => sender.send(Response::Signal(Err(YubicoError::OperationNotAllowed))).unwrap(),
                    "BACKEND_ERROR" => sender.send(Response::Signal(Err(YubicoError::BackendError))).unwrap(),
                    "NOT_ENOUGH_ANSWERS" => sender.send(Response::Signal(Err(YubicoError::NotEnoughAnswers))).unwrap(),
                    "REPLAYED_REQUEST" => sender.send(Response::Signal(Err(YubicoError::ReplayedRequest))).unwrap(),
                    _ => sender.send(Response::Signal(Err(YubicoError::UnknownStatus))).unwrap()
                }
            },
            Err(e) => {
                sender.send( Response::Signal(Err(e)) ).unwrap();
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

            crypto::util::fixed_time_eq(signature.code(), decoded_signature)
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
        let mut custon_headers = Headers::new();

        custon_headers.set(UserAgent::new("github.com/wisespace-io/yubico-rs"));

        let client = reqwest::Client::new();
        let mut response = client
            .get(url.as_str())
            .headers(custon_headers)
            .send()?;

        let mut data = String::new();
        response.read_to_string(&mut data)?;

        Ok(data)
    }
}
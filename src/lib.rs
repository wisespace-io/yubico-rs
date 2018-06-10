#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

#[macro_use] extern crate url;
extern crate reqwest;
extern crate base64;
extern crate crypto;
extern crate rand;
extern crate hidapi;
extern crate threadpool;

pub mod config;
pub mod yubicoerror;

use config::Config;
use yubicoerror::YubicoError;
use hidapi::HidDeviceInfo;
use reqwest::header::{Headers, UserAgent};
use std::io::prelude::*;
use base64::{encode, decode};
use crypto::mac::{Mac, MacResult};
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use rand::{OsRng, Rng};
use threadpool::ThreadPool;
use std::collections::BTreeMap;
use std::sync::mpsc::{ channel, Sender };
use url::percent_encoding::{utf8_percent_encode, SIMPLE_ENCODE_SET};

const VENDOR_ID: u16 = 0x1050;

pub enum Slot {
    Slot1,
    Slot2,
}

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
pub struct Yubico {
    client_id: String,
    key: Vec<u8>,
}

impl Yubico {
    /// Creates a new Yubico instance.
    pub fn new<C, K>(client_id: C, key: K) -> Self
        where C: Into<String>, K: Into<String>
    { 
        Yubico {
            client_id: client_id.into(),
            key: key.into().into_bytes(),
        }
    }

    pub fn find_yubikey(&self) -> Result<HidDeviceInfo> {
        let mut devices: Vec<HidDeviceInfo> = Vec::new();

        let api = hidapi::HidApi::new().unwrap();
        for device in &api.devices() {
            if device.vendor_id == VENDOR_ID {
                devices.push(device.clone());
                return Ok(devices[0].clone());
            }
        }

        Err(YubicoError::DeviceNotFound)
    }

    pub fn challenge_response(&self, challenge: &[u8], device: HidDeviceInfo, slot: Slot) {

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
                let mut query = format!("id={}&nonce={}&otp={}&sl=secure", self.client_id, nonce, str_otp);

                match self.build_signature(query.clone()) {
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
                            let self_clone = self.clone(); //threads can't reference values which are not owned by the thread.
                            pool.execute(move|| { 
                                self_clone.process(tx, api_host.as_str(), request) 
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

    //  1. Apply the HMAC-SHA-1 algorithm on the line as an octet string using the API key as key
    fn build_signature(&self, query: String) -> Result<MacResult> {
        let decoded_key = decode(&self.key)?;

        let mut hmac = Hmac::new(Sha1::new(), &decoded_key);
        hmac.input(query.as_bytes());
        Ok(hmac.result())
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

        if let Ok(signature) = self.build_signature(query.clone()) {
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

    fn generate_nonce(&self) -> String {
        OsRng::new().unwrap()
                    .gen_ascii_chars()
                    .take(40)
                    .collect()
    }
}
#[macro_use] extern crate url;
#[macro_use] extern crate hyper;
extern crate hyper_native_tls;
extern crate base64;
extern crate crypto;
extern crate rand;
extern crate threadpool;

pub mod yubicoerror;

use std::ascii::AsciiExt;
use yubicoerror::YubicoError;
use hyper::net::HttpsConnector;
use hyper_native_tls::NativeTlsClient;
use hyper::header::{Headers};
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

define_encode_set! {
    /// This encode set is used in the URL parser for query strings.
    pub QUERY_ENCODE_SET = [SIMPLE_ENCODE_SET] | {'+', '='}
}

static API1_HOST : &'static str = "https://api.yubico.com/wsapi/2.0/verify";
static API2_HOST : &'static str = "https://api2.yubico.com/wsapi/2.0/verify";
static API3_HOST : &'static str = "https://api3.yubico.com/wsapi/2.0/verify";
static API4_HOST : &'static str = "https://api4.yubico.com/wsapi/2.0/verify";
static API5_HOST : &'static str = "https://api5.yubico.com/wsapi/2.0/verify";

header! { (UserAgent, "User-Agent") => [String] }

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
    pub fn new(client_id: String, key: String) -> Self {
        Yubico {
            client_id: client_id,
            key: decode(&key[..]).unwrap(),
        }
    }

    // Verify a provided OTP
    pub fn verify(&self, otp: String) -> Result<String> {
        match self.printable_characters(otp.clone()) {
            false => Err(YubicoError::BadOTP),
            _ => {                
                let nonce: String = self.generate_nonce();
                let mut query = format!("id={}&nonce={}&otp={}&sl=secure", self.client_id, nonce, otp);

                let signature = self.build_signature(query.clone());
                // Base 64 encode the resulting value according to RFC 4648
                let encoded_signature = encode(signature.code());

                // Append the value under key h to the message.
                let signature_param = format!("&h={}", encoded_signature);
                let encoded = utf8_percent_encode(signature_param.as_ref(), QUERY_ENCODE_SET).collect::<String>();
                query.push_str(encoded.as_ref());

                let request = Request {otp: otp, nonce: nonce, signature: encoded_signature, query: query};

                let pool = ThreadPool::new(3);
                let (tx, rx) = channel();
                let api_hosts = vec![API1_HOST, API2_HOST, API3_HOST, API4_HOST, API5_HOST];
                for api_host in api_hosts {
                    let tx = tx.clone();
                    let request = request.clone();
                    let self_clone = self.clone(); //threads can't reference values which are not owned by the thread.
                    pool.execute(move|| { self_clone.process(tx, api_host, request) });
                }

                let mut results: Vec<Result<String>> = Vec::new();
                for _ in 0..5 {
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
        }
    }

    //  1. Apply the HMAC-SHA-1 algorithm on the line as an octet string using the API key as key
    fn build_signature(&self, query: String) -> MacResult {
        let mut hmac = Hmac::new(Sha1::new(), &self.key[..]);
        hmac.input(query.as_bytes());
        hmac.result()
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

        let signature = self.build_signature(query.clone());
        let decoded_signature = &decode(signature_response).unwrap()[..];

        crypto::util::fixed_time_eq(signature.code(), decoded_signature)
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
        let ssl = NativeTlsClient::new().unwrap();
        let connector = HttpsConnector::new(ssl);
        let client = hyper::Client::with_connector(connector);

        let mut custom_headers = Headers::new();
        custom_headers.set(UserAgent("github.com/wisespace-io/yubico-rs".to_owned()));

        let mut response = String::new();
        let mut res = try!(client.get(&url).headers(custom_headers).send());
        try!(res.read_to_string(&mut response));

        Ok(response)
    }

    fn generate_nonce(&self) -> String {
        OsRng::new().unwrap()
                    .gen_ascii_chars()
                    .take(40)
                    .collect()
    }
}
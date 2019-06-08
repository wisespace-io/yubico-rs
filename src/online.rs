use std::collections::BTreeMap;
use std::io::Read;
use std::sync::mpsc::{channel, Sender};

use base64::{decode, encode};
use rand::distributions::Alphanumeric;
use rand::Rng;
use rand::rngs::OsRng;
use reqwest::header::USER_AGENT;
use threadpool::ThreadPool;
use url::percent_encoding::{SIMPLE_ENCODE_SET, utf8_percent_encode};

use ::{Request, sec};
use config::Config;
use yubicoerror::YubicoError;

use crate::Result;

define_encode_set! {
    /// This encode set is used in the URL parser for query strings.
    pub QUERY_ENCODE_SET = [SIMPLE_ENCODE_SET] | {'+', '='}
}

pub fn verify<S>(otp: S, config: Config) -> Result<String>
    where S: Into<String>
{
    let request = build_request(otp, &config)?;

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

enum Response {
    Signal(Result<String>),
}

fn build_request<S>(otp: S, config: &Config) -> Result<Request>
    where S: Into<String> {
    let str_otp = otp.into();
    match printable_characters(str_otp.clone()) {
        false => Err(YubicoError::BadOTP),
        _ => {
            let nonce: String = generate_nonce();
            let mut query = format!("id={}&nonce={}&otp={}&sl=secure", config.client_id, nonce, str_otp);

            match sec::build_signature(&config.key, query.clone()) {
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
fn printable_characters(otp: String) -> bool {
    for c in otp.chars() {
        if !c.is_ascii() {
            return false;
        }
    }
    otp.len() > 32 && otp.len() < 48
}

fn generate_nonce() -> String {
    OsRng::new().unwrap()
        .sample_iter(&Alphanumeric)
        .take(40)
        .collect()
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
            Ok(raw_response) => {
                let result = verify_response(request, raw_response, &self.key)
                    .map(|()| "The OTP is valid.".to_owned());
                sender.send(Response::Signal(result)).unwrap();
            },
            Err(e) => {
                sender.send(Response::Signal(Err(e))).unwrap();
            }
        }
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

fn verify_response(
    request: Request,
    raw_response: String,
    key: &[u8],
)
                   -> Result<()>
{
    let response_map: BTreeMap<String, String> = build_response_map(raw_response);

    let status: &str = &*response_map.get("status").unwrap();

    if let "OK" = status {
        // Signature located in the response must match the signature we will build
        let signature_response : &str = &*response_map.get("h").unwrap();
        if !is_same_signature(signature_response, response_map.clone(), key) {
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
fn is_same_signature(
    signature_response: &str,
    mut response_map: BTreeMap<String, String>,
    key: &[u8],
) -> bool {
    response_map.remove("h");

    let mut query = String::new();
    for (key, value) in response_map {
        let param = format!("{}={}&", key, value);
        query.push_str(param.as_ref());
    }
    query.pop(); // remove last &

    if let Ok(signature) = sec::build_signature(key, query.clone()) {
        let decoded_signature = &decode(signature_response).unwrap()[..];

        use subtle::ConstantTimeEq;

        signature.code().ct_eq(decoded_signature).into()
    } else {
        return false;
    }
}

fn build_response_map(result: String) -> BTreeMap<String, String> {
    let mut parameters = BTreeMap::new();
    for line in result.lines() {
        let param: Vec<&str> = line.splitn(2, '=').collect();
        if param.len() > 1 {
            parameters.insert(param[0].to_string(), param[1].to_string());
        }
    }
    parameters
}

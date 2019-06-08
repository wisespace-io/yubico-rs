mod sync;

use std::collections::BTreeMap;

use base64::{decode, encode};
use rand::distributions::Alphanumeric;
use rand::Rng;
use rand::rngs::OsRng;
use url::percent_encoding::{SIMPLE_ENCODE_SET, utf8_percent_encode};

use ::{Request, sec};
use yubicoerror::YubicoError;

use crate::Result;

pub use online::sync::verify;
use config::Config;

define_encode_set! {
    /// This encode set is used in the URL parser for query strings.
    pub QUERY_ENCODE_SET = [SIMPLE_ENCODE_SET] | {'+', '='}
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

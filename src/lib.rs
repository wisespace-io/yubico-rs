#[cfg(feature = "online-tokio")]
pub mod async_verifier;
pub mod config;
mod sec;
pub mod sync_verifier;
pub mod yubicoerror;

use std::collections::BTreeMap;

use base64::{decode, encode};
use config::Config;
use rand::distributions::Alphanumeric;
use rand::rngs::OsRng;
use rand::Rng;
use url::percent_encoding::{define_encode_set, utf8_percent_encode, SIMPLE_ENCODE_SET};
use yubicoerror::YubicoError;

#[cfg(feature = "online-tokio")]
pub use async_verifier::verify_async;
pub use sync_verifier::verify;

type Result<T> = ::std::result::Result<T, YubicoError>;

define_encode_set! {
    /// This encode set is used in the URL parser for query strings.
    pub QUERY_ENCODE_SET = [SIMPLE_ENCODE_SET] | {'+', '='}
}

#[derive(Clone)]
pub struct Request {
    query: String,
    response_verifier: ResponseVerifier,
}

impl Request {
    fn build_url(&self, for_api_host: &str) -> String {
        format!("{}?{}", for_api_host, self.query)
    }
}

#[derive(Clone)]
pub struct ResponseVerifier {
    otp: String,
    nonce: String,
    key: Vec<u8>,
}

impl ResponseVerifier {
    fn verify_response(&self, raw_response: String) -> Result<()> {
        let response_map: BTreeMap<String, String> = build_response_map(raw_response);

        let status: &str = &*response_map.get("status").unwrap();

        if let "OK" = status {
            // Signature located in the response must match the signature we will build
            let signature_response: &str = &*response_map
                .get("h")
                .ok_or_else(|| YubicoError::InvalidResponse)?;
            if !is_same_signature(signature_response, response_map.clone(), &self.key) {
                return Err(YubicoError::SignatureMismatch);
            }

            // Check if "otp" in the response is the same as the "otp" supplied in the request.
            let otp_response: &str = &*response_map
                .get("otp")
                .ok_or_else(|| YubicoError::InvalidResponse)?;
            if !self.otp.eq(otp_response) {
                return Err(YubicoError::OTPMismatch);
            }

            // Check if "nonce" in the response is the same as the "nonce" supplied in the request.
            let nonce_response: &str = &*response_map
                .get("nonce")
                .ok_or_else(|| YubicoError::InvalidResponse)?;
            if !self.nonce.eq(nonce_response) {
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
                _ => Err(YubicoError::UnknownStatus),
            }
        }
    }
}

fn build_request<S>(otp: S, config: &Config) -> Result<Request>
where
    S: Into<String>,
{
    let str_otp = otp.into();

    // A Yubikey can be configured to add line ending chars, or not.
    let str_otp = str_otp.trim().to_string();

    if printable_characters(&str_otp) {
        let nonce: String = generate_nonce();
        let mut query = format!(
            "id={}&nonce={}&otp={}&sl={}",
            config.client_id, nonce, str_otp, config.sync_level
        );

        match sec::build_signature(&config.key, query.as_bytes()) {
            Ok(signature) => {
                // Base 64 encode the resulting value according to RFC 4648
                let encoded_signature = encode(&signature.code());

                // Append the value under key h to the message.
                let signature_param = format!("&h={}", encoded_signature);
                let encoded = utf8_percent_encode(signature_param.as_ref(), QUERY_ENCODE_SET)
                    .collect::<String>();
                query.push_str(encoded.as_ref());

                let verifier = ResponseVerifier {
                    otp: str_otp,
                    nonce,
                    key: config.key.clone(),
                };

                let request = Request {
                    query,
                    response_verifier: verifier,
                };

                Ok(request)
            }
            Err(error) => Err(error),
        }
    } else {
        Err(YubicoError::BadOTP)
    }
}

// Recommendation is that clients only check that the input consists of 32-48 printable characters
fn printable_characters(otp: &str) -> bool {
    for c in otp.chars() {
        if !c.is_ascii() {
            return false;
        }
    }
    otp.len() > 32 && otp.len() < 48
}

fn generate_nonce() -> String {
    OsRng::new()
        .unwrap()
        .sample_iter(&Alphanumeric)
        .take(40)
        .collect()
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

    if let Ok(signature) = sec::build_signature(key, query.as_bytes()) {
        let decoded_signature = &decode(signature_response).unwrap()[..];

        use subtle::ConstantTimeEq;

        signature.code().ct_eq(decoded_signature).into()
    } else {
        false
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

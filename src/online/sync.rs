use std::io::Read;
use std::sync::mpsc::{channel, Sender};

use reqwest::header::USER_AGENT;
use threadpool::ThreadPool;

use config::Config;
use online::{build_request, verify_response};
use Request;
use Result;
use yubicoerror::YubicoError;


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
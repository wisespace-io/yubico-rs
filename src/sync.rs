use std::io::Read;
use std::sync::mpsc::{channel, Sender};

use reqwest::header::USER_AGENT;
use threadpool::ThreadPool;

use crate::build_request;
use crate::Request;
use crate::Result;
use config::Config;
use yubicoerror::YubicoError;

pub fn verify<S>(otp: S, config: Config) -> Result<String>
where
    S: Into<String>,
{
    let request = build_request(otp, &config)?;

    let number_of_hosts = config.api_hosts.len();
    let pool = ThreadPool::new(number_of_hosts);
    let (tx, rx) = channel();

    for api_host in config.api_hosts {
        let tx = tx.clone();
        let request = request.clone();
        let user_agent = config.user_agent.clone();
        pool.execute(move || {
            process(tx, api_host.as_str(), &request, user_agent);
        });
    }

    let mut success = false;
    let mut results: Vec<Result<String>> = Vec::new();
    for _ in 0..number_of_hosts {
        match rx.recv() {
            Ok(Response::Signal(result)) => match result {
                Ok(_) => {
                    results.truncate(0);
                    success = true;
                }
                Err(_) => {
                    results.push(result);
                }
            },
            Err(e) => {
                results.push(Err(YubicoError::ChannelError(e)));
                break;
            }
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

fn process(sender: Sender<Response>, api_host: &str, request: &Request, user_agent: String) {
    match get(request.build_url(api_host), user_agent) {
        Ok(raw_response) => {
            let result = request
                .response_verifier
                .verify_response(raw_response)
                .map(|()| "The OTP is valid.".to_owned());
            sender.send(Response::Signal(result)).unwrap();
        }
        Err(e) => {
            sender.send(Response::Signal(Err(e))).unwrap();
        }
    }
}

pub fn get(url: String, user_agent: String) -> Result<String> {
    let client = reqwest::Client::new();
    let mut response = client
        .get(url.as_str())
        .header(USER_AGENT, user_agent)
        .send()?;

    let mut data = String::new();
    response.read_to_string(&mut data)?;

    Ok(data)
}

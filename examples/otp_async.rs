#![recursion_limit = "128"]
extern crate futures;
extern crate tokio;
extern crate yubico;

use futures::future::Future;
use yubico::verify_async;

use std::io::stdin;
use yubico::config::Config;

fn main() {
    println!("Please plug in a yubikey and enter an OTP");

    let client_id = std::env::var("YK_CLIENT_ID")
        .expect("Please set a value to the YK_CLIENT_ID environment variable.");

    let api_key = std::env::var("YK_API_KEY")
        .expect("Please set a value to the YK_API_KEY environment variable.");

    let otp = read_user_input();

    let config = Config::default().set_client_id(client_id).set_key(api_key);

    tokio::run(
        verify_async(otp, config)
            .unwrap()
            .map(|_| {
                println!("Valid OTP.");
            })
            .map_err(|err| {
                println!("Invalid OTP. Cause: {:?}", err);
            }),
    )
}

fn read_user_input() -> String {
    let mut buf = String::new();

    stdin()
        .read_line(&mut buf)
        .expect("Could not read user input.");

    buf
}

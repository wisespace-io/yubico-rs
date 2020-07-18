extern crate yubico;

use yubico::config::*;
use yubico::verify;

fn main() {
    println!("Please plug in a yubikey and enter an OTP");

    let client_id = std::env::var("YK_CLIENT_ID")
        .expect("Please set a value to the YK_CLIENT_ID environment variable.");

    let api_key = std::env::var("YK_API_KEY")
        .expect("Please set a value to the YK_API_KEY environment variable.");
    
    let config = Config::default()
        .set_client_id(client_id)
        .set_key(api_key)
        .set_proxy_url("http://your_proxy");

    match verify("OTP", config) {
        Ok(answer) => println!("{}", answer),
        Err(e) => println!("Error: {}", e),
    }
}

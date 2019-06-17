extern crate yubico;

use yubico::verify;
use yubico::config::*;

fn main() {
   let config = Config::default()
       .set_client_id("CLIENT_ID")
       .set_key("API_KEY")
       .set_api_hosts(vec!["https://api.example.com/verify".into()]);

   match verify("OTP", config) {
      Ok(answer) => println!("{}", answer),
      Err(e) => println!("Error: {}", e),
   }
}
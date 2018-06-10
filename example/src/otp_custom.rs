extern crate yubico;

use yubico::Yubico;
use yubico::config::*;

fn main() {
   let yubi = Yubico::new("CLIENT_ID", "API_KEY");

   let config = Config::default().set_api_hosts(vec!["https://api.example.com/verify".into()]);
   let result = yubi.verify("OTP", config);
   match result {
      Ok(answer) => println!("{}", answer),
      Err(e) => println!("Error: {}", e),
   }
}
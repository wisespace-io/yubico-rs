extern crate yubico;

use yubico::Yubico;
use yubico::config::*;

fn main() {
   let yubi = Yubico::new("CLIENT_ID", "API_KEY");
   let result = yubi.verify("OTP", Config::default());
   match result {
      Ok(answer) => println!("{}", answer),
      Err(e) => println!("Error: {}", e),
   }
}

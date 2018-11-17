extern crate yubico;

use yubico::Yubico;
use yubico::config::*;

fn main() {
   let yubi = Yubico::new();

   let config = Config::default()
       .set_client_id("38734")
       .set_key("pJM4TyTWKJ1XA/+2JoiF+BXl3Oc=");

   let result = yubi.verify("z", config);
   match result {
      Ok(answer) => println!("{}", answer),
      Err(e) => println!("Error: {}", e),
   }

   loop {
       
   }
}

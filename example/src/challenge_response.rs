extern crate yubico;
extern crate pretty_hex;

use pretty_hex::*;
use std::ops::Deref;
use yubico::{Yubico};
use yubico::config::{Config, Slot, Mode};

fn main() {
   let mut yubi = Yubico::new();

   if let Ok(device) = yubi.find_yubikey() {
       println!("Vendor ID: {:?} Product ID {:?}", device.vendor_id, device.product_id);

       let config = Config::default()
           .set_vendor_id(device.vendor_id)
           .set_product_id(device.product_id)
           .set_variable_size(true)
           .set_mode(Mode::Sha1)
           .set_slot(Slot::Slot2);

       // Challenge can not be greater than 64 bytes
       let challenge = String::from("mychallenge");
       let (hmac_result, _) = yubi.challenge_response(challenge.as_bytes(), config).unwrap();

       // Just for debug, lets check the hex
       let v: &[u8] = hmac_result.deref();
       println!("{:?}", v.hex_dump());
     
   } else {
       println!("Yubikey not found");
   }
}

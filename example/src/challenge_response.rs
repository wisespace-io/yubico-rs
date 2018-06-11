extern crate yubico;

use yubico::{Yubico, Slot};

fn main() {
   let mut yubi = Yubico::new("CLIENT_ID", "API_KEY");

   if let Ok(device) = yubi.find_yubikey() {
       println!("Vendor ID: {:?} Product ID {:?}", device.vendor_id, device.product_id);

       let challenge = "my challenge";
       yubi.challenge_response(challenge.as_bytes(), device, Slot::Slot1);
   }
}

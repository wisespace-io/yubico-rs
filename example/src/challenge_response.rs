extern crate yubico;

use yubico::Yubico;

fn main() {
   let yubi = Yubico::new("CLIENT_ID", "API_KEY");

   if let Ok(device) = yubi.find_yubikey() {
       println!("Vendor ID: {:?} Product ID {:?}", device.vendor_id, device.product_id);
   }
}

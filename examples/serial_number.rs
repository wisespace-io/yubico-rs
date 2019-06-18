extern crate hex;
extern crate yubico;

use yubico::{Yubico};
use yubico::config::{Config, Slot};

fn main() {
   let mut yubi = Yubico::new();

   if let Ok(device) = yubi.find_yubikey() {
       println!("Vendor ID: {:?} Product ID {:?}", device.vendor_id, device.product_id);

       let config = Config::default()
           .set_vendor_id(device.vendor_id)
           .set_product_id(device.product_id)
           .set_slot(Slot::Slot2);

       let serial_number = yubi.read_serial_number(config).unwrap();

       println!("Serial Number {}", serial_number);
     
   } else {
       println!("Yubikey not found");
   }
}

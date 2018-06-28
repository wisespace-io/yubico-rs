extern crate yubico;

use yubico::{Yubico};
use yubico::config::{Config, Command};
use yubico::configure::{ DeviceModeConfig };
use yubico::otpmode::{ Aes128Key };

fn main() {
   let mut yubi = Yubico::new();

   if let Ok(device) = yubi.find_yubikey() {
       println!("Vendor ID: {:?} Product ID {:?}", device.vendor_id, device.product_id);

       let config = Config::default()
           .set_vendor_id(device.vendor_id)
           .set_product_id(device.product_id)
           .set_command(Command::Configuration2);

        let require_press_button = false;

        // Private Identity must have 6 bytes (input parameter in the OTP generation algorithm)
        let private_identity: &[u8; 6] = b"norway";
        
        // Secret must have 16 bytes        
        let secret: &[u8; 16] = b"_awesome_secret_";
        let aes128_key: Aes128Key = Aes128Key::from_slice(secret);

        let mut device_config = DeviceModeConfig::default();
        device_config.challenge_response_otp(&aes128_key, private_identity, require_press_button);

        if let Err(err) = yubi.write_config(config, &mut device_config) {
            println!("{:?}", err);
        } else {
            println!("Device configured");
        }
     
   } else {
       println!("Yubikey not found");
   }
}

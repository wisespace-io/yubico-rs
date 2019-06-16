# Yubico &emsp; [![Build Status]][travis] [![Latest Version]][crates.io] [![MIT licensed]][MIT] [![Apache-2.0 licensed]][APACHE]

[Build Status]: https://travis-ci.org/wisespace-io/yubico-rs.png?branch=master
[travis]: https://travis-ci.org/wisespace-io/yubico-rs
[Latest Version]: https://img.shields.io/crates/v/yubico.svg
[crates.io]: https://crates.io/crates/yubico
[MIT licensed]: https://img.shields.io/badge/License-MIT-blue.svg
[MIT]: ./LICENSE-MIT
[Apache-2.0 licensed]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[APACHE]: ./LICENSE-APACHE

**Enables integration with the Yubico validation platform, so you can use Yubikey's one-time-password in your Rust application, allowing a user to authenticate via Yubikey.**

---

## Current features

- [X] Yubikey client API library, [validation protocol version 2.0](https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html).
- [X] [Challenge-Response](https://wiki.archlinux.org/index.php/yubikey#Function_and_Application_of_Challenge-Response), YubiKey 2.2 and later supports HMAC-SHA1 or Yubico challenge-response operations.
- [x] Configuration.

## Usage

Add this to your Cargo.toml

```toml
[dependencies]
yubico = "0.5"
```

The following are a list of Cargo features that can be enabled or disabled:

- online (enabled by default): Provides TLS support via Reqwest to connect over HTTPS in order to validate OTP against the yubico/custom servers. On Linux, it will use OpenSSL 1.1.
- online-tokio (enabled by default): Provides integration to Tokio using futures.
- usb (enabled by default): Provides USB support via libusb. It can safely be disabled when using the library to do only OTP with servers.

You can enable or disable them using the example below:

  ```toml
  [dependencies.yubico]
  version = "0.5"
  # don't include the default features (online)
  default-features = false
  # cherry-pick individual features
  features = []
  ```

[Request your api key](https://upgrade.yubico.com/getapikey/).

### OTP with Default Servers

```rust
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
```

## OTP with custom API servers

```rust
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
```

### Configure Yubikey (HMAC-SHA1 mode)

Note, please read about the [initial configuration](https://wiki.archlinux.org/index.php/yubikey#Initial_configuration)
Alternatively you can configure the yubikey with the official [Yubikey Personalization GUI](https://developers.yubico.com/yubikey-personalization-gui/).

```rust
extern crate rand;
extern crate yubico;

use yubico::{Yubico};
use yubico::config::{Config, Command};
use yubico::configure::{ DeviceModeConfig };
use yubico::hmacmode::{ HmacKey };
use rand::{thread_rng, Rng};
use rand::distributions::{Alphanumeric};

fn main() {
   let mut yubi = Yubico::new();

   if let Ok(device) = yubi.find_yubikey() {
       println!("Vendor ID: {:?} Product ID {:?}", device.vendor_id, device.product_id);

       let config = Config::default()
           .set_vendor_id(device.vendor_id)
           .set_product_id(device.product_id)
           .set_command(Command::Configuration2);

        let mut rng = thread_rng();

        // Secret must have 20 bytes
        // Used rand here, but you can set your own secret: let secret: &[u8; 20] = b"my_awesome_secret_20";
        let secret: String = rng.sample_iter(&Alphanumeric).take(20).collect();
        let hmac_key: HmacKey = HmacKey::from_slice(secret.as_bytes());

        let mut device_config = DeviceModeConfig::default();
        device_config.challenge_response_hmac(&hmac_key, false, false);

        if let Err(err) = yubi.write_config(config, &mut device_config) {
            println!("{:?}", err);
        } else {
            println!("Device configured");
        }

   } else {
       println!("Yubikey not found");
   }
}
```

### Example Challenge-Response (HMAC-SHA1 mode)

Configure the yubikey with [Yubikey Personalization GUI](https://developers.yubico.com/yubikey-personalization-gui/)

```rust
extern crate hex;
extern crate yubico;

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
       // In HMAC Mode, the result will always be the SAME for the SAME provided challenge
       let hmac_result= yubi.challenge_response_hmac(challenge.as_bytes(), config).unwrap();

       // Just for debug, lets check the hex
       let v: &[u8] = hmac_result.deref();
       let hex_string = hex::encode(v);

       println!("{}", hex_string);

   } else {
       println!("Yubikey not found");
   }
}
```

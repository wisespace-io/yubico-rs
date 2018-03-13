[![Build Status](https://travis-ci.org/wisespace-io/yubico-rs.png?branch=master)](https://travis-ci.org/wisespace-io/yubico-rs)
[![Crates.io](https://img.shields.io/crates/v/yubico.svg)](https://crates.io/crates/yubico)
[![MIT licensed](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE-MIT)
[![Apache-2.0 licensed](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)

# Yubico

Yubikey client API library, [validation protocol version 2.0](https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html).

Enables integration with the Yubico validation platform, so you can use Yubikey's one-time-password in your Rust application,
allowing a user to authenticate via Yubikey.

# Usage

Add this to your Cargo.toml

```toml
[dependencies]
yubico = "0.2"
```

[Request your api key](https://upgrade.yubico.com/getapikey/).

## Example with Default Servers

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

## Example with custom API servers

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
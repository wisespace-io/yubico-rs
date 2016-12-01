[![License](http://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/wisespace-io/yubico-rs/blob/master/LICENSE)
[![](https://meritbadge.herokuapp.com/yubico)](https://crates.io/crates/yubico)

# Yubico
Yubikey client API library, [validation protocol version 2.0](https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html).

Enables integration with the Yubico validation platform, so you can use Yubikey's one-time-password in your Rust application,
allowing a user to authenticate via Yubikey.

IMPORTANT: WIP, signature verification hasn't been implemented yet.

# Usage

Add this to your Cargo.toml

```toml
[dependencies]
yubico = "0.1"
```

[Request your api key](https://upgrade.yubico.com/getapikey/).

# Example
```rust
extern crate yubico;

use yubico::Yubico;

fn main() {
   let yubi = Yubico::new("CLIENT_ID".into(), "API_KEY".into());
   let result = yubi.verify("OTP".into());
   match result {
      Ok(answer) => println!("{}", answer),
      Err(e) => println!("Error: {}", e),
   }
}
```

## License

* MIT license (see [LICENSE](LICENSE) or <http://opensource.org/licenses/MIT>)
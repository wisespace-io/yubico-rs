static API1_HOST : &'static str = "https://api.yubico.com/wsapi/2.0/verify";
static API2_HOST : &'static str = "https://api2.yubico.com/wsapi/2.0/verify";
static API3_HOST : &'static str = "https://api3.yubico.com/wsapi/2.0/verify";
static API4_HOST : &'static str = "https://api4.yubico.com/wsapi/2.0/verify";
static API5_HOST : &'static str = "https://api5.yubico.com/wsapi/2.0/verify";

#[derive(Clone, Debug, PartialEq)]
pub enum Slot {
    Slot1,
    Slot2,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Mode {
    Sha1,
    Otp,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum Command {
    ChallengeOtp1 = 0x20,
    ChallengeOtp2 = 0x28,
    ChallengeHmac1 = 0x30,
    ChallengeHmac2 = 0x38,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub client_id: String,
    pub key: Vec<u8>,
    pub product_id: u16,
    pub vendor_id: u16,
    pub variable: bool,
    pub slot: Slot,
    pub mode: Mode,
    pub command: Command,
    pub api_hosts: Vec<String>,
}

#[allow(dead_code)]
impl Config {
    pub fn default() -> Config {
        Config {
            client_id: String::new(),
            key: Vec::new(),
            product_id: 0x00,
            vendor_id: 0x1050,                       
            variable: true,
            slot: Slot::Slot1,
            mode: Mode::Sha1,
            command: Command::ChallengeHmac1,
            api_hosts: build_hosts(),
        }
    }

    pub fn set_client_id<C>(mut self, client_id: C) -> Self 
        where C: Into<String>
    {
        self.client_id = client_id.into();
        self
    }

    pub fn set_key<K>(mut self, key: K) -> Self
        where K: Into<String>
    {
        self.key = key.into().into_bytes();
        self
    }

    pub fn set_api_hosts(mut self, hosts: Vec<String>) -> Self {
        self.api_hosts = hosts;
        self
    }

    pub fn set_vendor_id(mut self, vendor_id: u16) -> Self {
        self.vendor_id = vendor_id;
        self
    }

    pub fn set_product_id(mut self, product_id: u16) -> Self {
        self.product_id = product_id;
        self
    }
    
    pub fn set_variable_size(mut self, variable: bool) -> Self {
        self.variable = variable;
        self
    }

    pub fn set_slot(mut self, slot: Slot) -> Self {
        self.slot = slot;
        self
    }

    pub fn set_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    pub fn set_command(mut self, command: Command) -> Self {
        self.command = command;
        self
    }    
}

fn build_hosts() -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();

    hosts.push(API1_HOST.to_string());
    hosts.push(API2_HOST.to_string());
    hosts.push(API3_HOST.to_string());
    hosts.push(API4_HOST.to_string());
    hosts.push(API5_HOST.to_string());

    hosts
}
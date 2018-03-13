static API1_HOST : &'static str = "https://api.yubico.com/wsapi/2.0/verify";
static API2_HOST : &'static str = "https://api2.yubico.com/wsapi/2.0/verify";
static API3_HOST : &'static str = "https://api3.yubico.com/wsapi/2.0/verify";
static API4_HOST : &'static str = "https://api4.yubico.com/wsapi/2.0/verify";
static API5_HOST : &'static str = "https://api5.yubico.com/wsapi/2.0/verify";

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub api_hosts: Vec<String>,
}

#[allow(dead_code)]
impl Config {
    pub fn default() -> Config {
        Config {
            api_hosts: build_hosts(),
        }
    }

    pub fn set_api_hosts(mut self, hosts: Vec<String>) -> Self {
        self.api_hosts = hosts;
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